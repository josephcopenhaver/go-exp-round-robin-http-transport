package xhttp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"math/rand/v2"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/josephcopenhaver/go-exp-round-robin-http-transport/xnet"
	xnet_i "github.com/josephcopenhaver/go-exp-round-robin-http-transport/xnet/internal"
	"github.com/josephcopenhaver/go-exp-round-robin-http-transport/xqueue"
	"github.com/josephcopenhaver/go-exp-round-robin-http-transport/xstrings"
	"github.com/josephcopenhaver/go-exp-round-robin-http-transport/xsync"
	"golang.org/x/sync/semaphore"
)

// maxHostnameLength is the maximum length of a hostname according to RFC 1035 and RFC 1123.
const maxHostnameLength = 253

var (
	ErrTransportClosed           = errors.New("transport closed")
	errMaxLifespanExceeded       = errors.New("connection max lifespan exceeded")
	errIdleTimeoutExceeded       = errors.New("connection idle timeout exceeded")
	errConnectionInactive        = errors.New("connection closed by server or client, or connection is no longer usable for reads/writes due to a network error or timeout")
	errMaxHostnameLengthExceeded = errors.New("hostname exceeds maximum length as per RFC 1035 and RFC 1123")
)

// TODO: regularly expire ips that are not discovered for a timeout and close their idle connections
//
// it's likely best to regularly re-resolve the hosts in the cache and remove the ones that are not found after the above timeout
//
// depending solely on the connection reuse is not enough as DNS resolving is not being performed on GetOrCreateConnection if connection reuse is high enough

// TODO: connections that are idle for far too long should be closed if they exceed the idle timeout, the connection lifespan. Otherwise the LIFO queues can grow indefinitely and leak ports + memory.

// TODO: ensure that connections have socket level keep-alive enabled and primed when they go idle
// TODO: when a connection is too old, has been idle for too long, or has been closed by the server, then the fifo queue should be traversed to find a still valid one.
// TODO: should an idle connection no longer be valid, then the next one should be tried until all pools are traversed and idle-age of all connections indicates that all idle connections should be flushed
//
// TODO: should closing a connection that was reused too many times be a feature?

// TODO: should likely try to reuse connections that are idle in the same queue rather than trying the next possible ip all the time
// we only want to establish more connections if we're highly unbalanced and there are periods when queues are empty

// TODO: Test that a new connection can be initialized without violating the round-robin per-host max connections limit
// TODO: When a new connection is created, acquire a semaphore slot for the max connections per host tracker
// TODO: when the connection limit is reached, wait for a connection to be closed or returned to the pool before creating a new one
// TODO: expose a "RoundRobinConnectTimeout" option for use across all Connect attempts and a "RoundRobinPerConnectTimeout" option for each individual connection attempt; if specified the former must be greater than the latter; not sure if both should be require options
// TODO: expose a setting that allows a user to "prefer ipv4" if network type is ip rather than just ip4 or ip6 similar to HAProxy's "prefer ipv4" setting
//
// TODO: expose a "RoundRobinRoundTripTimeout" option that allows a user to specify a timeout for the entire round-robin connection establishment / selection and request-response cycle; this is useful for cases where the user wants to ensure that the entire request-response cycle does not take longer than a certain time because the RoundTripper is handling the read body operation.
//
// should that not be the case, then it should have no effect and require the things utilizing the hypothetical connection wrappers that observe read state and listen for Close before re-pooling to handle the timeout themselves

type portMap struct {
	m xsync.Map[string, xsync.Map[uint16, *roundRobinQueue]]
}

func newPortMap() portMap {
	return portMap{xsync.NewMap[string, xsync.Map[uint16, *roundRobinQueue]]()}
}

func (pm portMap) load(hostKey string, port uint16) (*roundRobinQueue, bool) {
	v, ok := pm.m.Load(hostKey)
	if !ok {
		return nil, false
	}

	return v.Load(port)
}

func (pm portMap) withRange(f func(string, uint16, *roundRobinQueue) bool) {
	keepGoing := true
	pm.m.Range(func(hostKey string, portMap xsync.Map[uint16, *roundRobinQueue]) bool {
		portMap.Range(func(port uint16, rrq *roundRobinQueue) bool {
			keepGoing = f(hostKey, port, rrq)
			return keepGoing
		})
		return keepGoing
	})
}

func (pm portMap) loadOrStore(hostKey string, port uint16, rrqPtr *roundRobinQueue) (*roundRobinQueue, bool) {
	m, ok := pm.m.Load(hostKey)
	if !ok {
		m = xsync.NewMap[uint16, *roundRobinQueue]()
		m, _ = pm.m.LoadOrStore(hostKey, m)
	}
	return m.LoadOrStore(port, rrqPtr)
}

func newRRConnLifoQueue() xqueue.LIFO[*roundRobinConn] {
	op := xqueue.LIFOOpts[*roundRobinConn]()
	q, err := xqueue.NewLIFO(
		op.MaxCapacity(256), // TODO: parameterize max idle connections per host
		// TODO: parameterize initial idle connection capacity per host
		// TODO: parameterize max connections per host and manage set of semaphores for each host
	)
	if err != nil {
		panic(err)
	}

	return q
}

type roundRobinIPState struct {
	ip        string
	idleConns xqueue.LIFO[*roundRobinConn]
	sema      *semaphore.Weighted
	// lastSeenInDNSRespAt TODO: check this value during refresh time
	lastSeenInDNSRespAt time.Time
}

type roundRobinQueue struct {
	lastUpdatedAt time.Time
	ipListRWM     sync.RWMutex
	ipToIdx       xsync.Map[string, int]
	ipIdxToState  []roundRobinIPState
	nextIdx       uint64
}

type dnsResolver interface {
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
}

type dialer interface {
	DialTimeout(network, address string, timeout time.Duration) (net.Conn, error)
}

type roundRobinConnector struct {
	resolver           dnsResolver
	dialer             dialer
	dnsCacheMap        xsync.Map[string, *xnet.DNSCache]
	dnsRWM             sync.RWMutex
	rrqByHostKeyPort   portMap
	wg                 sync.WaitGroup
	stop               context.CancelFunc
	maxConnLifespan    time.Duration // TODO: parameterize this
	maxConnIdleTimeout time.Duration
}

// Next returns the next idle connection from the round-robin queue.
// It returns the connection, the IP address it is associated with, and a boolean indicating if a connection was found.
// If no idle connections are available, it returns nil, the IP it would have returned a connection for if an idle one had existed, and false.
//
// Note: the ip string returned on ok==true is likely not too useful and might be adjusted in the future to be an empty string
// TODO: assess the above note ^^^
func (q *roundRobinQueue) Next() (*roundRobinConn, string, bool) {
	q.ipListRWM.RLock()
	defer q.ipListRWM.RUnlock()

	if len(q.ipIdxToState) == 0 {
		return nil, "", false
	}

	var st *roundRobinIPState
	{
		idx := atomic.AddUint64(&q.nextIdx, 1) % uint64(len(q.ipIdxToState))
		st = &q.ipIdxToState[idx]
	}
	idleConns := st.idleConns

	c, ok := idleConns.Get()
	if !ok {
		return nil, st.ip, false
	}

	for {
		err := c.isActive()
		if err == nil {
			break
		}

		// TODO: debug log the issue

		// TODO: short circuit the loop if the error type indicates
		// that the connection is timed-out regardless of the the connection
		// being connected still or not
		//
		// this lets the routine started by roundRobinConnector.start manage cleanup duties

		// cleanup the connection
		{
			ignoredErr := q.putCloseNoLock(c)
			_ = ignoredErr
		}

		// try to get the next idle connection
		c, ok = idleConns.Get()
		if !ok {
			return nil, st.ip, false
		}
	}

	return c, "", true
}

// Put places a connection back into the round-robin queue
func (q *roundRobinQueue) Put(conn *roundRobinConn) bool {
	q.ipListRWM.RLock()
	defer q.ipListRWM.RUnlock()

	i, ok := q.ipToIdx.Load(conn.ipStr)
	if !ok {
		return false
	}

	return q.ipIdxToState[i].idleConns.Put(conn)
}

// PutClose places a connection back into the round-robin queue and closes it if the queue is closed or the HostKey or target ip are not found in the queue.
func (q *roundRobinQueue) PutClose(conn *roundRobinConn) error {
	result := conn.unwrappedClose()

	var sema *semaphore.Weighted
	defer func() {
		if sema != nil {
			sema.Release(1)
		}
	}()

	q.ipListRWM.RLock()
	defer q.ipListRWM.RUnlock()

	i, ok := q.ipToIdx.Load(conn.ipStr)
	if !ok {
		return result
	}

	sema = q.ipIdxToState[i].sema

	return result
}

// putCloseNoLock is the same as PutClose but does not acquire the ipListRWM lock.
//
// useful when the round-robin queue is already locked and the caller does not want to
// release the lock to re-acquire again just after calling this function and avoid a deadlock.
func (q *roundRobinQueue) putCloseNoLock(conn *roundRobinConn) error {
	result := conn.unwrappedClose()

	var sema *semaphore.Weighted
	defer func() {
		if sema != nil {
			sema.Release(1)
		}
	}()

	// the next two commented lines are the only fundamental differences here between this function and PutClose
	// q.ipListRWM.RLock()
	// defer q.ipListRWM.RUnlock()

	i, ok := q.ipToIdx.Load(conn.ipStr)
	if !ok {
		return result
	}

	sema = q.ipIdxToState[i].sema

	return result
}

// isCacheExpired is a simple accessor that takes a given maxAge and the current time
// and returns true if the cache is expired, meaning that the lastUpdatedAt is zero or
// the lastUpdatedAt plus the maxAge is not after the current time.
//
// This is used to determine if the DNS cache for a given hostKey is still valid or needs to be refreshed.
func (q *roundRobinQueue) isCacheExpired(maxAge time.Duration, now time.Time) bool {
	q.ipListRWM.RLock()
	defer q.ipListRWM.RUnlock()

	if q.lastUpdatedAt.IsZero() || !q.lastUpdatedAt.Add(maxAge).After(now) {
		return true
	}

	return false
}

func (d *roundRobinConnector) PutClose(c net.Conn) error {
	// Assert that the connection is of type roundRobinConn
	conn := c.(*roundRobinConn)
	if conn == nil {
		panic("roundRobinConnector can only put connections of type *roundRobinConn that are non-nil")
	}

	if conn.dialer != d {
		panic("roundRobinConnector can only put connections that were created by it")
	}

	if rrq, ok := d.rrqByHostKeyPort.load(conn.hostKey, conn.port); ok {
		return rrq.PutClose(conn)
	}

	return conn.unwrappedClose()
}

// TODO: convert network to a numeric constant that serializes to a string and likely place it after the tlsConf parameter
func (d *roundRobinConnector) GetOrCreateConnection(req *http.Request, network string, tlsConf *tls.Config) (*roundRobinConn, *http.Request, error) {
	ctx := req.Context()

	const dialTimeout = 5 * time.Second // TODO: parameterize or state-ify this

	address := req.URL.Host
	var host string
	var port uint16
	{
		h, portStr, splitErr := net.SplitHostPort(address)
		portVal, portErr := strconv.ParseInt(portStr, 10, 32)
		if splitErr != nil {
			host = address
			if xstrings.EqualsIgnoreCaseASCII(req.URL.Scheme, "http") {
				address = net.JoinHostPort(host, "80")
				port = 80
			} else if xstrings.EqualsIgnoreCaseASCII(req.URL.Scheme, "https") {
				address = net.JoinHostPort(host, "443")
				port = 443
			} else {
				return nil, nil, errors.New("unsupported scheme in request URL: expected one of http or https")
			}
		} else if portErr != nil || portVal <= 0 || portVal > math.MaxUint16 {
			return nil, nil, errors.New("host-port separator in address without a valid port after it")
		} else {
			host = h
			port = uint16(portVal)
		}
	}

	if len(host) > maxHostnameLength {
		return nil, nil, errMaxHostnameLengthExceeded
	}

	var ipNetwork xnet.IPNetwork
	hostKey := host
	switch network {
	case "tcp":
		ipNetwork = xnet.IPNetworkUnified
		hostKey += "0"
	case "tcp4":
		ipNetwork = xnet.IPNetworkV4
		hostKey += "4"
	case "tcp6":
		ipNetwork = xnet.IPNetworkV6
		hostKey += "6"
	default:
		panic("network must be one of tcp, tcp4, or tcp6")
	}

	// If the host is not an IP address, we need to ensure that the Host header is set correctly
	// This is important for HTTP/1.1 and HTTP/2 where the Host header is required
	if (net.ParseIP(host) == nil) && (req.Host == "" || req.Host != host) {
		req.Host = host
	}

	slog.LogAttrs(ctx, slog.LevelDebug,
		"getting connection",
		slog.String("hostKey", hostKey),
		slog.Int("port", int(port)),
	)

	// dstIP tracks when a decision of which IP to use was made
	// this is resolved as part of attempting to read an idle connection from the cache
	// when there is a DNS cache, but no idle connection available
	var dstIP string

	if v, ok := d.rrqByHostKeyPort.load(hostKey, port); ok {
		slog.LogAttrs(ctx, slog.LevelDebug,
			"round-robin queue for hostKey + port found in connector",
			slog.String("hostKey", hostKey),
			slog.Int("port", int(port)),
		)

		c, ip, ok := v.Next()
		if ok {
			slog.LogAttrs(ctx, slog.LevelDebug,
				"reusing connection",
			)
			return c, req, nil
		}

		// if ip is not empty, it means that means we know the ip we want to dial with the specific host header
		// should it still be a valid ip address in the DNS cache or the next DNS resolution cycle

		dstIP = ip
	}

	slog.LogAttrs(ctx, slog.LevelDebug,
		"no idle connection found",
		slog.String("dst_ip", dstIP),
	)

	joinCharIndex := len(host)
	if host == "" {
		slog.LogAttrs(ctx, slog.LevelDebug,
			"host is empty",
		)
		c, err := d.dnsDial(ctx, tlsConf, req.URL.Scheme, hostKey, network, ipNetwork, address, joinCharIndex, dstIP, dialTimeout, 0)
		if err != nil {
			return nil, nil, err
		}
		return c, req, nil
	}

	ip := net.ParseIP(host)
	if ip == nil {
		slog.LogAttrs(ctx, slog.LevelDebug,
			"not an ip",
			slog.String("host", host),
			slog.String("next_strategy", "resolving name to ip via dnsDial"),
		)
		c, err := d.dnsDial(ctx, tlsConf, req.URL.Scheme, hostKey, network, ipNetwork, address, joinCharIndex, dstIP, dialTimeout, 0)
		if err != nil {
			return nil, nil, err
		}
		return c, req, nil
	}

	slog.LogAttrs(ctx, slog.LevelDebug,
		"hostname in url is an ip address",
	)

	// host is not a name but an IP address
	// lets normalize the ip address format and retry finding a connection if different

	if newHost := ip.String(); newHost != host {
		// update hostKey value to account for normalized ip based host
		hostKey = newHost + hostKey[len(hostKey)-1:]

		if v, ok := d.rrqByHostKeyPort.load(hostKey, port); ok {
			c, _, ok := v.Next()
			if ok {
				slog.LogAttrs(ctx, slog.LevelDebug,
					"reusing connection for resolved ip address",
				)
				return c, req, nil
			}
		}

		host = newHost
		address = hostKey[:len(hostKey)-1]
		joinCharIndex = len(host)
	}

	c, err := d.dnsDial(ctx, tlsConf, req.URL.Scheme, hostKey, network, ipNetwork, address, joinCharIndex, host, dialTimeout, 0)
	if err != nil {
		return nil, nil, err
	}
	return c, req, nil
}

func (d *roundRobinConnector) Put(c net.Conn, lastIdleAt time.Time) bool {
	// Assert that the connection is of type roundRobinConn
	conn := c.(*roundRobinConn)
	if conn == nil {
		panic("roundRobinConnector can only put connections of type *roundRobinConn that are non-nil")
	}

	if conn.dialer != d {
		panic("roundRobinConnector can only put connections that were created by it")
	}

	conn.lastIdleAt = lastIdleAt

	rrq, ok := d.rrqByHostKeyPort.load(conn.hostKey, conn.port)
	if !ok {
		return false
	}

	return rrq.Put(conn)
}

type _netConn = net.Conn

type roundRobinConn struct {
	_netConn
	ipStr      string
	bufReader  *bufio.Reader
	hostKey    string
	port       uint16
	createdAt  time.Time
	lastIdleAt time.Time

	// numReuses uint64 // TODO: not convinced connections should have a max reuse count policy, likely remove this field/comment

	// maxNumReuses uint64 // TODO: not convinced connections should have a max reuse count policy, likely remove this field/comment

	// dialer is the parent roundRobinConnector that created this connection
	//
	// perhaps in the future the connection could observe the layer4 and layer7 protocol states and "learn" if on-close it can instead place itself back into the idle pool
	//
	// this is a much harder implementation to target so for now just going to use the pointer to ensure that the connection is returned to the correct pool
	dialer *roundRobinConnector
}

// unwrappedClose is just an intent function with the same purpose as net.Conn.Close
//
// the difference here is that if I ever do any refactoring of the connection wrapper
// so that the exposed Close does something more clever, this one remains direct and
// simply closes the underlying net.Conn implementation.
func (c *roundRobinConn) unwrappedClose() error {
	return c._netConn.Close()
}

// active returns true if the connection is still usable for reads and writes.
//
// a connection can become inactive if it has been closed by the server
// (or the client for the sake of being exhaustive - but the purpose is purely
// to detect if idle connections are still established), the connection has
// been idle for longer than the configured idle timeout, or the connection
// has existed for longer than the configured connection max lifespan.
func (c *roundRobinConn) isActive() error {
	ok, err := xnet_i.IsConnected(c._netConn)
	if err != nil {
		return fmt.Errorf("failed to check if connection is active: %w", err)
	}

	if !ok {
		return errConnectionInactive
	}

	// verify that the connection itself is not too old since it was established
	{
		maxLifespan := c.dialer.maxConnLifespan
		if maxLifespan > 0 && time.Since(c.createdAt) >= maxLifespan {
			return errMaxLifespanExceeded
		}
	}

	// verify that the connection is not idle for too long
	{
		idleTimeout := c.dialer.maxConnIdleTimeout
		if idleTimeout > 0 && time.Since(c.lastIdleAt) >= idleTimeout {
			return errIdleTimeoutExceeded
		}
	}

	return nil
}

func (d *roundRobinConnector) dnsDial(ctx context.Context, tlsConf *tls.Config, scheme, hostKey, network string, ipNetwork xnet.IPNetwork, address string, joinCharIndex int, dstIP string, dialTimeout time.Duration, retryNum uint8) (*roundRobinConn, error) {

	const dnsCacheTimeout = 130 * time.Second // TODO: parameterize

	var port uint16
	if v, err := strconv.Atoi(address[joinCharIndex+1:]); err != nil {
		return nil, fmt.Errorf("failed to parse port from address: %w", err)
	} else {
		port = uint16(v)
	}

	isDirectIPDial := (dstIP != "" && address[:joinCharIndex] == dstIP)

	var conn net.Conn
	var ip string
	var createdAt time.Time
	rrq, ok := d.rrqByHostKeyPort.load(hostKey, port)
	if !isDirectIPDial && (!ok || rrq.isCacheExpired(dnsCacheTimeout, time.Now())) {
		err := func() error {

			//
			// TODO: use a singleflight operation here to avoid concurrent executors since they should all use the same result
			//

			unlocker := d.dnsRWM.RUnlock
			d.dnsRWM.RLock()
			defer func() {
				if f := unlocker; f != nil {
					f()
				}
			}()

			rrq, ok = d.rrqByHostKeyPort.load(hostKey, port)
			if ok && !rrq.isCacheExpired(dnsCacheTimeout, time.Now()) {
				return nil
			}

			{
				f := unlocker
				unlocker = nil
				f()

				unlocker = d.dnsRWM.Unlock
				d.dnsRWM.Lock()
			}

			rrq, ok = d.rrqByHostKeyPort.load(hostKey, port)
			if ok && !rrq.isCacheExpired(dnsCacheTimeout, time.Now()) {
				return nil
			}

			slog.LogAttrs(ctx, slog.LevelDebug,
				"resolving host to ip",
				slog.String("host", address[:joinCharIndex]),
			)

			const dnsTimeout = 10 * time.Second // TODO: parameterize or state-ify

			dnsCtx, cancel := context.WithTimeout(ctx, dnsTimeout)
			defer cancel()

			dnsCache, ok := d.dnsCacheMap.Load(hostKey)
			if !ok {
				dnsCache = xnet.NewDNSCache(hostKey[:joinCharIndex], dnsCacheTimeout, 15*time.Second, ipNetwork)
				dnsCache, _ = d.dnsCacheMap.LoadOrStore(hostKey, dnsCache)
			}
			dnsResolveStart := time.Now()
			dnsRecords, dnsRefreshLastSuccessfulAt, _, err := dnsCache.Read(dnsCtx, d.resolver)
			dnsResolveEnd := time.Now()
			if err != nil {
				return fmt.Errorf("failed to resolve ips for host %s: %w", address[:joinCharIndex], err)
			}
			slog.LogAttrs(ctx, slog.LevelDebug,
				"got dns response",
				slog.String("host", address[:joinCharIndex]),
				slog.Time("dns_resolve_start", dnsResolveStart),
				slog.Time("dns_resolve_end", dnsResolveEnd),
			)

			var errs []error
			// var dnsRecordIdx int
			{
				for i := range dnsRecords {
					v := &dnsRecords[i]

					if conn == nil {
						// dnsRecordIdx = i
						ip = v.IP
						slog.LogAttrs(ctx, slog.LevelDebug,
							"dialing ip",
							slog.String("ip", ip),
							slog.String("port", address[joinCharIndex+1:]),
							slog.String("host", address[:joinCharIndex]),
						)
						v, err := d.dialer.DialTimeout(network, net.JoinHostPort(ip, address[joinCharIndex+1:]), dialTimeout)
						if err == nil {
							createdAt = time.Now()
							slog.LogAttrs(ctx, slog.LevelDebug,
								"got connection",
								slog.String("ip", ip),
								slog.String("port", address[joinCharIndex+1:]),
								slog.String("host", address[:joinCharIndex]),
								slog.String("created_at", createdAt.String()),
							)
							conn = v
						} else {
							errs = append(errs, err)
						}
					}
				}
			}

			slog.LogAttrs(ctx, slog.LevelDebug,
				"got ip addresses for host",
				slog.String("host", address[:joinCharIndex]),
				slog.Time("dns_resolve_start", dnsResolveStart),
				slog.Time("dns_resolve_end", dnsResolveEnd),
				slog.Any("errors", errs),
			)

			// ensuring the round-robin queue is created and populated with the newly resolved IPs
			if rrq == nil {
				slog.LogAttrs(ctx, slog.LevelDebug,
					"no prior round-robin queue found for hostKey so creating a new one",
				)

				// allocate the new round-robin queue expecting the hostKey to not have one already
				{
					// randomly select the next index to start from
					nextIdx := rand.Uint64()
					// nextIdx := uint64(dnsRecordIdx) - 1 // this makes sure the next one is the one that was just dialed

					ipIdxToState := make([]roundRobinIPState, 0, len(dnsRecords))

					rrq = &roundRobinQueue{
						ipToIdx:       xsync.NewMap[string, int](),
						lastUpdatedAt: dnsRefreshLastSuccessfulAt,
						nextIdx:       nextIdx,
					}

					for _, v := range dnsRecords {
						i := len(ipIdxToState)
						ipIdxToState = append(ipIdxToState, roundRobinIPState{v.IP, newRRConnLifoQueue(), nil, v.LastSeen})
						rrq.ipToIdx.Store(v.IP, i)
					}

					rrq.ipIdxToState = ipIdxToState
				}

				rrq, _ = d.rrqByHostKeyPort.loadOrStore(hostKey, port, rrq)
			} else {
				slog.LogAttrs(ctx, slog.LevelDebug,
					"found existing round-robin queue found for hostKey + port so adding the new ips to it",
				)

				func() {
					rrq.ipListRWM.Lock()
					defer rrq.ipListRWM.Unlock()

					// normalize the index so it does not move from the relative
					// position it is at when the ipIdToConn slice is expanded
					rrq.nextIdx = rrq.nextIdx % uint64(len(rrq.ipIdxToState))

					originalLen := len(rrq.ipIdxToState) // TODO: delete this variable after debugging
					for _, v := range dnsRecords {
						if i, ok := rrq.ipToIdx.Load(v.IP); ok {
							// update the existing state with the new lastSeenInDNSRespAt value
							st := &rrq.ipIdxToState[i]
							if v.LastSeen.After(st.lastSeenInDNSRespAt) {
								st.lastSeenInDNSRespAt = v.LastSeen
							}

							continue
						}

						i := len(rrq.ipIdxToState)
						state := roundRobinIPState{v.IP, newRRConnLifoQueue(), nil, v.LastSeen}
						rrq.ipIdxToState = append(rrq.ipIdxToState, state)
						rrq.ipToIdx.Store(v.IP, i)
					}

					if dnsRefreshLastSuccessfulAt.After(rrq.lastUpdatedAt) {
						rrq.lastUpdatedAt = dnsRefreshLastSuccessfulAt
					}
					slog.LogAttrs(ctx, slog.LevelDebug,
						"added new ip addresses maybe added to the queue",
						slog.Int("delta", len(rrq.ipIdxToState)-originalLen),
					)
				}()
			}

			if conn == nil {
				slog.LogAttrs(ctx, slog.LevelDebug,
					"no conn established during dns resolution",
				)

				var err error
				if len(errs) > 1 {
					err = errors.Join(errs...)
				} else {
					err = errs[0]
				}

				return fmt.Errorf("failed to dial host %s: %v", address[:joinCharIndex], err)
			}

			return nil
		}()
		if err != nil {
			return nil, err
		}
	}

	isHttps := xstrings.EqualsIgnoreCaseASCII(scheme, "https")

	if conn != nil {
		goto TLS_HANDSHAKE_CHECK
	}

	// TODO: what if dstIP is no longer a valid IP address according to the latest DNS resolution + DNS entry timeout of cache contents?
	// note that the above concern is only valid when isDirectIPDial == false
	//
	// we should likely not use the chosen dstIP returned by the higher round-robin ip selection + idle connection selection logic
	//
	// but note that this is a racy-concern. It will eventually become closed when the next pooling attempt is made
	//
	// but because we do not check it here it's a short-lived connection in this case

	if dstIP != "" {
		// setting ip here to ensure that the connection is created with the correct IP address for re-pooling
		ip = dstIP

		ipPort := net.JoinHostPort(dstIP, address[joinCharIndex+1:])
		c, err := d.dialer.DialTimeout(network, ipPort, dialTimeout)
		if err != nil {
			return nil, fmt.Errorf("failed to dial %s: %w", address[:joinCharIndex], err)
		}
		createdAt = time.Now()
		conn = c

		goto TLS_HANDSHAKE_CHECK
	}

	// if we get here, it means that we have no idle connections and no well-known dstIP address to lean
	// on from previous DNS resolutions
	//
	// this happens if the cache was empty but become non-empty after the idle connection was requested
	//
	// in the case of this race condition we can just retry the method call once after determining an
	// ip to target from the pool or find a ready to use idle connection

	{
		c, ipStr, ok := rrq.Next()
		if ok {
			return c, nil
		}
		if retryNum > 0 {
			// this should almost never happen
			//
			// it means the DNS cache was forcefully emptied
			//
			// that or perhaps the DNS cache expired entirely and there is an outage event of DNS or extreme service latency
			//
			// Should this happen, we want to let people opt-in to a strategy here. Just erroring
			// it quite drastic if the targets almost never change, but that is highly subjective
			// and should be a user choice for their situation and preferred failure modes.
			return nil, fmt.Errorf("DNS cache expired and DNS queries failed to return any IPs for host")
		}

		slog.LogAttrs(ctx, slog.LevelDebug,
			"running nested dnsDial",
		)

		return d.dnsDial(ctx, tlsConf, scheme, hostKey, network, ipNetwork, address, joinCharIndex, ipStr, dialTimeout, retryNum+1)
	}

TLS_HANDSHAKE_CHECK:
	if isHttps {
		if tlsConf == nil {
			tlsConf = &tls.Config{
				ServerName: address[:joinCharIndex],
				RootCAs:    nil,
			}
		}
		tlsConn := tls.Client(conn, tlsConf)

		tlsHandshakeTimeout := 10 * time.Second // TODO: parameterize or state-ify this
		tlsHandshakeCtx, cancel := context.WithTimeout(ctx, tlsHandshakeTimeout)
		defer cancel()

		if err := tlsConn.HandshakeContext(tlsHandshakeCtx); err != nil {
			ignoredErr := conn.Close()
			_ = ignoredErr
			return nil, err
		}

		conn = tlsConn
	}

	var lastIdleAt time.Time
	return &roundRobinConn{conn, ip, bufio.NewReader(conn), hostKey, port, createdAt, lastIdleAt, d}, nil
}

func (d *roundRobinConnector) shutdown() error {
	d.stop()
	d.wg.Wait()
	return nil
}

func (rrq *roundRobinQueue) renewTargetIPs(_ context.Context, dnsRefreshLastSuccessfulAt time.Time, dnsRecords []xnet.DNSResponseRecord) {
	rrq.ipListRWM.Lock()
	defer rrq.ipListRWM.Unlock()

	// add any new IPs to the round-robin queue
	for i := range dnsRecords {
		v := &dnsRecords[i]
		if i, ok := rrq.ipToIdx.Load(v.IP); ok {
			// update the lastSeenInDNSRespAt value for the existing IP
			st := &rrq.ipIdxToState[i]
			if v.LastSeen.After(st.lastSeenInDNSRespAt) {
				st.lastSeenInDNSRespAt = v.LastSeen
			}
			continue
		}

		i := len(rrq.ipIdxToState)
		state := roundRobinIPState{v.IP, newRRConnLifoQueue(), nil, v.LastSeen}
		rrq.ipIdxToState = append(rrq.ipIdxToState, state)
		rrq.ipToIdx.Store(v.IP, i)
	}

	// TODO: trim off any IPs that have not been seen for the AssumeRemovedTimeout duration

	// TODO: adjust nextIDX if required / ideal

	if dnsRefreshLastSuccessfulAt.After(rrq.lastUpdatedAt) {
		rrq.lastUpdatedAt = dnsRefreshLastSuccessfulAt
	}
}

func (d *roundRobinConnector) refreshDNSCache(ctx context.Context) {
	// TODO: for each hostKey in the cache, we should re-resolve the DNS values
	// and update the round-robin queue with any new IPs
	//
	// note with a refresh operation high concurrency + locking frequency
	// and high lock contention can lead to starvation of the round-robin queue
	//
	// I expect nameservers to have throttling in place or have clear throughput
	// capacity limits but am not currently aware of how those limits are conveyed
	// so I will likely utilize a semaphore to limit the number of concurrent DNS
	// resolution operations as well as singleflight
	{
		type refreshRecord struct {
			dnsRecords          []xnet.DNSResponseRecord
			dnsLastSuccessfulAt time.Time
			ok                  bool
		}
		seenCache := map[string]refreshRecord{}

		d.rrqByHostKeyPort.withRange(func(hostKey string, port uint16, rrq *roundRobinQueue) bool {

			if v, ok := seenCache[hostKey]; ok {
				if v.ok {
					rrq.renewTargetIPs(ctx, v.dnsLastSuccessfulAt, v.dnsRecords)
				}
				return true
			}

			host := hostKey[:len(hostKey)-1]

			var ipNetwork xnet.IPNetwork
			switch hostKey[len(hostKey)-1] {
			case '0':
				ipNetwork = xnet.IPNetworkUnified
			case '4':
				ipNetwork = xnet.IPNetworkV4
			case '6':
				ipNetwork = xnet.IPNetworkV6
			default:
				panic("bad hostKey value, expected last character to be 0, 4, or 6")
			}

			const dnsTimeout = 10 * time.Second // TODO: parameterize or state-ify

			dnsCtx, cancel := context.WithTimeout(ctx, dnsTimeout)
			defer cancel()

			dnsCache, ok := d.dnsCacheMap.Load(hostKey)
			if !ok {
				dnsCache = xnet.NewDNSCache(host, 130*time.Second, 15*time.Second, ipNetwork)
				dnsCache, _ = d.dnsCacheMap.LoadOrStore(hostKey, dnsCache)
			}

			// TODO: it's technically possible to just attempt a refresh and not taint the records
			// slice lifetime by reading the records - we would need to have a callback on refresh
			// that would check if the rrq last update time is older than the dnsRefreshLastSuccessfulAt
			// time and if so then read the records into this context. That is a lot of extra complexity
			// for a small allocation prevention during relative idle time for this connector-host-port
			// combination. It's likely not worth implementing until tests show allocations can be saved
			// and have a meaningful impact on the performance of the connector / runtime GC.

			resolveStartAt := time.Now()
			dnsRecords, dnsRefreshLastSuccessfulAt, _, err := dnsCache.Read(dnsCtx, d.resolver)
			resolveEndAt := time.Now()
			seenCache[hostKey] = refreshRecord{dnsRecords, dnsRefreshLastSuccessfulAt, err == nil}
			if err != nil {
				slog.LogAttrs(ctx, slog.LevelError,
					"failed to resolve ip for host",
					slog.String("host", host),
					slog.Time("resolve_start_at", resolveStartAt),
					slog.Time("resolve_end_at", resolveEndAt),
					slog.String("resolve_duration", resolveEndAt.Sub(resolveStartAt).String()),
					slog.Time("dns_cache_refresh_last_successful_at", dnsRefreshLastSuccessfulAt),
					slog.String("error", err.Error()),
				)
				return true
			}

			slog.LogAttrs(ctx, slog.LevelDebug,
				"refreshDNSCache: got dns response",
				slog.String("host", host),
				slog.Time("resolve_start_at", resolveStartAt),
				slog.Time("resolve_end_at", resolveEndAt),
				slog.String("resolve_duration", resolveEndAt.Sub(resolveStartAt).String()),
				slog.Int("num_ips", len(dnsRecords)),
			)

			rrq.renewTargetIPs(ctx, dnsRefreshLastSuccessfulAt, dnsRecords)

			return true
		})
	}

	// TODO: short circuit if the refresh was unsuccessful up to the
	// MaxDNSCacheRefreshFailureToleranceLifetime configuration value
	//
	// if none is present, then continue with the next operation:
	// trim the DNS cache and idle connections (unless it is suppressed
	// via another configuration option where that circumstance applies)

	d.rrqByHostKeyPort.withRange(func(hostKey string, port uint16, rrq *roundRobinQueue) bool {
		// TODO: if the IP has not been seen in the DNS response for "a while", we should remove it from the queue
		// the AssumeRemovedTimeout should be the difference in time between the last time the IP was seen in the
		// DNS response and the last successful DNS resolution for the hostKey

		//
		// everything after here assumes the hostKey is still valid for the DNS cache retention policy / configuration
		//

		// TODO: the write lock here is a bottleneck,
		// however Next() uses a read lock and can
		// change the nextIdx while this is running
		//
		// since I want to ensure the nextIdx changes if an IP is removed
		// I need to use a write lock here or we need to introduce a lock
		// purely for the mutation of nextIdx
		rrq.ipListRWM.Lock()
		defer rrq.ipListRWM.Unlock()

		rrq.nextIdx = rrq.nextIdx % uint64(len(rrq.ipIdxToState))

		for stIdx := range rrq.ipIdxToState {
			// TODO: parallelize this loop to speed up the DNS cache refresh
			st := &rrq.ipIdxToState[stIdx]
			st.idleConns.WithWriteLock(func(idleConnsPtr *[]*roundRobinConn) {
				idleConns := *idleConnsPtr
				for i := len(idleConns) - 1; i >= 0; i-- {
					conn := idleConns[i]

					err := conn.isActive()
					if err == nil {
						continue
					}

					switch err {
					case errMaxLifespanExceeded, errIdleTimeoutExceeded:
						// every other entry in the LIFO queue is pretty
						// much guaranteed to be older than the one we just checked
						// so we can just close the connections remaining
						// and remove them from the queue
						numClosed := i + 1
						for i := i; i >= 0; i-- {
							conn := idleConns[i]
							func() {
								defer func() {
									if r := recover(); r != nil {
										slog.LogAttrs(ctx, slog.LevelError,
											"panic: roundRobinConn.Close",
											slog.String("remediation", "recovered and ignored"),
											slog.Any("recover", r),
										)
									}
								}()

								ignoredErr := conn.unwrappedClose()
								_ = ignoredErr
							}()
						}

						// shrink the slice to remove the connections that were just closed
						copy(idleConns, idleConns[numClosed:])
						clear(idleConns[len(idleConns)-numClosed:])
						idleConns = idleConns[:len(idleConns)-numClosed]
						*idleConnsPtr = idleConns

						// min ensures value is never negative and the robin attempts to
						// pick up where it left off in the best case scenario
						rrq.nextIdx -= min(rrq.nextIdx, uint64(numClosed))

						return
					}
				}
			})
		}
		// TODO: if there are no idle connections for the hostKey and no checked-out connections, then we should remove the hostKey from the cache

		return true
	})
}

func (d *roundRobinConnector) start(ctx context.Context, refreshInterval time.Duration) {
	ctx, d.stop = context.WithCancel(ctx)
	ctxDone := ctx.Done()

	tmr := time.NewTicker(refreshInterval)
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()

		for {
			// check if the context is done before entering the randomized select block
			select {
			case <-ctxDone:
				return
			default:
			}

			// wait for the next tick or context done
			select {
			case <-ctxDone:
				return
			case <-tmr.C:
			}

			d.refreshDNSCache(ctx)
		}
	}()
}

type roundRobinTransport struct {
	connector *roundRobinConnector
	closeM    sync.Mutex
	closed    bool
}

// errReader is a custom io.Reader that reads from a byte slice and returns an error
// when the end of the slice is reached, simulating an error condition that occurred
// during the reading of a response body io.Reader.
//
// this is useful for conveying errors and the total data read up to that point
// when connection management is fully managed by something like a round-robin transport
type errReader struct {
	b   []byte
	err error
	i   int
	// atErr indicates the terminal read error end state has been reached
	atErr bool
}

func newErrReader(b []byte, err error) *errReader {
	return &errReader{
		b:   b,
		err: err,
	}
}

func (r *errReader) Read(p []byte) (int, error) {
	if r.atErr {
		return 0, r.err
	}

	n := copy(p, r.b[r.i:])
	r.i += n

	if r.i == len(r.b) && n < len(p) {
		r.atErr = true
		return n, r.err
	}

	return n, nil
}

func contextReadAll(ctx context.Context, r io.Reader, closeNetConn func()) ([]byte, error) {
	const networkBufferSize = 32 * 1024

	type result struct {
		data []byte
		err  error
	}

	pr, pw := io.Pipe()
	defer pw.Close()

	var wg sync.WaitGroup
	defer wg.Wait()

	// Use TeeReader to pipe read data into a channel
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer pw.Close()

		_, err := io.CopyBuffer(pw, r, make([]byte, networkBufferSize))
		if err != nil && !errors.Is(err, io.EOF) {
			pw.CloseWithError(err)
		}
	}()

	// Collect from pipe and respect context
	done := make(chan result, 1)

	go func() {
		var b bytes.Buffer

		_, err := b.ReadFrom(pr)
		done <- result{data: b.Bytes(), err: err}
	}()

	ctxDone := ctx.Done()

	select {
	case <-ctxDone:
		err := ctx.Err()
		pr.CloseWithError(err)
		closeNetConn()

		err = fmt.Errorf("connection force-closed: %w", err)

		res := <-done
		if res.err != nil {
			return res.data, errors.Join(res.err, err)
		}

		return res.data, err
	case res := <-done:
		return res.data, res.err
	}
}

func (t *roundRobinTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var conn *roundRobinConn
	closeConn := sync.OnceFunc(func() {
		if conn != nil {
			t.connector.PutClose(conn)
		}
	})
	defer closeConn()

	ctx := req.Context()

	// TODO: if round-trip timeout cfg option is set and enabled, we should wrap the context and replace the request context with the wrapped one

	// get connection and possibly altered request
	{
		v, newReq, err := t.connector.GetOrCreateConnection(req, "tcp", nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create connection to %s: %w", req.URL.Host, err)
		}

		req = newReq
		conn = v
	}

	if err := req.Write(conn); err != nil {
		return nil, err
	}

	resp, err := http.ReadResponse(conn.bufReader, req)
	if err != nil {
		return nil, err
	}

	r := resp.Body
	resp.Body = http.NoBody

	if resp.ProtoMajor < 1 && resp.ProtoMajor > 2 || (resp.ProtoMajor == 1 && (resp.ProtoMinor < 0 || resp.ProtoMinor > 1) || (resp.ProtoMajor == 2 && resp.ProtoMinor != 0)) {
		r.Close()
		return nil, fmt.Errorf("unsupported HTTP protocol version in response %d.%d", resp.ProtoMajor, resp.ProtoMinor)
	}

	b, err := contextReadAll(ctx, r, closeConn)
	lastIdleAt := time.Now()
	if err != nil {
		resp.Body = io.NopCloser(newErrReader(b, err))
		r.Close()
		return resp, nil
	}

	r.Close()
	resp.Body = io.NopCloser(bytes.NewReader(b))

	//
	// negotiate connection reuse based on the request and response protocol versions
	//

	// verify that the request allows connection reuse
	{
		var reqConnection string
		var reqConnectionSet bool
		if v, ok := req.Header["Connection"]; ok {
			switch len(v) {
			case 0:
			case 1:
				reqConnection = v[0]
				reqConnectionSet = true
			default:
				return resp, nil
			}
		}

		// client always uses HTTP/1.1 or HTTP/2, so we can assume safely that if we get back a http 2.0 response the connection is reusable
		//
		// if the request is Connection unspecified, then we assume it is keep-alive enabled as per the HTTP/1.1 spec

		reqAllowsReuse := ((resp.ProtoMajor == 2 && resp.ProtoMinor == 0) || !reqConnectionSet || xstrings.EqualsIgnoreCaseASCII(reqConnection, "keep-alive"))

		if !reqAllowsReuse {
			return resp, nil
		}
	}

	// as a last step, verify that the request allows connection reuse
	{
		var respConnection string
		var respConnectionSet bool
		if v, ok := resp.Header["Connection"]; ok {
			switch len(v) {
			case 0:
			case 1:
				respConnection = v[0]
				respConnectionSet = true
			default:
				return resp, nil
			}
		}

		var respAllowsReuse bool
		switch resp.ProtoMajor {
		case 1:
			if req.ProtoMajor != 1 {
				// a 1.x response cannot be sent as a response to a 2.x or above request (a.k.a. non 1.x request)
				return resp, nil
			}

			switch resp.ProtoMinor {
			case 0:
				respAllowsReuse = xstrings.EqualsIgnoreCaseASCII(respConnection, "keep-alive")
			case 1:
				respAllowsReuse = (!respConnectionSet || xstrings.EqualsIgnoreCaseASCII(respConnection, "keep-alive"))
			}
		case 2:
			switch resp.ProtoMinor {
			case 0:
				respAllowsReuse = true
			}
		}

		if respAllowsReuse && t.connector.Put(conn, lastIdleAt) {
			conn = nil
		}
	}

	return resp, nil
}

func (t *roundRobinTransport) CloseIdleConnections() {
	// t.connector.idleConns // TODO: iterate over the idle queues and close their connection contents
}

func (r *roundRobinTransport) Shutdown() error {
	r.closeM.Lock()
	defer r.closeM.Unlock()

	if r.closed {
		return ErrTransportClosed
	}
	r.closed = true
	return r.connector.shutdown()
}

type RoundRobinTransporter interface {
	http.RoundTripper
	CloseIdleConnections()
	Shutdown() error
}

type wrappedDialer struct {
	d *net.Dialer
}

func (wd wrappedDialer) DialTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	var d net.Dialer
	if wd.d != nil {
		d = *wd.d
		d.Resolver = nil
	}

	d.Timeout = timeout

	return d.Dial(network, address)
}

func newDialer() dialer {
	return wrappedDialer{}
}

func NewRoundRobinTransport(ctx context.Context) RoundRobinTransporter {
	// TODO: allow passing a custom resolver
	resolver := dnsResolver(net.DefaultResolver)

	// TODO: allow passing a custom dialer
	dialer := newDialer()

	connector := &roundRobinConnector{
		resolver:         resolver,
		dialer:           dialer,
		dnsCacheMap:      xsync.NewMap[string, *xnet.DNSCache](),
		rrqByHostKeyPort: newPortMap(),
	}

	const refreshInterval = 30 * time.Second // TODO: parameterize the refresh interval
	connector.start(ctx, refreshInterval)

	return &roundRobinTransport{
		connector: connector,
	}
}
