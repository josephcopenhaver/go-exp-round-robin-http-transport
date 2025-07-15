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

	"github.com/josephcopenhaver/go-exp-round-robin-http-transport/xascii"
	"github.com/josephcopenhaver/go-exp-round-robin-http-transport/xnet"
	xnet_i "github.com/josephcopenhaver/go-exp-round-robin-http-transport/xnet/internal"
	"github.com/josephcopenhaver/go-exp-round-robin-http-transport/xqueue"
	"github.com/josephcopenhaver/go-exp-round-robin-http-transport/xsync"
	"golang.org/x/sync/semaphore"
)

// maxHostnameLength is the maximum length of a hostname according to RFC 1035 and RFC 1123.
const (
	maxHostnameLength      = 253
	headerValConnKeepAlive = "keep-alive"
	// headerValConnOWS is the set of optional whitespace characters that can be used in the Connection header value between comma separated values and before/after the possible list
	headerValConnOWS = "\x09\x20"
	schemeHTTP       = "http"
	schemeHTTPS      = "https"

	msgErrDialFailed    = "dial failed"
	prefixErrDialFailed = msgErrDialFailed + ": "
)

var (
	ErrTransportClosed           = errors.New("transport closed")
	errMaxLifespanExceeded       = errors.New("connection max lifespan exceeded")
	errIdleTimeoutExceeded       = errors.New("connection idle timeout exceeded")
	errConnectionInactive        = errors.New("connection closed by server or client, or connection is no longer usable for reads/writes due to a network error or timeout")
	errMaxHostnameLengthExceeded = errors.New("hostname exceeds maximum length as per RFC 1035 and RFC 1123")
	ErrDialFailedButCanRetry     = errors.New(msgErrDialFailed)
	errNoHostInRequestURL        = errors.New("http: no Host in request URL")
)

type retryableDialError struct {
	err error
}

func (e *retryableDialError) Error() string {
	return prefixErrDialFailed + e.err.Error()
}

func (e *retryableDialError) Unwrap() error {
	return e.err
}

func (e *retryableDialError) Is(target error) bool {
	return target == ErrDialFailedButCanRetry || errors.Is(e.err, target)
}

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

func (pm portMap) loadOrStore(hostKey string, port uint16, rrq *roundRobinQueue) (*roundRobinQueue, bool) {
	m, ok := pm.m.Load(hostKey)
	if !ok {
		m = xsync.NewMap[uint16, *roundRobinQueue]()
		m, _ = pm.m.LoadOrStore(hostKey, m)
	}
	return m.LoadOrStore(port, rrq)
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
	lastUpdatedAt     time.Time
	ipListRWM         sync.RWMutex
	ipToIdx           xsync.Map[string, int]
	ipIdxToState      []roundRobinIPState
	nextIdx           uint64
	disableDNSRefresh bool
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

	for {
		c, ok := idleConns.Get()
		if !ok {
			return nil, st.ip, false
		}

		// TODO: debug log the issue

		// TODO: short circuit the loop if the error type indicates
		// that the connection is timed-out regardless of the the connection
		// being connected still or not
		//
		// this lets the routine started by roundRobinConnector.start manage cleanup duties

		// if the connection is not active, then close it and try the next one
		if err := c.isActive(); err != nil {
			// cleans up the connection
			ignoredErr := q.putCloseNoLock(c)
			_ = ignoredErr

			continue
		}

		// if the socket deadlines cannot be reset to system defaults, then close it and try the next one
		if err := c.SetDeadline(time.Time{}); err != nil {
			// cleans up the connection
			ignoredErr := q.putCloseNoLock(c)
			_ = ignoredErr

			continue
		}

		// ladies and gentlemen, we have a winner!
		return c, "", true
	}
}

// Put places a connection back into the round-robin queue
func (q *roundRobinQueue) Put(conn *roundRobinConn) bool {
	q.ipListRWM.RLock()
	defer q.ipListRWM.RUnlock()

	i, ok := q.ipToIdx.Load(conn.ipStr)
	if !ok {
		return false
	}

	// TODO: understand ideal relationship between idle timeout and socket configs
	//
	// There is some relationship between the idle timeout and the socket read/write deadlines
	// where we really, really want one to be within or exceed the other.
	var idleDeadline time.Time
	if d := conn.dialer.maxConnIdleTimeout; d != 0 {
		// should actually have a buffer of dialTimeout and 1 second if the connection was never written to or read from
		// the 1 second buffer is to ensure that the connection is not closed immediately after being checked out
		// from the pool going from idle to active-pending states
		idleDeadline = conn.lastIdleAt.Add(d + 1*time.Second)
	}
	if err := conn.SetDeadline(idleDeadline); err != nil {
		// TODO: log the error
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

	const getConnectionTimeout = 10 * time.Second // TODO: parameterize or state-ify this
	const dialTimeout = 5 * time.Second           // TODO: parameterize or state-ify this

	address := req.URL.Host
	var host string
	var port uint16
	{
		h, portStr, splitErr := net.SplitHostPort(address)
		portVal, portErr := strconv.ParseInt(portStr, 10, 32)
		if splitErr != nil {
			host = address
			if len(req.URL.Scheme) == 0 {
				return nil, nil, errors.New("empty scheme in request URL: expected one of http or https")
			}
			if xascii.EqualsIgnoreCase(req.URL.Scheme, schemeHTTP) {
				address = net.JoinHostPort(host, "80")
				port = 80
			} else if xascii.EqualsIgnoreCase(req.URL.Scheme, schemeHTTPS) {
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

	if host == "" {
		return nil, nil, errNoHostInRequestURL
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

	// Note that because we resolve the hostname and connect manually,
	// we do not need to manipulate the request req.Host nor req.URL.Host
	// in any way.
	//
	// Also since we use the req.Write method everything still behaves the
	// same as if we were using standard http.Transport in the sense that
	// the request is sent with the correct Host header and scheme.

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
	ip := net.ParseIP(host)
	if ip == nil {
		slog.LogAttrs(ctx, slog.LevelDebug,
			"not an ip",
			slog.String("host", host),
			slog.String("next_strategy", "resolving name to ip"),
		)

		dialStartTime := time.Now()
		c, err := d.syncDNSAndDial(ctx, tlsConf, req.URL.Scheme, hostKey, network, address, dstIP, dialTimeout, ipNetwork, joinCharIndex, port)
		if err != nil {
			for errors.Is(err, ErrDialFailedButCanRetry) && time.Since(dialStartTime) < getConnectionTimeout {
				c, err = d.syncDNSAndDial(ctx, tlsConf, req.URL.Scheme, hostKey, network, address, dstIP, dialTimeout, ipNetwork, joinCharIndex, port)
				if err == nil {
					return c, req, nil
				}
			}
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
		address = net.JoinHostPort(host, address[joinCharIndex+1:])
		joinCharIndex = len(host)
	}

	c, err := d.syncDNSAndDial(ctx, tlsConf, req.URL.Scheme, hostKey, network, address, dstIP, dialTimeout, ipNetwork, joinCharIndex, port)
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

	// if you need to debug anything, use IsConnected instead of IsConnectedNoErr
	ok := xnet_i.IsConnectedNoErr(c._netConn)
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

type keepAliveObserver interface {
	SetKeepAliveConfig(config net.KeepAliveConfig) error
}

func (d *roundRobinConnector) directIPDial(ctx context.Context, tlsConf *tls.Config, scheme, hostKey, network string, address string, port uint16, dialTimeout time.Duration) (*roundRobinConn, error) {
	// TODO: implement in a cleaner way since this should be much simpler than the DNS resolution and round-robin queue management

	host := hostKey[:len(hostKey)-1]

	if _, ok := d.rrqByHostKeyPort.load(hostKey, port); !ok {
		// note that this approach is only safe on our memory because we do not expect
		// requests to flood the host immediately
		//
		// if I wanted to make sure no unused memory is allocated I would likely need a
		// "stop the world" mutex or a series of mutexes to pair with the hostKey and port
		// and then use a singleflight to ensure that only one goroutine is creating the
		// round-robin queue for the hostKey and port at a time
		//
		// TODO: might still be possible to use singleflight here to ensure that memory
		// is allocated once and only once per hostKey and port
		rrq := &roundRobinQueue{
			ipToIdx:           xsync.NewMap[string, int](),
			ipIdxToState:      []roundRobinIPState{{host, newRRConnLifoQueue(), nil, time.Time{}}},
			disableDNSRefresh: true,
		}
		rrq.ipToIdx.Store(host, 0)

		// calling loadOrStore here and not utilizing results at all is intended
		//
		// this is to ensure that the round-robin queue is stored in the map iff
		// it was not already present in the map
		//
		// so behaves more like "store-if-not-present" rather than "store-or-return-existing"
		d.rrqByHostKeyPort.loadOrStore(hostKey, port, rrq)
	}

	conn, err := d.dialer.DialTimeout(network, address, dialTimeout)
	createdAt := time.Now()
	if err != nil {
		return nil, fmt.Errorf("failed to dial IP directly %s: %w", address, err)
	}
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()

	if c, ok := conn.(keepAliveObserver); ok {

		// TODO: If the Deadlines need to be set differently than the system defaults,
		// it can and should be done here on connection creation - right now they do not.

		err := c.SetKeepAliveConfig(net.KeepAliveConfig{
			// If Enable is true, keep-alive probes are enabled.
			Enable: true,

			// Idle is the time that the connection must be idle before
			// the first keep-alive probe is sent.
			// If zero, a default value of 15 seconds is used.
			//
			// recommend 30–60s to detect dead peer in a minute or less
			Idle: 30 * time.Second,

			// Interval is the time between keep-alive probes.
			// If zero, a default value of 15 seconds is used.
			//
			// recommend 5–10s to detect dead peer in a minute or less
			// and retry keepalive frequently
			Interval: 5 * time.Second,

			// Count is the maximum number of keep-alive probes that
			// can go unanswered before dropping a connection.
			// If zero, a default value of 9 is used.
			//
			// recommended 3–5 to fail fast but tolerate some packet loss
			Count: 3,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to set keep-alive config on connection: %w", err)
		}
	} else {
		return nil, fmt.Errorf("connection does not support SetKeepAliveConfig: %T", conn)
	}

	respConn := conn
	if xascii.EqualsIgnoreCase(scheme, schemeHTTPS) {
		v, err := tlsHandshake(ctx, tlsConf, host, conn, 10*time.Second) // TODO: parameterize or state-ify this
		if err != nil {
			return nil, fmt.Errorf("failed to perform TLS handshake in direct-IP mode: %w", err)
		}
		conn = v
	}
	br := bufio.NewReader(respConn)

	conn = nil
	return &roundRobinConn{respConn, host, br, hostKey, port, createdAt, time.Time{}, d}, nil
}

// TODO: add circuit breaking logic if dialing a host fails with a clear server side connection refusal or similar error

// TOOD: parse port at higher level and pass it as a parameter to this dial function

func (d *roundRobinConnector) syncDNSAndDial(ctx context.Context, tlsConf *tls.Config, scheme, hostKey, network, address, dstIP string, dialTimeout time.Duration, ipNetwork xnet.IPNetwork, joinCharIndex int, port uint16) (*roundRobinConn, error) {

	// const rrCacheTimeout = 130 * time.Second     // TODO: parameterize
	const tlsHandshakeTimeout = 10 * time.Second // TODO: parameterize or state-ify this
	host := hostKey[:len(hostKey)-1]

	if dstIP != "" {
		// if this is a direct IP dial, then we can skip the DNS resolution and round-robin queue management
		if host == dstIP {
			return d.directIPDial(ctx, tlsConf, scheme, hostKey, network, address, port, dialTimeout)
		}

		// attempting to connect to a specific IP address
		conn, err := d.dialer.DialTimeout(network, net.JoinHostPort(dstIP, address[joinCharIndex+1:]), dialTimeout)
		createdAt := time.Now()
		if err != nil {
			if dnsCache, ok := d.dnsCacheMap.Load(hostKey); ok {
				if dnsRefreshLastSuccessfulAt, n, dnsRefreshed, _ := dnsCache.Refresh(ctx, d.resolver, xnet.DNSRefreshOpts().ExcludeIPs(dstIP)); n > 0 {
					_ = dnsRefreshLastSuccessfulAt
					_ = dnsRefreshed
					// TODO: we should likely update the round-robin queue with the new IPs here if the refresh was successful or
					// is more recent than the last update time of the round-robin queue
					return nil, &retryableDialError{err}
				}
			}

			return nil, fmt.Errorf("cannot retry: dial failed: %w", err)
		}
		defer func() {
			if conn != nil {
				conn.Close()
			}
		}()

		if c, ok := conn.(keepAliveObserver); ok {

			// TODO: If the Deadlines need to be set differently than the system defaults,
			// it can and should be done here on connection creation - right now they do not.

			err := c.SetKeepAliveConfig(net.KeepAliveConfig{
				// If Enable is true, keep-alive probes are enabled.
				Enable: true,

				// Idle is the time that the connection must be idle before
				// the first keep-alive probe is sent.
				// If zero, a default value of 15 seconds is used.
				//
				// recommend 30–60s to detect dead peer in a minute or less
				Idle: 30 * time.Second,

				// Interval is the time between keep-alive probes.
				// If zero, a default value of 15 seconds is used.
				//
				// recommend 5–10s to detect dead peer in a minute or less
				// and retry keepalive frequently
				Interval: 5 * time.Second,

				// Count is the maximum number of keep-alive probes that
				// can go unanswered before dropping a connection.
				// If zero, a default value of 9 is used.
				//
				// recommended 3–5 to fail fast but tolerate some packet loss
				Count: 3,
			})
			if err != nil {
				return nil, fmt.Errorf("failed to set keep-alive config on connection: %w", err)
			}
		} else {
			return nil, fmt.Errorf("connection does not support SetKeepAliveConfig: %T", conn)
		}

		slog.LogAttrs(ctx, slog.LevelDebug,
			"new connection",
			slog.String("hostKey", hostKey),
			slog.Int("port", int(port)),
			slog.String("dst_ip", dstIP),
		)

		respConn := conn
		if xascii.EqualsIgnoreCase(scheme, schemeHTTPS) {
			v, err := tlsHandshake(ctx, tlsConf, host, conn, tlsHandshakeTimeout)
			if err != nil {
				return nil, fmt.Errorf("failed to perform TLS handshake: %w", err)
			}

			respConn = v
		}
		br := bufio.NewReader(respConn)

		conn = nil
		return &roundRobinConn{respConn, dstIP, br, hostKey, port, createdAt, time.Time{}, d}, nil
	}

	//
	// determining the destination IP address to dial
	//

	dnsCache, ok := d.dnsCacheMap.Load(hostKey)
	if !ok {
		dnsCache = xnet.NewDNSCache(host, 130*time.Second, 15*time.Second, ipNetwork)
		dnsCache, _ = d.dnsCacheMap.LoadOrStore(hostKey, dnsCache)
	}

	dnsRecords, dnsRefreshLastSuccessfulAt, _, dnsLookupErr := dnsCache.Read(ctx, d.resolver)
	if dnsLookupErr != nil && (dnsRefreshLastSuccessfulAt.IsZero() || len(dnsRecords) == 0) {
		// something is up with the DNS resolver or the DNS cache
		// and there is no last successful DNS refresh time or no DNS records
		//
		// so there is not connection attempt possible and no retry possible
		return nil, dnsLookupErr
	}

	// dnsRecords = dnsRecords[0:1:1] // uncommenting this line will make the code only use the first DNS record and prove that pooling works

	rrq, ok := d.rrqByHostKeyPort.load(hostKey, port)
	if !ok {
		// note that this approach is only safe on our memory because we do not expect
		// requests to flood the host immediately
		//
		// if I wanted to make sure no unused memory is allocated I would likely need a
		// "stop the world" mutex or a series of mutexes to pair with the hostKey and port
		// and then use a singleflight to ensure that only one goroutine is creating the
		// round-robin queue for the hostKey and port at a time
		//
		// TODO: might still be possible to use singleflight here to ensure that memory
		// is allocated once and only once per hostKey and port
		rrq = &roundRobinQueue{
			ipToIdx: xsync.NewMap[string, int](),
			nextIdx: uint64(rand.IntN(len(dnsRecords))),
		}
		rrq.loadInitialDNSRecords(dnsRefreshLastSuccessfulAt, dnsRecords)

		if v, loaded := d.rrqByHostKeyPort.loadOrStore(hostKey, port, rrq); loaded {
			rrq = v
			rrq.renewTargetIPs(dnsRefreshLastSuccessfulAt, dnsRecords)
		}
	} else {
		rrq.renewTargetIPs(dnsRefreshLastSuccessfulAt, dnsRecords)
	}

	c, dstIP, ok := rrq.Next()
	if ok {
		return c, nil
	}

	if dstIP == "" {
		panic("algorithm error: would have created an infinite loop")
	}

	return d.syncDNSAndDial(ctx, tlsConf, scheme, hostKey, network, address, dstIP, dialTimeout, ipNetwork, joinCharIndex, port)
}

func tlsHandshake(ctx context.Context, tlsConf *tls.Config, serverName string, conn net.Conn, timeout time.Duration) (net.Conn, error) {
	if tlsConf == nil {
		tlsConf = &tls.Config{ServerName: serverName}
	} else {
		tlsConf = tlsConf.Clone()
		tlsConf.ServerName = serverName
	}

	tlsConn := tls.Client(conn, tlsConf)

	tlsHandshakeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if err := tlsConn.HandshakeContext(tlsHandshakeCtx); err != nil {
		ignoredErr := conn.Close()
		_ = ignoredErr
		return nil, err
	}

	return tlsConn, nil
}

func (d *roundRobinConnector) shutdown() error {
	d.stop()
	d.wg.Wait()
	return nil
}

func (rrq *roundRobinQueue) needsRefresh(dnsRefreshLastSuccessfulAt time.Time) bool {
	return rrq.lastUpdatedAt.IsZero() || dnsRefreshLastSuccessfulAt.After(rrq.lastUpdatedAt)
}

func (rrq *roundRobinQueue) renewTargetIPs(dnsRefreshLastSuccessfulAt time.Time, dnsRecords []xnet.DNSResponseRecord) {

	rrq.ipListRWM.RLock()
	unlocker := rrq.ipListRWM.RUnlock
	defer func() {
		if f := unlocker; f != nil {
			f()
		}
	}()

	if !rrq.needsRefresh(dnsRefreshLastSuccessfulAt) {
		return
	}

	{
		f := unlocker
		unlocker = nil
		f()

		unlocker = rrq.ipListRWM.Unlock
		rrq.ipListRWM.Lock()
	}

	if !rrq.needsRefresh(dnsRefreshLastSuccessfulAt) {
		return
	}

	// add any new IPs to the round-robin queue
	for i := range dnsRecords {
		v := &dnsRecords[i]
		if i, ok := rrq.ipToIdx.Load(v.IP); ok {
			// update the lastSeenInDNSRespAt value for the existing IP
			rrq.ipIdxToState[i].lastSeenInDNSRespAt = v.LastSeen
			continue
		}

		i := len(rrq.ipIdxToState)
		state := roundRobinIPState{v.IP, newRRConnLifoQueue(), nil, v.LastSeen}
		rrq.ipIdxToState = append(rrq.ipIdxToState, state)
		rrq.ipToIdx.Store(v.IP, i)
	}

	// TODO: trim off any IPs that have not been seen for the AssumeRemovedTimeout duration

	// TODO: adjust nextIDX if required / ideal

	rrq.lastUpdatedAt = dnsRefreshLastSuccessfulAt
}

func (rrq *roundRobinQueue) loadInitialDNSRecords(dnsRefreshLastSuccessfulAt time.Time, dnsRecords []xnet.DNSResponseRecord) {
	rrq.ipIdxToState = make([]roundRobinIPState, 0, len(dnsRecords))

	for i := range dnsRecords {
		v := &dnsRecords[i]

		i := len(rrq.ipIdxToState)
		state := roundRobinIPState{v.IP, newRRConnLifoQueue(), nil, v.LastSeen}
		rrq.ipIdxToState = append(rrq.ipIdxToState, state)
		rrq.ipToIdx.Store(v.IP, i)
	}

	rrq.lastUpdatedAt = dnsRefreshLastSuccessfulAt
}

// refreshCacheLayers is a repeating async operation that refreshes the DNS cache layers
func (d *roundRobinConnector) refreshCacheLayers(ctx context.Context, dnsCacheInactiveTimeout time.Duration) {
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
			if rrq.disableDNSRefresh {
				return true
			}

			if v, ok := seenCache[hostKey]; ok {
				if v.ok {
					rrq.renewTargetIPs(v.dnsLastSuccessfulAt, v.dnsRecords)
				}
				return true
			}

			const dnsTimeout = 10 * time.Second // TODO: parameterize or state-ify

			dnsCtx, cancel := context.WithTimeout(ctx, dnsTimeout)
			defer cancel()

			dnsCache, ok := d.dnsCacheMap.Load(hostKey)
			if !ok {
				// This would mean that the hostname was never resolved and no request has been made
				// to the hostKey's host before - or that the dns record was purposefully removed
				// probably due to a visibility timeout or removal policy or a consistent inability
				// to resolve the hostKey's hostname to any IPs.
				//
				// lets not attempt to resolve the hostKey's hostname if nothing is trying to connect
				// to it anymore or it is now never resolving to any IPs.

				return true
			}

			// If the ip cache for this hostkey has had no "recent read requests" - likely if not
			// since the last two consecutive async refreshes, then we can skip the DNS resolution until that
			// changes.

			if t := dnsCache.LastNonAsyncReadTime(); t.IsZero() || time.Since(t) >= dnsCacheInactiveTimeout {
				return true
			}

			// TODO: it's technically possible to just attempt a refresh and not taint the records
			// slice lifetime by reading the records - we would need to have a callback on refresh
			// that would check if the rrq last update time is older than the dnsRefreshLastSuccessfulAt
			// time and if so then read the records into this context. That is a lot of extra complexity
			// for a small allocation prevention during relative idle time for this connector-host-port
			// combination. It's likely not worth implementing until tests show allocations can be saved
			// and have a meaningful impact on the performance of the connector / runtime GC.

			resolveStartAt := time.Now()
			dnsRecords, dnsRefreshLastSuccessfulAt, _, err := dnsCache.Read(dnsCtx, d.resolver, xnet.DNSReadOpts().ForAsyncOperation(true))
			resolveEndAt := time.Now()
			seenCache[hostKey] = refreshRecord{dnsRecords, dnsRefreshLastSuccessfulAt, err == nil}
			if err != nil {
				slog.LogAttrs(ctx, slog.LevelError,
					"refreshCacheLayers: failed to resolve ip for host",
					slog.String("hostKey", hostKey),
					slog.Time("resolve_start_at", resolveStartAt),
					slog.Time("resolve_end_at", resolveEndAt),
					slog.String("resolve_duration", resolveEndAt.Sub(resolveStartAt).String()),
					slog.Time("dns_cache_refresh_last_successful_at", dnsRefreshLastSuccessfulAt),
					slog.String("error", err.Error()),
				)
				return true
			}

			slog.LogAttrs(ctx, slog.LevelDebug,
				"refreshCacheLayers: got dns response",
				slog.String("hostKey", hostKey),
				slog.Time("resolve_start_at", resolveStartAt),
				slog.Time("resolve_end_at", resolveEndAt),
				slog.String("resolve_duration", resolveEndAt.Sub(resolveStartAt).String()),
				slog.Int("num_ips", len(dnsRecords)),
			)

			rrq.renewTargetIPs(dnsRefreshLastSuccessfulAt, dnsRecords)

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

	dnsCacheInactiveTimeout := refreshInterval*2 + 30*time.Second

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

			d.refreshCacheLayers(ctx, dnsCacheInactiveTimeout)
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

type parseHeaderResult struct {
	Connection struct {
		KeepAlive bool
		NotEmpty  bool
	}
}

// parseHeader returns data about the Connection header in the reply or response.
//
// it just happens to have the same implementation for both request and response headers
// and it computes the result without allocating any memory.
//
// should we need different parsing logic for request and response headers in the future,
// this can and should be split into two functions and two different result structs.
func parseHeader(h http.Header) parseHeaderResult {
	var result, resp parseHeaderResult
	if h == nil {
		return result
	}

	if v, ok := h["Connection"]; ok && len(v) > 0 {
		resp.Connection.NotEmpty = true

		ucbCutset := xascii.UnsafeConstBytes(headerValConnOWS)
		ucbKeepAlive := xascii.UnsafeConstBytes(headerValConnKeepAlive)

	KEEP_ALIVE_SEARCH:
		for _, v := range v {
			if len(v) == 0 {
				continue
			}

			ucbNext := xascii.UnsafeConstBytes(v)
			var ucbCur []byte
			for {
				ucbCur, ucbNext = xascii.CutByte(ucbNext, ',')
				if xascii.EqualsIgnoreCase(xascii.Trim(ucbCur, ucbCutset), ucbKeepAlive) {
					resp.Connection.KeepAlive = true
					break KEEP_ALIVE_SEARCH
				}
				if len(ucbNext) == 0 {
					break
				}
			}
		}
	}

	result = resp
	return result
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
		reqH := parseHeader(req.Header)

		// client always uses HTTP/1.1 or HTTP/2, so we can assume safely that if we get back a http 2.0 response the connection is reusable
		//
		// if the request is Connection unspecified, then we assume it is keep-alive enabled as per the HTTP/1.1 spec

		reqAllowsReuse := ((resp.ProtoMajor == 2 && resp.ProtoMinor == 0) || !reqH.Connection.NotEmpty || reqH.Connection.KeepAlive)

		if !reqAllowsReuse {
			return resp, nil
		}
	}

	// as a last step, verify that the request allows connection reuse
	{
		respH := parseHeader(resp.Header)

		var respAllowsReuse bool
		switch resp.ProtoMajor {
		case 1:
			if req.ProtoMajor != 1 {
				// a 1.x response cannot be sent as a response to a 2.x or above request (a.k.a. non 1.x request)
				return resp, nil
			}

			switch resp.ProtoMinor {
			case 0:
				respAllowsReuse = respH.Connection.KeepAlive
			case 1:
				respAllowsReuse = (!respH.Connection.NotEmpty || respH.Connection.KeepAlive)
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
