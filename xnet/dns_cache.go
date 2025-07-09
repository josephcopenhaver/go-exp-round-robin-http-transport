package xnet

import (
	"context"
	"errors"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrHostNotFound = errors.New("host not found")
)

type dnsResolver interface {
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
}

type IPNetwork uint8

const (
	IPNetworkUnified IPNetwork = iota + 1
	IPNetworkV4
	IPNetworkV6
)

func (i IPNetwork) String() string {
	if i < IPNetworkUnified || i > IPNetworkV6 {
		return ""
	}

	return []string{
		"ip",
		"ip4",
		"ip6",
	}[i-1]
}

type DNSResponseRecord struct {
	LastSeen time.Time
	IP       string
}

type DNSCache struct {
	rwm                           sync.RWMutex
	records                       []DNSResponseRecord
	host                          string
	lastRefreshedAt               time.Time
	lastRefreshSucceededAt        time.Time
	lastRefreshError              error
	staleTimeout                  time.Duration
	errStaleTimeout               time.Duration
	recordVisibilityTimeout       time.Duration
	numConsecutiveRefreshFailures int
	replaceRecords                int32
	ipNetwork                     IPNetwork
}

func NewDNSCache(host string, staleTimeout, errStaleTimeout time.Duration, ipNetwork IPNetwork) *DNSCache {
	return &DNSCache{
		host:            host,
		staleTimeout:    staleTimeout,
		errStaleTimeout: errStaleTimeout,
		ipNetwork:       ipNetwork,
	}
}

func (c *DNSCache) needsRefresh() bool {
	if c.lastRefreshedAt.IsZero() {
		return true
	}

	var staleTimeout time.Duration
	if c.lastRefreshSucceededAt.IsZero() || c.lastRefreshSucceededAt.Before(c.lastRefreshedAt) {
		staleTimeout = c.errStaleTimeout
	} else {
		staleTimeout = c.staleTimeout
	}

	return time.Since(c.lastRefreshedAt) >= staleTimeout
}

func (c *DNSCache) Refresh(ctx context.Context, resolver dnsResolver) (time.Time, int, bool, error) {

	//
	// TODO: use a singleflight operation here to avoid concurrent executors since they should all use the same result
	//

	c.rwm.RLock()
	unlocker := c.rwm.RUnlock
	defer func() {
		if f := unlocker; f != nil {
			unlocker = nil
			f()
		}
	}()

	if !c.needsRefresh() {
		if len(c.records) == 0 {
			if c.lastRefreshError == nil {
				return c.lastRefreshSucceededAt, 0, false, ErrHostNotFound
			}
			return c.lastRefreshSucceededAt, 0, false, c.lastRefreshError
		}
		return c.lastRefreshSucceededAt, len(c.records), false, c.lastRefreshError
	}

	{
		f := unlocker
		unlocker = nil
		f()

		unlocker = c.rwm.Unlock
		c.rwm.Lock()
	}

	if !c.needsRefresh() {
		if len(c.records) == 0 {
			if c.lastRefreshError == nil {
				return c.lastRefreshSucceededAt, 0, false, ErrHostNotFound
			}
			return c.lastRefreshSucceededAt, 0, false, c.lastRefreshError
		}
		return c.lastRefreshSucceededAt, len(c.records), false, c.lastRefreshError
	}

	c.refresh(ctx, resolver)

	if len(c.records) == 0 {
		if c.lastRefreshError == nil {
			return c.lastRefreshSucceededAt, 0, false, ErrHostNotFound
		}
		return c.lastRefreshSucceededAt, 0, false, c.lastRefreshError
	}

	return c.lastRefreshSucceededAt, len(c.records), true, c.lastRefreshError
}

func (c *DNSCache) Read(ctx context.Context, resolver dnsResolver) (_records []DNSResponseRecord, _lastRefreshSuccessAt time.Time, _refreshed bool, _lastRefreshError error) {
	//
	// TODO: use a singleflight operation here to avoid concurrent executors since they should all use the same result
	//

	c.rwm.RLock()
	unlocker := c.rwm.RUnlock
	defer func() {
		if f := unlocker; f != nil {
			unlocker = nil
			f()
		}
	}()

	if !c.needsRefresh() {
		if len(c.records) == 0 {
			if c.lastRefreshError == nil {
				return nil, c.lastRefreshSucceededAt, false, ErrHostNotFound
			}
			return nil, c.lastRefreshSucceededAt, false, c.lastRefreshError
		}

		atomic.StoreInt32(&c.replaceRecords, 1)
		return c.records, c.lastRefreshSucceededAt, false, c.lastRefreshError
	}

	{
		f := unlocker
		unlocker = nil
		f()

		unlocker = c.rwm.Unlock
		c.rwm.Lock()
	}

	if !c.needsRefresh() {
		if len(c.records) == 0 {
			if c.lastRefreshError == nil {
				return nil, c.lastRefreshSucceededAt, false, ErrHostNotFound
			}
			return nil, c.lastRefreshSucceededAt, false, c.lastRefreshError
		}

		atomic.StoreInt32(&c.replaceRecords, 1)
		return c.records, c.lastRefreshSucceededAt, false, c.lastRefreshError
	}

	c.refresh(ctx, resolver)

	if len(c.records) == 0 {
		if c.lastRefreshError == nil {
			return nil, c.lastRefreshSucceededAt, true, ErrHostNotFound
		}
		return nil, c.lastRefreshSucceededAt, true, c.lastRefreshError
	}

	atomic.StoreInt32(&c.replaceRecords, 1)
	return c.records, c.lastRefreshSucceededAt, true, c.lastRefreshError
}

func (c *DNSCache) refresh(ctx context.Context, resolver dnsResolver) {
	rawIPs, err := resolver.LookupIP(ctx, c.ipNetwork.String(), c.host)
	c.lastRefreshedAt = time.Now()
	if err != nil {
		c.numConsecutiveRefreshFailures++
		c.lastRefreshError = err
		return
	}

	var seenIPs map[string]struct{}
	{
		seenIPs = make(map[string]struct{}, len(rawIPs))
		for _, rawIP := range rawIPs {
			ip := rawIP.String()
			if _, seen := seenIPs[ip]; seen {
				continue
			}
			seenIPs[ip] = struct{}{}
		}
	}

	if c.replaceRecords == 0 {
		// no need to replace the records slice, so just going to update it in place
		//
		// we would need to replace it if something had read it and might be holding a reference to it
		// or a sub-slice
		records := c.records

		for i := range records {
			v := &records[i]
			if _, ok := seenIPs[v.IP]; ok {
				delete(seenIPs, v.IP)
				v.LastSeen = c.lastRefreshedAt
			}
		}

		records = slices.DeleteFunc(records, func(record DNSResponseRecord) bool {
			return c.lastRefreshedAt.Sub(record.LastSeen) >= c.recordVisibilityTimeout
		})

		records = slices.Grow(records, len(seenIPs))
		for k := range seenIPs {
			records = append(records, DNSResponseRecord{c.lastRefreshedAt, k})
		}

		c.numConsecutiveRefreshFailures = 0
		c.lastRefreshError = nil
		c.lastRefreshSucceededAt = c.lastRefreshedAt
		c.records = records

		return
	}

	var numToRemove int
	for i := range c.records {
		if _, ok := seenIPs[c.records[i].IP]; !ok && c.lastRefreshedAt.Sub(c.records[i].LastSeen) >= c.recordVisibilityTimeout {
			numToRemove++
		}
	}

	newRecords := make([]DNSResponseRecord, 0, len(seenIPs)+len(c.records)-numToRemove)
	for i := range c.records {
		v := &c.records[i]
		var lastSeen time.Time
		if _, ok := seenIPs[v.IP]; ok {
			delete(seenIPs, v.IP)
			lastSeen = c.lastRefreshedAt
		} else if c.lastRefreshedAt.Sub(v.LastSeen) >= c.recordVisibilityTimeout {
			continue
		} else {
			lastSeen = v.LastSeen
		}

		newRecords = append(newRecords, DNSResponseRecord{lastSeen, v.IP})
	}

	for k := range seenIPs {
		newRecords = append(newRecords, DNSResponseRecord{c.lastRefreshedAt, k})
	}

	c.numConsecutiveRefreshFailures = 0
	c.lastRefreshError = nil
	c.lastRefreshSucceededAt = c.lastRefreshedAt
	c.records = newRecords
	c.replaceRecords = 0
}
