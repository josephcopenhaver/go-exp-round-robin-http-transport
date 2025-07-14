package xnet

//
// DNS Read Options
//

type dnsReadConfig struct {
	// isAsync indicates that the read operation is for an asynchronous resolution.
	isAsync bool
}

type DNSReadOption func(*dnsReadConfig)

type DNSReadOptions struct{}

func DNSReadOpts() DNSReadOptions {
	return DNSReadOptions{}
}

func (DNSReadOptions) ForAsyncOperation(b bool) DNSReadOption {
	return func(cfg *dnsReadConfig) {
		cfg.isAsync = b
	}
}

//
// DNS Refresh Options
//

type dnsRefreshConfig struct {
	excludeIPs []string
}

type DNSRefreshOption func(*dnsRefreshConfig)

type DNSRefreshOptions struct{}

func DNSRefreshOpts() DNSRefreshOptions {
	return DNSRefreshOptions{}
}

func (DNSRefreshOptions) ExcludeIPs(excludeIPs ...string) DNSRefreshOption {
	return func(cfg *dnsRefreshConfig) {
		cfg.excludeIPs = excludeIPs
	}
}
