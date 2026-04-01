package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
)

// SRVResolverConfig configures the SRV DNS resolver.
type SRVResolverConfig struct {
	Hostname  string // SRV record name (e.g. "apisrv.service.consul")
	Service   string // SRV service field (e.g. "http"), empty = direct lookup
	Proto     string // SRV proto field (e.g. "tcp"), empty = direct lookup
	DNSServer string // custom DNS server (e.g. "127.0.0.1:8600"), empty = system DNS
}

// NewSRVResolver creates a Resolver that discovers backends via DNS SRV + A/AAAA records.
func NewSRVResolver(cfg SRVResolverConfig) Resolver {
	r := &srvResolver{
		hostname: cfg.Hostname,
		service:  cfg.Service,
		proto:    cfg.Proto,
	}

	if cfg.DNSServer != "" {
		r.resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, network, cfg.DNSServer)
			},
		}
	} else {
		r.resolver = net.DefaultResolver
	}

	return r
}

type srvResolver struct {
	resolver *net.Resolver
	hostname string
	service  string
	proto    string
}

func (r *srvResolver) Resolve(ctx context.Context) ([]Target, error) {
	_, addrs, err := r.resolver.LookupSRV(ctx, r.service, r.proto, r.hostname)
	if err != nil {
		return nil, fmt.Errorf("proxy: SRV lookup %s: %w", r.hostname, err)
	}

	if len(addrs) == 0 {
		return nil, fmt.Errorf("proxy: SRV returned 0 records for %s", r.hostname)
	}

	// filter by priority: only lowest priority group
	sort.Slice(addrs, func(i, j int) bool {
		return addrs[i].Priority < addrs[j].Priority
	})
	minPriority := addrs[0].Priority

	var targets []Target
	var errs []error

	for _, a := range addrs {
		if a.Priority != minPriority {
			break // sorted — only higher priority remains
		}

		host := strings.TrimSuffix(a.Target, ".") // SRV trailing dot
		port := strconv.Itoa(int(a.Port))
		key := net.JoinHostPort(host, port)

		// resolve A/AAAA via same resolver
		ips, lookupErr := r.resolver.LookupHost(ctx, host)
		if lookupErr != nil {
			errs = append(errs, fmt.Errorf("proxy: A/AAAA for %s: %w", host, lookupErr))
			continue
		}

		if len(ips) == 0 {
			errs = append(errs, fmt.Errorf("proxy: no A/AAAA for %s", host))
			continue
		}

		targets = append(targets, Target{
			Addr: net.JoinHostPort(ips[0], port),
			Key:  key,
		})
	}

	if len(targets) == 0 && len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	return targets, errors.Join(errs...) // partial success: targets + errors
}
