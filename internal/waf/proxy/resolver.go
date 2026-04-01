package proxy

import (
	"context"
	"net/url"
)

// Target is a single backend endpoint ready for proxying.
type Target struct {
	Addr   string // ip:port or host:port (used as URL host in ReverseProxy)
	Key    string // stable identity for reconciliation (FQDN:port for SRV, url string for static)
	Scheme string // optional: per-target scheme override (e.g. "https" for static targets)
}

// Resolver discovers backend targets.
type Resolver interface {
	Resolve(ctx context.Context) ([]Target, error)
}

// Static returns a Resolver that always returns the given targets.
func Static(urls []*url.URL) Resolver {
	targets := make([]Target, len(urls))
	for i, u := range urls {
		targets[i] = Target{Addr: u.Host, Key: u.String(), Scheme: u.Scheme}
	}

	return &staticResolver{targets: targets}
}

type staticResolver struct {
	targets []Target
}

func (r *staticResolver) Resolve(_ context.Context) ([]Target, error) {
	return r.targets, nil
}
