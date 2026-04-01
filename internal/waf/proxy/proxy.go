package proxy

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync/atomic"
	"time"

	"wafsrv/internal/waf"

	"github.com/sony/gobreaker/v2"
)

var errBackend5xx = errors.New("proxy: backend returned 5xx")

// Config holds proxy configuration.
type Config struct {
	Scheme         string // URL scheme for backends (default "http")
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration // used by http.Server in app
	IdleTimeout    time.Duration // used by http.Server in app
	MaxRequestBody int64         // used by bodyLimit middleware in app
	CBEnabled      bool
	CBThreshold    uint32
	CBTimeout      time.Duration
	TrustedProxies []string // used by realIP middleware in app
	RealIPHeaders  []string // used by realIP middleware in app

	// Discovery refresh settings. Zero values = no refresh (static mode).
	RefreshInterval time.Duration
	ResolveTimeout  time.Duration
}

// ResolveResult describes the result of a single resolve+reconcile cycle.
type ResolveResult struct {
	Backends int
	Added    int
	Removed  int
	Error    error // nil = success, non-nil = resolve failed (old pool kept)
}

// ProxyStatus describes the current state of the proxy.
type ProxyStatus struct {
	Targets []TargetStatus `json:"targets"`
}

// TargetStatus describes a single target's status.
type TargetStatus struct {
	URL   string `json:"url"`
	State string `json:"state"` // "closed" | "open" | "half-open" | "n/a"
}

// backend is a single backend endpoint with its own circuit breaker.
type backend struct {
	url   *url.URL
	proxy *httputil.ReverseProxy
	cb    *gobreaker.CircuitBreaker[*http.Response]
	name  string // host:port for metrics/logging
	key   string // stable identity for reconciliation
}

// pool is an immutable snapshot of backends, swapped atomically.
type pool struct {
	backends []*backend
}

// Proxy is a reverse proxy with dynamic backend discovery and per-backend circuit breakers.
type Proxy struct {
	pool      atomic.Pointer[pool]
	idx       atomic.Uint64 // round-robin counter, stable across pool swaps
	transport http.RoundTripper
	scheme    string

	// discovery
	resolver       Resolver
	refresh        time.Duration
	resolveTimeout time.Duration

	// circuit breaker config
	cbEnabled   bool
	cbThreshold uint32
	cbTimeout   time.Duration
}

// LatencyRecorder records per-target latency.
type LatencyRecorder interface {
	RecordTargetLatency(target string, d time.Duration)
}

// New creates a new Proxy. Resolver determines the source of backends:
//
//	proxy.New(cfg, proxy.Static(urls))         — static targets
//	proxy.New(cfg, proxy.NewSRVResolver(dcfg)) — DNS SRV discovery
//
// If initial resolve fails, Proxy is created with an empty pool (503 until first successful resolve).
func New(cfg Config, resolver Resolver) (*Proxy, error) {
	scheme := cfg.Scheme
	if scheme == "" {
		scheme = "http"
	}

	p := &Proxy{
		transport:      newTransport(cfg.ReadTimeout),
		scheme:         scheme,
		resolver:       resolver,
		refresh:        cfg.RefreshInterval,
		resolveTimeout: cfg.ResolveTimeout,
		cbEnabled:      cfg.CBEnabled,
		cbThreshold:    cfg.CBThreshold,
		cbTimeout:      cfg.CBTimeout,
	}

	// initial resolve
	targets, err := resolver.Resolve(context.Background())
	if err == nil && len(targets) > 0 {
		p.reconcile(targets)
	}

	return p, err
}

// Run starts the refresh loop. Blocks until ctx.Done().
// For static resolver (refresh=0) returns immediately.
// Callback is called after each resolve cycle for logging/metrics in app.
func (p *Proxy) Run(ctx context.Context, onResolve func(ResolveResult)) {
	if p.refresh <= 0 {
		return
	}

	ticker := time.NewTicker(p.refresh)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rctx, cancel := context.WithTimeout(ctx, p.resolveTimeout)
			targets, err := p.resolver.Resolve(rctx)
			cancel()

			var result ResolveResult
			if err != nil || len(targets) == 0 {
				result = ResolveResult{Error: err}
			} else {
				added, removed := p.reconcile(targets)
				pl := p.pool.Load()
				result = ResolveResult{
					Backends: len(pl.backends),
					Added:    added,
					Removed:  removed,
				}
			}

			if onResolve != nil {
				onResolve(result)
			}
		}
	}
}

// Handler returns an http.Handler that proxies requests.
func (p *Proxy) Handler() http.Handler {
	return p.HandlerWithLatency(nil)
}

// HandlerWithLatency returns an http.Handler that proxies requests and records per-target latency.
func (p *Proxy) HandlerWithLatency(lr LatencyRecorder) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pl := p.pool.Load()
		if pl == nil || len(pl.backends) == 0 {
			http.Error(w, "no backends available", http.StatusServiceUnavailable)
			return
		}

		idx := p.nextIdx(len(pl.backends))
		b := pl.backends[idx]

		if rc := waf.FromContext(r.Context()); rc != nil {
			rc.Target = b.name
		}

		if lr != nil {
			start := time.Now()
			b.proxy.ServeHTTP(w, r)
			lr.RecordTargetLatency(b.url.String(), time.Since(start))
		} else {
			b.proxy.ServeHTTP(w, r)
		}
	})
}

// Status returns the current proxy status including per-backend circuit breaker state.
func (p *Proxy) Status() ProxyStatus {
	pl := p.pool.Load()
	if pl == nil {
		return ProxyStatus{}
	}

	targets := make([]TargetStatus, len(pl.backends))
	for i, b := range pl.backends {
		state := "n/a"
		if b.cb != nil {
			state = b.cb.State().String()
		}
		targets[i] = TargetStatus{URL: b.url.String(), State: state}
	}

	return ProxyStatus{Targets: targets}
}

// Backends returns the number of backends in the current pool.
func (p *Proxy) Backends() int {
	pl := p.pool.Load()
	if pl == nil {
		return 0
	}

	return len(pl.backends)
}

// FirstBackendURL returns the URL of the first backend (for schema discovery fallback).
func (p *Proxy) FirstBackendURL() string {
	pl := p.pool.Load()
	if pl == nil || len(pl.backends) == 0 {
		return ""
	}

	return pl.backends[0].url.String()
}

func (p *Proxy) nextIdx(n int) uint64 {
	if n == 1 {
		return 0
	}

	return (p.idx.Add(1) - 1) % uint64(n)
}

func (p *Proxy) reconcile(targets []Target) (added, removed int) {
	old := p.pool.Load()
	oldMap := make(map[string]*backend)
	if old != nil {
		for _, b := range old.backends {
			oldMap[b.key] = b
		}
	}

	newBackends := make([]*backend, 0, len(targets))
	for _, t := range targets {
		if b, ok := oldMap[t.Key]; ok && b.name == t.Addr {
			newBackends = append(newBackends, b) // reuse proxy + CB + connections
			delete(oldMap, t.Key)
		} else {
			newBackends = append(newBackends, p.newBackend(t))
			if ok {
				delete(oldMap, t.Key) // IP changed — recreate
			}
			added++
		}
	}
	removed = len(oldMap)

	p.pool.Store(&pool{backends: newBackends})

	return added, removed
}

func (p *Proxy) newBackend(t Target) *backend {
	scheme := p.scheme
	if t.Scheme != "" {
		scheme = t.Scheme
	}

	u := &url.URL{Scheme: scheme, Host: t.Addr}
	b := &backend{
		url:  u,
		name: t.Addr,
		key:  t.Key,
	}

	if p.cbEnabled {
		b.cb = gobreaker.NewCircuitBreaker[*http.Response](gobreaker.Settings{ //nolint:bodyclose // false positive: generic type parameter, not an HTTP call
			Name:        t.Addr,
			MaxRequests: 1,
			Timeout:     p.cbTimeout,
			ReadyToTrip: func(counts gobreaker.Counts) bool {
				return counts.ConsecutiveFailures >= p.cbThreshold
			},
		})
	}

	b.proxy = &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = u.Scheme
			req.URL.Host = u.Host
			req.Host = u.Host
			if _, ok := req.Header["User-Agent"]; !ok {
				req.Header.Set("User-Agent", "")
			}
		},
		Transport: wrappedTransport(p.transport, b.cb),
	}

	return b
}

func wrappedTransport(transport http.RoundTripper, cb *gobreaker.CircuitBreaker[*http.Response]) http.RoundTripper {
	if cb == nil {
		return transport
	}

	return roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		resp, err := cb.Execute(func() (*http.Response, error) {
			resp, err := transport.RoundTrip(r)
			if err != nil {
				return nil, err
			}

			// count 5xx as failures for circuit breaker, but still return the response
			if resp.StatusCode >= http.StatusInternalServerError {
				return resp, errBackend5xx
			}

			return resp, nil
		})

		// circuit breaker returns both resp and err for 5xx — pass resp through
		if resp != nil {
			return resp, nil
		}

		return nil, err
	})
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func newTransport(timeout time.Duration) *http.Transport {
	return &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: timeout,
	}
}
