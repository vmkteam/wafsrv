package rpc

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// DiscoveryConfig holds schema discovery configuration.
type DiscoveryConfig struct {
	SchemaURL string        // absolute URL to fetch schema
	Refresh   time.Duration // refresh interval
}

// Discovery fetches and caches JSON-RPC method schema from a backend.
type Discovery struct {
	mu          sync.RWMutex
	methods     map[string]bool
	methodList  []string
	lastRefresh time.Time
	lastErr     error

	cfg    DiscoveryConfig
	client *http.Client
	logger *slog.Logger
}

// NewDiscovery creates a new schema discovery.
func NewDiscovery(cfg DiscoveryConfig, logger *slog.Logger) *Discovery {
	return &Discovery{
		cfg:    cfg,
		client: &http.Client{Timeout: 10 * time.Second},
		logger: logger,
	}
}

// Start performs initial fetch and starts background refresh.
// Initial fetch retries up to 3 times. If all fail, starts with empty method set (fail-open).
func (d *Discovery) Start(ctx context.Context) {
	// initial fetch with retries
	for range 3 {
		if err := d.refresh(ctx); err == nil {
			break
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}

	// background refresh
	go d.loop(ctx)
}

func (d *Discovery) loop(ctx context.Context) {
	ticker := time.NewTicker(d.cfg.Refresh)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := d.refresh(ctx); err != nil {
				d.logger.WarnContext(ctx, "schema refresh failed", "url", d.cfg.SchemaURL, "error", err)
			}
		}
	}
}

func (d *Discovery) refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.cfg.SchemaURL, nil)
	if err != nil {
		d.setError(err)
		return err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "wafsrv/1.0")

	resp, err := d.client.Do(req)
	if err != nil {
		d.setError(err)
		return fmt.Errorf("rpc: schema fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("rpc: schema fetch: HTTP %d", resp.StatusCode)
		d.setError(err)

		return err
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
	if err != nil {
		d.setError(err)
		return fmt.Errorf("rpc: schema read: %w", err)
	}

	methods, err := ParseSchema(body)
	if err != nil {
		d.setError(err)
		return err
	}

	d.setMethods(methods)

	d.logger.InfoContext(ctx, "schema refreshed", "url", d.cfg.SchemaURL, "methods", len(methods))

	return nil
}

func (d *Discovery) setMethods(methods []string) {
	set := make(map[string]bool, len(methods))
	for _, m := range methods {
		set[m] = true
	}

	d.mu.Lock()
	d.methods = set
	d.methodList = methods
	d.lastRefresh = time.Now()
	d.lastErr = nil
	d.mu.Unlock()
}

func (d *Discovery) setError(err error) {
	d.mu.Lock()
	d.lastErr = err
	d.mu.Unlock()
}

// IsKnown returns true if the method is in the schema, or if schema is not loaded (fail-open).
func (d *Discovery) IsKnown(method string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.methods == nil {
		return true // fail-open: schema not loaded yet
	}

	return d.methods[method]
}

// Loaded returns true if schema has been successfully loaded at least once.
func (d *Discovery) Loaded() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()

	return d.methods != nil
}

// Methods returns the current method list.
func (d *Discovery) Methods() []string {
	d.mu.RLock()
	defer d.mu.RUnlock()

	return d.methodList
}

// MethodCount returns the number of known methods.
func (d *Discovery) MethodCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()

	return len(d.methods)
}

// DiscoveryStatus holds discovery status for dashboard.
type DiscoveryStatus struct {
	Enabled     bool      `json:"enabled"`
	MethodCount int       `json:"methodCount"`
	LastRefresh time.Time `json:"lastRefresh"`
	LastError   string    `json:"lastError,omitempty"`
}

// Status returns current discovery status.
func (d *Discovery) Status() DiscoveryStatus {
	d.mu.RLock()
	defer d.mu.RUnlock()

	s := DiscoveryStatus{
		Enabled:     true,
		MethodCount: len(d.methods),
		LastRefresh: d.lastRefresh,
	}

	if d.lastErr != nil {
		s.LastError = d.lastErr.Error()
	}

	return s
}

// ResolveSchemaURL resolves a relative schema URL against a backend target.
func ResolveSchemaURL(schemaURL, target string) string {
	if schemaURL == "" {
		return ""
	}

	// absolute URL
	if strings.HasPrefix(schemaURL, "http://") || strings.HasPrefix(schemaURL, "https://") {
		return schemaURL
	}

	// relative → append to target
	target = strings.TrimRight(target, "/")

	if !strings.HasPrefix(schemaURL, "/") {
		schemaURL = "/" + schemaURL
	}

	return target + schemaURL
}
