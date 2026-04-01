package app

import (
	"bytes"
	"fmt"
	"hash/fnv"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"wafsrv/internal/waf"
	"wafsrv/internal/waf/event"
	"wafsrv/internal/waf/proxy"
	"wafsrv/internal/waf/rpc"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
)

// Middleware is a function that wraps an http.Handler.
type Middleware func(http.Handler) http.Handler

// Chain composes middlewares left to right: Chain(a, b, c)(h) = a(b(c(h))).
func Chain(middlewares ...Middleware) Middleware {
	return func(final http.Handler) http.Handler {
		for i := len(middlewares) - 1; i >= 0; i-- {
			final = middlewares[i](final)
		}

		return final
	}
}

type accessLogConfig struct {
	logger          *slog.Logger
	serviceName     string
	requestsTotal   *prometheus.CounterVec
	requestDuration *prometheus.HistogramVec
	recorder        *event.Recorder
	platformSet     map[string]struct{}
}

func accessLog(cfg accessLogConfig) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

			// create RequestContext here so it's accessible in defer via rc pointer.
			// initContext fills in fields (RequestID, Platform, etc.) downstream.
			// Without this, r.WithContext() in initContext creates a new *Request,
			// leaving the outer r with the old context — making FromContext(r.Context()) nil in defer.
			rc := &waf.RequestContext{}
			r = r.WithContext(waf.NewContext(r.Context(), rc))

			defer func() {
				if rvr := recover(); rvr != nil {
					stack := make([]byte, 4096)
					stack = stack[:runtime.Stack(stack, false)]
					cfg.logger.ErrorContext(r.Context(), "panic recovered", "panic", rvr, "stack", string(stack))
					rec.WriteHeader(http.StatusBadGateway)
				}

				duration := time.Since(start)

				// prometheus (all requests)
				platform := normalizePlatform(rc.Platform, cfg.platformSet)
				trafficType := "unsigned"
				if rc.TrafficType != "" {
					trafficType = rc.TrafficType
				}

				cfg.requestsTotal.WithLabelValues(cfg.serviceName, r.Method, statusBucket(rec.status), platform, trafficType).Inc()
				cfg.requestDuration.WithLabelValues(cfg.serviceName, r.Method, rc.Target).Observe(duration.Seconds())

				// per-target error rate
				if rc.Target != "" {
					cfg.recorder.RecordTargetResult(rc.Target, rec.status >= 500)
				}

				// time series (all requests)
				cfg.recorder.RecordIncoming()
				cfg.recorder.RecordLatency(duration)

				// top-N and bandwidth (all requests)
				recordAccessTops(cfg.recorder, r, rec, rc)

				// access log (all requests)
				logAccessEntry(cfg.logger, r, rec, rc, duration, cfg.serviceName)
			}()

			next.ServeHTTP(rec, r)
		})
	}
}

func recordAccessTops(recorder *event.Recorder, r *http.Request, rec *statusRecorder, rc *waf.RequestContext) {
	recorder.RecordBytesSent(rec.size)

	if rc == nil {
		return
	}

	country := ""
	if rc.IP != nil {
		country = rc.IP.Country
	}

	isBlocked := rec.status == http.StatusForbidden || rec.status == http.StatusTooManyRequests || rec.status == 499
	recorder.RecordTops(rc.ClientIP.String(), r.URL.Path, country, rc.Platform, isBlocked)

	if ua := r.UserAgent(); ua != "" {
		recorder.RecordUA(ua)
	}

	if ref := r.Referer(); ref != "" {
		recorder.RecordReferer(ref)
	}

	if rc.IP != nil && rc.IP.ASNOrg != "" {
		recorder.RecordASN(rc.IP.ASNOrg)
	}
}

func logAccessEntry(logger *slog.Logger, r *http.Request, rec *statusRecorder, rc *waf.RequestContext, duration time.Duration, serviceName string) {
	attrs := make([]slog.Attr, 0, 16) //nolint:mnd
	attrs = append(attrs, []slog.Attr{
		slog.String("service", serviceName),
		slog.String("method", r.Method),
		slog.String("host", r.Host),
		slog.String("path", r.URL.Path),
		slog.Int("status", rec.status),
		slog.Int64("durationMs", duration.Milliseconds()),
		slog.Int("bytesSent", rec.size),
		slog.String("userAgent", r.UserAgent()),
	}...)

	attrs = append(attrs, accessLogRCAttrs(rc)...)

	logger.LogAttrs(r.Context(), slog.LevelInfo, "request", attrs...)
}

// initContext fills RequestContext fields and sets X-Request-ID.
// The RequestContext is created earlier in accessLog middleware.
func initContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if id == "" {
			id = uuid.NewString()
		}

		platform := strings.ToLower(r.Header.Get("Platform"))

		if rc := waf.FromContext(r.Context()); rc != nil {
			rc.RequestID = id
			rc.Platform = platform
			rc.Version = r.Header.Get("Version")
			rc.Discriminator = computeDiscriminator(platform, r.UserAgent())
		}

		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r)
	})
}

func realIP(headers []string, trusted []netip.Prefix) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if rc := waf.FromContext(r.Context()); rc != nil {
				rc.ClientIP = proxy.ExtractIP(r, headers, trusted)
			}

			next.ServeHTTP(w, r)
		})
	}
}

func staticBypass(cfg StaticConfig) Middleware {
	if len(cfg.Paths) == 0 && len(cfg.Extensions) == 0 {
		return nil
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet && isStatic(r.URL.Path, cfg) {
				if rc := waf.FromContext(r.Context()); rc != nil {
					rc.Static = true
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

func isStaticRequest(r *http.Request) bool {
	rc := waf.FromContext(r.Context())
	return rc != nil && rc.Static
}

func isStatic(path string, cfg StaticConfig) bool {
	for _, p := range cfg.Paths {
		if strings.HasPrefix(path, p) {
			return true
		}
	}

	dot := strings.LastIndexByte(path, '.')
	if dot < 0 {
		return false
	}

	ext := strings.ToLower(path[dot:])
	for _, e := range cfg.Extensions {
		if ext == e {
			return true
		}
	}

	return false
}

var rpcBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, rpc.MaxParseSize)
		return &b
	},
}

func rpcParser(endpoints []JSONRPCEndpoint) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost && r.Body != nil && !isStaticRequest(r) {
				if ep := matchRPCPath(r.URL.Path, endpoints); ep != nil {
					parseRPCBody(r, ep.Name)
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

func matchRPCPath(path string, endpoints []JSONRPCEndpoint) *JSONRPCEndpoint {
	for i := range endpoints {
		if strings.HasPrefix(path, endpoints[i].Path) {
			return &endpoints[i]
		}
	}

	return nil
}

func parseRPCBody(r *http.Request, endpointName string) {
	bufp, _ := rpcBufPool.Get().(*[]byte)
	buf := (*bufp)[:0]

	n, err := io.ReadFull(io.LimitReader(r.Body, rpc.MaxParseSize), buf[:cap(buf)])
	buf = buf[:n]

	if err != nil && err != io.ErrUnexpectedEOF {
		*bufp = buf[:0]
		rpcBufPool.Put(bufp)

		return
	}

	if len(buf) == 0 {
		*bufp = buf[:0]
		rpcBufPool.Put(bufp)

		return
	}

	// copy data out of pooled buffer before returning it
	body := make([]byte, len(buf))
	copy(body, buf)

	*bufp = buf[:0]
	rpcBufPool.Put(bufp)

	// restore body for downstream handlers
	r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), r.Body))

	call := rpc.Parse(body, endpointName)
	if call == nil {
		return
	}

	call.Body = body // save for sign field extraction

	if rc := waf.FromContext(r.Context()); rc != nil {
		rc.RPC = call
	}
}

func bodyLimit(maxBytes int64) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Body != nil && maxBytes > 0 {
				r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			}

			next.ServeHTTP(w, r)
		})
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status      int
	size        int
	wroteHeader bool
}

func (r *statusRecorder) WriteHeader(code int) {
	if !r.wroteHeader {
		r.status = code
		r.wroteHeader = true
	}

	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if !r.wroteHeader {
		r.status = http.StatusOK
		r.wroteHeader = true
	}

	n, err := r.ResponseWriter.Write(b)
	r.size += n

	return n, err
}

// Flush implements http.Flusher — required for httputil.ReverseProxy streaming.
func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap returns the underlying ResponseWriter for http.ResponseController.
func (r *statusRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}

type observeConfig struct {
	rpcRequestsTotal *prometheus.CounterVec
	serviceName      string
	recorder         *event.Recorder
	platformSet      map[string]struct{}
}

// observe records prometheus metrics for requests that reach the backend.
func observe(cfg observeConfig) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			next.ServeHTTP(w, r)
			duration := time.Since(start)

			cfg.recorder.RecordRequest(false)

			rc := waf.FromContext(r.Context())
			if rc != nil && rc.RPC != nil {
				platform := normalizePlatform(rc.Platform, cfg.platformSet)
				for _, m := range rc.RPC.Methods {
					cfg.rpcRequestsTotal.WithLabelValues(cfg.serviceName, m, platform, rc.RPC.Endpoint).Inc()
					cfg.recorder.RecordMethodLatency(m, duration)
					cfg.recorder.RecordRPCMethod(m)
				}
			}
		})
	}
}

func accessLogRCAttrs(rc *waf.RequestContext) []slog.Attr {
	if rc == nil {
		return nil
	}

	attrs := []slog.Attr{
		slog.String("requestId", rc.RequestID),
		slog.String("clientIp", rc.ClientIP.String()),
	}

	if rc.IP != nil && rc.IP.Country != "" {
		attrs = append(attrs, slog.String("country", rc.IP.Country))
	}

	if rc.IP != nil && rc.IP.ASNOrg != "" {
		attrs = append(attrs, slog.String("asnOrg", rc.IP.ASNOrg))
	}

	if rc.Platform != "" {
		attrs = append(attrs, slog.String("platform", rc.Platform))
	}

	if rc.Version != "" {
		attrs = append(attrs, slog.String("version", rc.Version))
	}

	attrs = append(attrs, slog.String("discriminator", rc.Discriminator))

	if rc.RPC != nil {
		attrs = append(attrs, slog.Any("rpcMethods", rc.RPC.Methods))
	}

	if rc.Decision != 0 {
		attrs = append(attrs, slog.String("decision", rc.Decision.String()))
	}

	if rc.WAFScore > 0 {
		attrs = append(attrs, slog.Float64("wafScore", rc.WAFScore))
	}

	if rc.Static {
		attrs = append(attrs, slog.Bool("static", true))
	}

	return attrs
}

// normalizePlatform returns the platform name if it's in the known set, or "other".
// Empty platform is returned as-is (browser/SSR).
func normalizePlatform(platform string, known map[string]struct{}) string {
	if platform == "" {
		return ""
	}

	if _, ok := known[platform]; ok {
		return platform
	}

	return "other"
}

func statusBucket(code int) string {
	switch {
	case code < 200:
		return "1xx"
	case code < 300:
		return "2xx"
	case code < 400:
		return "3xx"
	case code < 500:
		return "4xx"
	default:
		return "5xx"
	}
}

// parseSize parses human-readable size strings like "1KB", "5MB", "100MB".
func parseSize(s string, def int64) int64 {
	if s == "" {
		return def
	}

	s = strings.TrimSpace(s)

	// find where digits end and suffix begins
	i := 0
	for i < len(s) && (s[i] == '.' || (s[i] >= '0' && s[i] <= '9')) {
		i++
	}

	if i == 0 {
		return def
	}

	num, err := strconv.ParseFloat(s[:i], 64)
	if err != nil {
		return def
	}

	suffix := strings.TrimLeftFunc(s[i:], unicode.IsSpace)
	suffix = strings.ToUpper(suffix)

	var multiplier int64

	switch suffix {
	case "B", "":
		multiplier = 1
	case "K", "KB", "KIB":
		multiplier = 1 << 10
	case "M", "MB", "MIB":
		multiplier = 1 << 20
	case "G", "GB", "GIB":
		multiplier = 1 << 30
	default:
		return def
	}

	result := int64(num * float64(multiplier))
	if result <= 0 {
		return def
	}

	return result
}

// parseDuration parses a duration string, returning def on error.
func parseDuration(s string, def time.Duration) time.Duration {
	if s == "" {
		return def
	}

	d, err := time.ParseDuration(s)
	if err != nil {
		return def
	}

	return d
}

// computeDiscriminator returns Platform + ":" + fnv32a(userAgent) as hex.
func computeDiscriminator(platform, ua string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(ua))

	return platform + ":" + strconv.FormatUint(uint64(h.Sum32()), 16)
}

func parseFallbackAction(s string) waf.Action {
	switch s {
	case "block":
		return waf.ActionBlock
	case "log":
		return waf.ActionLog
	default:
		return waf.ActionPass
	}
}

// parseSizeString validates a size string. Returns error with field name if invalid.
func parseSizeString(s, field string) error {
	if s == "" {
		return nil
	}

	if parseSize(s, -1) == -1 {
		return fmt.Errorf("config: invalid size %q for %s (use e.g. 1MB, 10MB, 1KB)", s, field)
	}

	return nil
}
