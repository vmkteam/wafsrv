package limit

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"wafsrv/internal/waf"
	"wafsrv/internal/waf/event"
	"wafsrv/internal/waf/storage"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/vmkteam/embedlog"
)

// Metrics holds rate limiter prometheus metrics.
type Metrics struct {
	ExceededTotal *prometheus.CounterVec
	Recorder      *event.Recorder
}

// Config holds rate limiter configuration.
type Config struct {
	PerIP       Rate
	Action      string // "block" | "throttle"
	MaxCounters int
	RetryAfter  time.Duration // sent as Retry-After header on 429
	Rules       []Rule        // RPC method matching
	URLRules    []URLRule     // HTTP path/method/host matching
}

// Rule defines a per-method rate limit (JSON-RPC matching).
type Rule struct {
	Name     string
	Endpoint string // JSONRPC.Endpoints[].Name, "" = all
	Match    []string
	Limit    Rate
	Action   string
}

// URLRule defines a per-URL rate limit (HTTP path/method/host matching).
// AND-semantics across non-empty fields.
type URLRule struct {
	Name   string
	Path   []string // URL path prefix list
	Method []string // HTTP method list, e.g. ["GET","POST"]
	Host   []string // HTTP Host header list (optional, for multi-host wafsrv)
	Limit  Rate
	Action string
}

// Rate is a parsed rate limit (count per duration).
type Rate struct {
	Count    int
	Duration time.Duration
}

// ParseRate parses "100/min" format into Rate.
func ParseRate(s string) (Rate, error) {
	parts := strings.SplitN(s, "/", 2)
	if len(parts) != 2 {
		return Rate{}, fmt.Errorf("limit: invalid rate format %q (expected N/unit)", s)
	}

	count, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return Rate{}, fmt.Errorf("limit: invalid rate count %q: %w", parts[0], err)
	}

	var dur time.Duration

	switch strings.TrimSpace(parts[1]) {
	case "sec", "second":
		dur = time.Second
	case "min", "minute":
		dur = time.Minute
	case "hour":
		dur = time.Hour
	default:
		return Rate{}, fmt.Errorf("limit: invalid rate unit %q (use sec/min/hour)", parts[1])
	}

	return Rate{Count: count, Duration: dur}, nil
}

// Limiter provides per-IP and per-method rate limiting.
type Limiter struct {
	cfg     Config
	counter storage.Counter
	embedlog.Logger
	metrics Metrics
}

// New creates a new Limiter.
func New(cfg Config, counter storage.Counter, sl embedlog.Logger, metrics Metrics) *Limiter {
	return &Limiter{
		cfg:     cfg,
		counter: counter,
		Logger:  sl,
		metrics: metrics,
	}
}

// Middleware returns an HTTP middleware that enforces rate limits.
func (l *Limiter) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rc := waf.FromContext(r.Context())
			if rc == nil {
				next.ServeHTTP(w, r)
				return
			}

			// skip static assets and whitelisted IPs
			if rc.Static || rc.SignedLevel >= 2 || (rc.IP != nil && rc.IP.Whitelisted) {
				next.ServeHTTP(w, r)
				return
			}

			if !l.allowIP(rc.ClientIP.String()) {
				rc.Decision = waf.ActionThrottle
				l.metrics.ExceededTotal.WithLabelValues("per_ip", l.cfg.Action).Inc()
				l.Print(r.Context(), "rate_limit",
					"clientIp", rc.ClientIP.String(),
					"rule", "per_ip",
					"action", l.cfg.Action,
				)
				l.addEvent(rc.ClientIP.String(), r.URL.Path, "per_ip", rc.Platform)
				l.reject(w)

				return
			}

			if rc.RPC != nil {
				if rule := l.matchRule(rc.RPC); rule != nil {
					if !l.enforce(w, r, rc, rule.Name, rule.Action, rule.Limit) {
						return
					}
				}
			}

			if rule := l.matchURLRule(r); rule != nil {
				if !l.enforce(w, r, rc, rule.Name, rule.Action, rule.Limit) {
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

func (l *Limiter) allowIP(ip string) bool {
	allowed, _ := l.counter.Allow("ip:"+ip, l.cfg.PerIP.Count, l.cfg.PerIP.Duration)
	return allowed
}

func (l *Limiter) allowKey(key string, rt Rate) bool {
	allowed, _ := l.counter.Allow("m:"+key, rt.Count, rt.Duration)
	return allowed
}

func (l *Limiter) matchRule(rpc *waf.RPCCall) *Rule {
	for i := range l.cfg.Rules {
		rule := &l.cfg.Rules[i]

		// endpoint filter
		if rule.Endpoint != "" && rule.Endpoint != rpc.Endpoint {
			continue
		}

		for _, method := range rpc.Methods {
			for _, match := range rule.Match {
				if method == match {
					return rule
				}
			}
		}
	}

	return nil
}

func (l *Limiter) matchURLRule(r *http.Request) *URLRule {
	for i := range l.cfg.URLRules {
		rule := &l.cfg.URLRules[i]

		if len(rule.Path) > 0 && !hasAnyPrefix(rule.Path, r.URL.Path) {
			continue
		}

		if len(rule.Method) > 0 && !contains(rule.Method, r.Method) {
			continue
		}

		if len(rule.Host) > 0 && !contains(rule.Host, r.Host) {
			continue
		}

		return rule
	}

	return nil
}

// enforce applies rate limit for a matched rule. Returns false if request was rejected.
func (l *Limiter) enforce(w http.ResponseWriter, r *http.Request, rc *waf.RequestContext, name, action string, rt Rate) bool {
	key := rc.ClientIP.String() + ":" + rc.Discriminator + ":" + name
	if l.allowKey(key, rt) {
		return true
	}

	rc.Decision = waf.ActionThrottle
	l.metrics.ExceededTotal.WithLabelValues(name, action).Inc()
	l.addEvent(rc.ClientIP.String(), r.URL.Path, name, rc.Platform)
	l.Print(r.Context(), "rate_limit",
		"clientIp", rc.ClientIP.String(),
		"rule", name,
		"action", action,
	)
	l.reject(w)

	return false
}

func hasAnyPrefix(list []string, value string) bool {
	for _, p := range list {
		if strings.HasPrefix(value, p) {
			return true
		}
	}

	return false
}

func contains(list []string, value string) bool {
	for _, v := range list {
		if v == value {
			return true
		}
	}

	return false
}

func (l *Limiter) addEvent(clientIP, path, rule, platform string) {
	l.metrics.Recorder.AddEvent(event.Event{
		Type:     "rate_limit",
		ClientIP: clientIP,
		Path:     path,
		Detail:   rule,
	})
	l.metrics.Recorder.RecordRateLimited(clientIP, path, platform)
}

func (l *Limiter) reject(w http.ResponseWriter) {
	w.Header().Set(waf.HeaderAction, waf.ActionHeaderThrottle)

	if l.cfg.RetryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int(l.cfg.RetryAfter.Seconds())))
	}

	http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
}
