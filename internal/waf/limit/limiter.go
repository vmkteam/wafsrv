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
	Rules       []Rule
}

// Rule defines a per-method rate limit.
type Rule struct {
	Name     string
	Endpoint string // JSONRPC.Endpoints[].Name, "" = all
	Match    []string
	Limit    Rate
	Action   string
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
					key := rc.ClientIP.String() + ":" + rc.Discriminator + ":" + rule.Name
					if !l.allowKey(key, rule.Limit) {
						l.metrics.ExceededTotal.WithLabelValues(rule.Name, rule.Action).Inc()
						l.addEvent(rc.ClientIP.String(), r.URL.Path, rule.Name, rc.Platform)
						l.Print(r.Context(), "rate_limit",
							"clientIp", rc.ClientIP.String(),
							"rule", rule.Name,
							"action", rule.Action,
						)
						l.reject(w)

						return
					}
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
	w.Header().Set("Retry-After", "60")
	http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
}
