package app

import (
	"wafsrv/internal/waf/adaptive"
	"wafsrv/internal/waf/decide"
	"wafsrv/internal/waf/engine"
	"wafsrv/internal/waf/event"
	"wafsrv/internal/waf/filter"
	"wafsrv/internal/waf/ip"
	"wafsrv/internal/waf/limit"
	"wafsrv/internal/waf/rpc"
	"wafsrv/internal/waf/sign"

	"github.com/prometheus/client_golang/prometheus"
)

// Metric names — single source of truth for all wafsrv prometheus metrics.
const (
	metricRequestsTotal      = "wafsrv_requests_total"
	metricRequestDuration    = "wafsrv_request_duration_seconds"
	metricRPCRequestsTotal   = "wafsrv_rpc_requests_total"
	metricIPBlockedTotal     = "wafsrv_ip_blocked_total"
	metricIPWhitelistedTotal = "wafsrv_ip_whitelisted_total"
	metricTrafficFilterTotal = "wafsrv_traffic_filter_total"
	metricRateLimitExceeded  = "wafsrv_ratelimit_exceeded_total"
	metricWAFBlockedTotal    = "wafsrv_waf_blocked_total"
	metricDecisionTotal      = "wafsrv_decision_total"
	metricSignTotal          = "wafsrv_sign_total"
	metricRPCInspectTotal    = "wafsrv_rpc_inspect_total"
	metricAdaptiveTrigger    = "wafsrv_adaptive_trigger_total"
	metricAdaptiveAttack     = "wafsrv_adaptive_attack_total"
)

// appMetrics holds all prometheus metrics for the application.
type appMetrics struct {
	registry *prometheus.Registry

	// global (access log middleware)
	requestsTotal    *prometheus.CounterVec
	requestDuration  *prometheus.HistogramVec
	rpcRequestsTotal *prometheus.CounterVec

	// ip intelligence
	ipBlockedTotal     *prometheus.CounterVec
	ipWhitelistedTotal prometheus.Counter

	// traffic filter
	filterMatchedTotal *prometheus.CounterVec

	// rate limiting
	rateLimitExceeded *prometheus.CounterVec

	// WAF engine
	wafBlockedTotal *prometheus.CounterVec

	// decision engine
	decisionTotal *prometheus.CounterVec

	// signing
	signTotal *prometheus.CounterVec

	// rpc inspect
	rpcInspectTotal *prometheus.CounterVec

	// adaptive
	adaptiveTrigger *prometheus.CounterVec
	adaptiveAttack  *prometheus.CounterVec
}

// newMetrics creates all prometheus metrics and registers them.
func newMetrics() *appMetrics {
	m := &appMetrics{
		registry: prometheus.NewRegistry(),

		requestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: metricRequestsTotal,
			Help: "Total number of proxied requests.",
		}, []string{"service", "method", "status", "platform", "traffic_type"}),

		requestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    metricRequestDuration,
			Help:    "Request duration in seconds.",
			Buckets: prometheus.DefBuckets,
		}, []string{"service", "method", "target"}),

		rpcRequestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: metricRPCRequestsTotal,
			Help: "Total number of JSON-RPC method calls.",
		}, []string{"service", "rpc_method", "platform", "endpoint"}),

		ipBlockedTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: metricIPBlockedTotal,
			Help: "Total blocked requests by IP rules.",
		}, []string{"reason"}),

		ipWhitelistedTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: metricIPWhitelistedTotal,
			Help: "Total whitelisted requests.",
		}),

		filterMatchedTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: metricTrafficFilterTotal,
			Help: "Total traffic filter matches.",
		}, []string{"rule", "action"}),

		rateLimitExceeded: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: metricRateLimitExceeded,
			Help: "Total rate limit exceeded events.",
		}, []string{"rule", "action"}),

		wafBlockedTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: metricWAFBlockedTotal,
			Help: "Total WAF interceptions by rule ID.",
		}, []string{"rule_id"}),

		decisionTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: metricDecisionTotal,
			Help: "Total decisions by action.",
		}, []string{"action", "platform"}),

		signTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: metricSignTotal,
			Help: "Total signing verifications.",
		}, []string{"platform", "result"}),

		rpcInspectTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: metricRPCInspectTotal,
			Help: "Total RPC inspection results.",
		}, []string{"endpoint", "action"}),

		adaptiveTrigger: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: metricAdaptiveTrigger,
			Help: "Total adaptive trigger activations.",
		}, []string{"trigger"}),

		adaptiveAttack: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: metricAdaptiveAttack,
			Help: "Total adaptive auto-attack mode toggles.",
		}, []string{"action"}),
	}

	m.registry.MustRegister(
		m.requestsTotal,
		m.requestDuration,
		m.rpcRequestsTotal,
		m.ipBlockedTotal,
		m.ipWhitelistedTotal,
		m.filterMatchedTotal,
		m.rateLimitExceeded,
		m.wafBlockedTotal,
		m.decisionTotal,
		m.signTotal,
		m.rpcInspectTotal,
		m.adaptiveTrigger,
		m.adaptiveAttack,
	)

	return m
}

// ipMetrics returns ip.Metrics populated from appMetrics.
func (m *appMetrics) ipMetrics(rec *event.Recorder) ip.Metrics {
	return ip.Metrics{
		BlockedTotal:     m.ipBlockedTotal,
		WhitelistedTotal: m.ipWhitelistedTotal,
		Recorder:         rec,
	}
}

// filterMetrics returns filter.Metrics populated from appMetrics.
func (m *appMetrics) filterMetrics(rec *event.Recorder) filter.Metrics {
	return filter.Metrics{
		MatchedTotal: m.filterMatchedTotal,
		Recorder:     rec,
	}
}

// limitMetrics returns limit.Metrics populated from appMetrics.
func (m *appMetrics) limitMetrics(rec *event.Recorder) limit.Metrics {
	return limit.Metrics{
		ExceededTotal: m.rateLimitExceeded,
		Recorder:      rec,
	}
}

// engineMetrics returns engine.Metrics populated from appMetrics.
func (m *appMetrics) engineMetrics(rec *event.Recorder) engine.Metrics {
	return engine.Metrics{
		BlockedTotal: m.wafBlockedTotal,
		Recorder:     rec,
	}
}

// signMetrics returns sign.Metrics populated from appMetrics.
func (m *appMetrics) signMetrics(rec *event.Recorder) sign.Metrics {
	return sign.Metrics{
		Total:    m.signTotal,
		Recorder: rec,
	}
}

// decideMetrics returns decide.Metrics populated from appMetrics.
func (m *appMetrics) decideMetrics(rec *event.Recorder, platformSet map[string]struct{}) decide.Metrics {
	return decide.Metrics{
		DecisionTotal: m.decisionTotal,
		Recorder:      rec,
		PlatformSet:   platformSet,
	}
}

// inspectMetrics returns rpc.InspectMetrics populated from appMetrics.
func (m *appMetrics) inspectMetrics(rec *event.Recorder) rpc.InspectMetrics {
	return rpc.InspectMetrics{
		InspectTotal: m.rpcInspectTotal,
		Recorder:     rec,
	}
}

// adaptiveMetrics returns adaptive.Metrics populated from appMetrics.
func (m *appMetrics) adaptiveMetrics() adaptive.Metrics {
	return adaptive.Metrics{
		TriggerTotal: m.adaptiveTrigger,
		AttackTotal:  m.adaptiveAttack,
	}
}
