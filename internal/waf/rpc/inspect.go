package rpc

import (
	"net/http"

	"wafsrv/internal/waf"
	"wafsrv/internal/waf/event"

	"github.com/prometheus/client_golang/prometheus"
)

// InspectConfig holds per-endpoint inspection configuration.
type InspectConfig struct {
	Endpoint        string // endpoint name
	MethodWhitelist bool
	MaxBatchSize    int
}

// InspectMetrics holds prometheus metrics for RPC inspection.
type InspectMetrics struct {
	InspectTotal *prometheus.CounterVec // labels: endpoint, action
	Recorder     *event.Recorder
}

// Inspector performs JSON-RPC deep inspection (method whitelist + batch limit).
type Inspector struct {
	configs    map[string]InspectConfig // endpoint name → config
	discoverer map[string]*Discovery    // endpoint name → discovery (may be nil)
	metrics    InspectMetrics
}

// NewInspector creates a new RPC inspector.
func NewInspector(configs []InspectConfig, discoverer map[string]*Discovery, metrics InspectMetrics) *Inspector {
	cfgMap := make(map[string]InspectConfig, len(configs))
	for _, c := range configs {
		cfgMap[c.Endpoint] = c
	}

	return &Inspector{
		configs:    cfgMap,
		discoverer: discoverer,
		metrics:    metrics,
	}
}

// Middleware returns an HTTP middleware that inspects JSON-RPC requests.
func (ins *Inspector) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rc := waf.FromContext(r.Context())
			if rc == nil || rc.RPC == nil {
				next.ServeHTTP(w, r)
				return
			}

			cfg, ok := ins.configs[rc.RPC.Endpoint]
			if !ok {
				next.ServeHTTP(w, r)
				return
			}

			// batch size check
			if cfg.MaxBatchSize > 0 && rc.RPC.BatchSize > cfg.MaxBatchSize {
				ins.metrics.InspectTotal.WithLabelValues(cfg.Endpoint, "batch_exceeded").Inc()
				ins.addEvent(rc, r.URL.Path, "batch_exceeded")
				http.Error(w, "Batch size exceeded", http.StatusForbidden)

				return
			}

			// method whitelist check
			if cfg.MethodWhitelist {
				if d, ok := ins.discoverer[cfg.Endpoint]; ok {
					for _, method := range rc.RPC.Methods {
						if !d.IsKnown(method) {
							ins.metrics.InspectTotal.WithLabelValues(cfg.Endpoint, "method_blocked").Inc()
							ins.addEvent(rc, r.URL.Path, "method_blocked:"+method)
							http.Error(w, "Method not allowed", http.StatusForbidden)

							return
						}
					}
				}
			}

			ins.metrics.InspectTotal.WithLabelValues(cfg.Endpoint, "pass").Inc()
			next.ServeHTTP(w, r)
		})
	}
}

// Discoveries returns discoverer map for status reporting.
func (ins *Inspector) Discoveries() map[string]*Discovery {
	return ins.discoverer
}

func (ins *Inspector) addEvent(rc *waf.RequestContext, path, detail string) {
	if ins.metrics.Recorder == nil {
		return
	}

	ins.metrics.Recorder.AddEvent(event.Event{
		Type:     "rpc_inspect",
		ClientIP: rc.ClientIP.String(),
		Path:     path,
		Detail:   detail,
	})
}
