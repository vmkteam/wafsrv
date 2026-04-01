package rpc

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"wafsrv/internal/waf"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/suite"
)

type InspectSuite struct {
	suite.Suite
}

func TestInspect(t *testing.T) {
	suite.Run(t, new(InspectSuite))
}

func (s *InspectSuite) TestMethodWhitelistPass() {
	ins := s.newInspector(true, 0, []string{"auth.login", "catalog.search"})

	handler := ins.Middleware()(okHandler())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, s.rpcRequest("auth.login"))

	s.Equal(http.StatusOK, w.Code)
}

func (s *InspectSuite) TestMethodWhitelistBlock() {
	ins := s.newInspector(true, 0, []string{"auth.login"})

	handler := ins.Middleware()(okHandler())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, s.rpcRequest("admin.delete"))

	s.Equal(http.StatusForbidden, w.Code)
	s.Contains(w.Body.String(), "Method not allowed")
}

func (s *InspectSuite) TestBatchLimitPass() {
	ins := s.newInspector(false, 5, nil)

	handler := ins.Middleware()(okHandler())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, s.batchRequest(3))

	s.Equal(http.StatusOK, w.Code)
}

func (s *InspectSuite) TestBatchLimitExceeded() {
	ins := s.newInspector(false, 2, nil)

	handler := ins.Middleware()(okHandler())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, s.batchRequest(5))

	s.Equal(http.StatusForbidden, w.Code)
	s.Contains(w.Body.String(), "Batch size exceeded")
}

func (s *InspectSuite) TestBatchLimitZeroNoLimit() {
	ins := s.newInspector(false, 0, nil)

	handler := ins.Middleware()(okHandler())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, s.batchRequest(100))

	s.Equal(http.StatusOK, w.Code)
}

func (s *InspectSuite) TestFailOpenNoSchema() {
	// whitelist enabled but no discovery → pass
	ins := NewInspector(
		[]InspectConfig{{Endpoint: "main", MethodWhitelist: true}},
		map[string]*Discovery{}, // no discovery for "main"
		testInspectMetrics(),
	)

	handler := ins.Middleware()(okHandler())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, s.rpcRequest("anything"))

	s.Equal(http.StatusOK, w.Code)
}

func (s *InspectSuite) TestNonRPCPassThrough() {
	ins := s.newInspector(true, 5, []string{"auth.login"})

	handler := ins.Middleware()(okHandler())
	w := httptest.NewRecorder()

	// no RPC call in context
	r := httptest.NewRequest(http.MethodGet, "/static/main.js", nil)
	rc := &waf.RequestContext{ClientIP: netip.MustParseAddr("1.1.1.1")}
	r = r.WithContext(waf.NewContext(r.Context(), rc))

	handler.ServeHTTP(w, r)

	s.Equal(http.StatusOK, w.Code)
}

func (s *InspectSuite) TestDiscoveryParseSMD() {
	// mock SMD server
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		smd := map[string]any{
			"services": map[string]any{
				"auth.login":     map[string]any{},
				"catalog.search": map[string]any{},
			},
		}
		json.NewEncoder(w).Encode(smd)
	}))
	defer srv.Close()

	d := NewDiscovery(DiscoveryConfig{SchemaURL: srv.URL, Refresh: 0}, slog.Default())

	// manual fetch
	err := d.refresh(s.T().Context())
	s.Require().NoError(err)

	s.True(d.IsKnown("auth.login"))
	s.True(d.IsKnown("catalog.search"))
	s.False(d.IsKnown("admin.delete"))
	s.Equal(2, d.MethodCount())
}

func (s *InspectSuite) newInspector(whitelist bool, maxBatch int, methods []string) *Inspector {
	configs := []InspectConfig{{
		Endpoint:        "main",
		MethodWhitelist: whitelist,
		MaxBatchSize:    maxBatch,
	}}

	discoveries := map[string]*Discovery{}

	if len(methods) > 0 {
		d := NewDiscovery(DiscoveryConfig{}, nil)
		d.setMethods(methods)
		discoveries["main"] = d
	}

	return NewInspector(configs, discoveries, testInspectMetrics())
}

func (s *InspectSuite) rpcRequest(method string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/rpc/", nil)
	rc := &waf.RequestContext{
		ClientIP: netip.MustParseAddr("1.1.1.1"),
		RPC:      &waf.RPCCall{Endpoint: "main", Methods: []string{method}},
	}

	return r.WithContext(waf.NewContext(r.Context(), rc))
}

func (s *InspectSuite) batchRequest(size int) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/rpc/", nil)

	methods := make([]string, size)
	for i := range size {
		methods[i] = "method." + string(rune('a'+i%26))
	}

	rc := &waf.RequestContext{
		ClientIP: netip.MustParseAddr("1.1.1.1"),
		RPC:      &waf.RPCCall{Endpoint: "main", Methods: methods, IsBatch: true, BatchSize: size},
	}

	return r.WithContext(waf.NewContext(r.Context(), rc))
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func testInspectMetrics() InspectMetrics {
	return InspectMetrics{
		InspectTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "test_rpc_inspect_total",
			Help: "test",
		}, []string{"endpoint", "action"}),
	}
}
