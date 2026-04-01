package app

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"wafsrv/internal/waf/proxy"

	"github.com/stretchr/testify/suite"
	"github.com/vmkteam/embedlog"
)

type AppSuite struct {
	suite.Suite
	backend *httptest.Server
	app     *App
}

func TestApp(t *testing.T) {
	suite.Run(t, new(AppSuite))
}

func (s *AppSuite) SetupTest() {
	s.backend = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.Method == http.MethodPost {
			body, _ := io.ReadAll(r.Body)
			_, _ = w.Write(body)
			return
		}

		_, _ = w.Write([]byte(`{"result":"ok"}`))
	}))

	cfg := Config{
		Proxy: ProxyConfig{
			Listen:      ":0",
			Targets:     []string{s.backend.URL},
			ServiceName: "test-svc",
			Timeouts:    TimeoutsConfig{Read: "5s", Write: "5s", Idle: "30s"},
			Limits:      LimitsConfig{MaxRequestBody: "1MB"},
			RealIP:      RealIPConfig{Headers: []string{"X-Real-IP"}, TrustedProxies: []string{"10.0.0.0/8"}},
		},
		Management: ManagementConfig{Listen: ":0"},
	}

	sl := embedlog.NewLogger(false, true)
	var err error
	s.app, err = New("wafsrv", sl, cfg)
	s.Require().NoError(err)
}

func (s *AppSuite) TearDownTest() {
	s.backend.Close()
}

func (s *AppSuite) TestDataHandler_GET() {
	trusted, _ := proxy.ParseTrustedProxies([]string{"10.0.0.0/8"})
	handler := s.app.buildDataHandler(trusted)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/test")
	s.Require().NoError(err)
	defer resp.Body.Close()

	s.Equal(http.StatusOK, resp.StatusCode, "should proxy GET successfully")
	s.NotEmpty(resp.Header.Get("X-Request-ID"), "should set X-Request-ID")

	body, _ := io.ReadAll(resp.Body)
	s.JSONEq(`{"result":"ok"}`, string(body))
}

func (s *AppSuite) TestDataHandler_POST_RPC() {
	trusted, _ := proxy.ParseTrustedProxies([]string{"10.0.0.0/8"})
	handler := s.app.buildDataHandler(trusted)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	rpcBody := `{"jsonrpc":"2.0","method":"auth.login","params":{"email":"test@test.com"},"id":1}`
	resp, err := http.Post(ts.URL+"/rpc/", "application/json", strings.NewReader(rpcBody))
	s.Require().NoError(err)
	defer resp.Body.Close()

	s.Equal(http.StatusOK, resp.StatusCode, "should proxy JSON-RPC POST")

	body, _ := io.ReadAll(resp.Body)
	s.Contains(string(body), "auth.login", "should pass RPC body through")
}

func (s *AppSuite) TestDataHandler_RequestID_Passthrough() {
	trusted, _ := proxy.ParseTrustedProxies([]string{"10.0.0.0/8"})
	handler := s.app.buildDataHandler(trusted)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/", nil)
	req.Header.Set("X-Request-ID", "custom-id-123")
	resp, err := http.DefaultClient.Do(req)
	s.Require().NoError(err)
	defer resp.Body.Close()

	s.Equal("custom-id-123", resp.Header.Get("X-Request-ID"), "should preserve existing X-Request-ID")
}

func (s *AppSuite) TestMgmtHandler_Health() {
	handler := s.app.buildMgmtHandler()
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/health")
	s.Require().NoError(err)
	defer resp.Body.Close()

	s.Equal(http.StatusOK, resp.StatusCode)

	var result map[string]string
	err = json.NewDecoder(resp.Body).Decode(&result)
	s.Require().NoError(err)
	s.Equal("ok", result["status"])
}

func (s *AppSuite) TestMgmtHandler_RPC_StatusGet() {
	handler := s.app.buildMgmtHandler()
	ts := httptest.NewServer(handler)
	defer ts.Close()

	rpcBody := `{"jsonrpc":"2.0","method":"status.get","id":1}`
	resp, err := http.Post(ts.URL+"/rpc/", "application/json", strings.NewReader(rpcBody))
	s.Require().NoError(err)
	defer resp.Body.Close()

	s.Equal(http.StatusOK, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	s.Contains(string(body), "test-svc", "should return service name via zenrpc")
	s.Contains(string(body), "uptimeSeconds", "should return uptime")
}

func (s *AppSuite) TestMgmtHandler_Metrics() {
	// trigger a metric to ensure it appears
	s.app.metrics.requestsTotal.WithLabelValues("test-svc", "GET", "2xx", "", "unsigned").Inc()

	handler := s.app.buildMgmtHandler()
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/metrics")
	s.Require().NoError(err)
	defer resp.Body.Close()

	s.Equal(http.StatusOK, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	s.Contains(string(body), "wafsrv_requests_total", "should expose prometheus metrics")
}

func BenchmarkMiddlewareChain(b *testing.B) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"result":"ok"}`))
	}))
	defer backend.Close()

	cfg := Config{
		Proxy: ProxyConfig{
			Listen:      ":0",
			Targets:     []string{backend.URL},
			ServiceName: "bench-svc",
			Timeouts:    TimeoutsConfig{Read: "5s", Write: "5s", Idle: "30s"},
			Limits:      LimitsConfig{MaxRequestBody: "1MB"},
		},
		Management: ManagementConfig{Listen: ":0"},
	}

	sl := embedlog.NewLogger(false, false)
	app, err := New("wafsrv", sl, cfg)
	if err != nil {
		b.Fatal(err)
	}

	trusted, _ := proxy.ParseTrustedProxies(nil)
	handler := app.buildDataHandler(trusted)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		resp, err := http.Get(ts.URL + "/")
		if err != nil {
			b.Fatal(err)
		}
		resp.Body.Close()
	}
}
