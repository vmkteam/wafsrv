package proxy

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

type ProxySuite struct {
	suite.Suite
}

func TestProxy(t *testing.T) {
	suite.Run(t, new(ProxySuite))
}

func (s *ProxySuite) TestBasicProxy() {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"result":"ok"}`))
	}))
	defer backend.Close()

	p := s.newProxy(backend.URL)
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/test")
	s.Require().NoError(err)
	defer resp.Body.Close()

	s.Equal(http.StatusOK, resp.StatusCode, "should proxy request successfully")

	body, err := io.ReadAll(resp.Body)
	s.Require().NoError(err)
	s.JSONEq(`{"result":"ok"}`, string(body), "should return backend response body")
}

func (s *ProxySuite) TestProxyPost() {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	defer backend.Close()

	p := s.newProxy(backend.URL)
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	reqBody := `{"jsonrpc":"2.0","method":"test","id":1}`
	resp, err := http.Post(ts.URL+"/rpc/", "application/json", strings.NewReader(reqBody))
	s.Require().NoError(err)
	defer resp.Body.Close()

	s.Equal(http.StatusOK, resp.StatusCode, "should proxy POST request")

	body, err := io.ReadAll(resp.Body)
	s.Require().NoError(err)
	s.Equal(reqBody, string(body), "should pass request body to backend")
}

func (s *ProxySuite) TestRoundRobin() {
	var hits [2]int

	b1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits[0]++
		w.WriteHeader(http.StatusOK)
	}))
	defer b1.Close()

	b2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits[1]++
		w.WriteHeader(http.StatusOK)
	}))
	defer b2.Close()

	u1, _ := url.Parse(b1.URL)
	u2, _ := url.Parse(b2.URL)

	p, err := New(Config{
		ReadTimeout: 5 * time.Second,
		CBEnabled:   false,
	}, Static([]*url.URL{u1, u2}))
	s.Require().NoError(err)

	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	for range 10 {
		resp, err := http.Get(ts.URL + "/")
		s.Require().NoError(err)
		resp.Body.Close()
	}

	s.Equal(5, hits[0], "should distribute requests evenly to backend 1")
	s.Equal(5, hits[1], "should distribute requests evenly to backend 2")
}

func (s *ProxySuite) TestCircuitBreaker() {
	callCount := 0
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCount++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer backend.Close()

	u, _ := url.Parse(backend.URL)
	p, err := New(Config{
		ReadTimeout: 5 * time.Second,
		CBEnabled:   true,
		CBThreshold: 3,
		CBTimeout:   1 * time.Second,
	}, Static([]*url.URL{u}))
	s.Require().NoError(err)

	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	// trigger circuit breaker: 3 consecutive failures
	for range 5 {
		resp, err := http.Get(ts.URL + "/")
		s.Require().NoError(err)
		resp.Body.Close()
	}

	s.LessOrEqual(callCount, 4, "circuit breaker should stop forwarding after threshold")
}

func (s *ProxySuite) TestPerBackendCircuitBreaker() {
	callCount := 0
	badBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCount++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer badBackend.Close()

	goodHits := 0
	goodBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		goodHits++
		w.WriteHeader(http.StatusOK)
	}))
	defer goodBackend.Close()

	u1, _ := url.Parse(badBackend.URL)
	u2, _ := url.Parse(goodBackend.URL)

	p, err := New(Config{
		ReadTimeout: 5 * time.Second,
		CBEnabled:   true,
		CBThreshold: 2,
		CBTimeout:   10 * time.Second,
	}, Static([]*url.URL{u1, u2}))
	s.Require().NoError(err)

	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	// send 20 requests — bad backend CB should open, good should keep working
	for range 20 {
		resp, err := http.Get(ts.URL + "/")
		s.Require().NoError(err)
		resp.Body.Close()
	}

	s.Greater(goodHits, 5, "good backend should keep receiving requests")
}

func (s *ProxySuite) TestEmptyPool() {
	failResolver := &failingResolver{}
	p, err := New(Config{ReadTimeout: 5 * time.Second}, failResolver)
	s.Require().Error(err, "should return error from initial resolve")
	s.Require().NotNil(p, "proxy should still be created")

	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/")
	s.Require().NoError(err)
	defer resp.Body.Close()

	s.Equal(http.StatusServiceUnavailable, resp.StatusCode, "should return 503 with empty pool")
}

func (s *ProxySuite) TestBackendHeaders() {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Custom-Header", "test-value")
		_, _ = w.Write([]byte(r.Header.Get("Accept")))
	}))
	defer backend.Close()

	p := s.newProxy(backend.URL)
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/", nil)
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	s.Require().NoError(err)
	defer resp.Body.Close()

	s.Equal("test-value", resp.Header.Get("X-Custom-Header"), "should pass response headers from backend")

	body, _ := io.ReadAll(resp.Body)
	s.Equal("application/json", string(body), "should pass request headers to backend")
}

func (s *ProxySuite) TestStatus() {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	u, _ := url.Parse(backend.URL)
	p, err := New(Config{
		ReadTimeout: 5 * time.Second,
		CBEnabled:   true,
		CBThreshold: 3,
		CBTimeout:   1 * time.Second,
	}, Static([]*url.URL{u}))
	s.Require().NoError(err)

	status := p.Status()
	s.Len(status.Targets, 1, "should have one target")
	s.Equal("closed", status.Targets[0].State, "CB should be closed initially")
}

func (s *ProxySuite) TestReconcileReuse() {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	u, _ := url.Parse(backend.URL)
	p, err := New(Config{
		ReadTimeout: 5 * time.Second,
		CBEnabled:   true,
		CBThreshold: 3,
		CBTimeout:   1 * time.Second,
	}, Static([]*url.URL{u}))
	s.Require().NoError(err)

	// get reference to original backend
	pl := p.pool.Load()
	s.Require().Len(pl.backends, 1)
	origBackend := pl.backends[0]

	// reconcile with same target — should reuse
	added, removed := p.reconcile([]Target{{Addr: u.Host, Key: u.String()}})
	s.Equal(0, added)
	s.Equal(0, removed)

	pl2 := p.pool.Load()
	s.Same(origBackend, pl2.backends[0], "should reuse backend when Key+Addr unchanged")
}

func (s *ProxySuite) TestFirstBackendURL() {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	p := s.newProxy(backend.URL)
	u, _ := url.Parse(backend.URL)
	s.Contains(p.FirstBackendURL(), u.Host, "should return first backend URL")
}

func (s *ProxySuite) newProxy(target string) *Proxy {
	u, err := url.Parse(target)
	s.Require().NoError(err)

	p, err := New(Config{
		ReadTimeout: 5 * time.Second,
		CBEnabled:   false,
	}, Static([]*url.URL{u}))
	s.Require().NoError(err)

	return p
}

// failingResolver always returns an error.
type failingResolver struct{}

func (r *failingResolver) Resolve(_ context.Context) ([]Target, error) {
	return nil, errors.New("resolve failed")
}

func BenchmarkProxy(b *testing.B) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":{"ok":true},"id":1}`))
	}))
	defer backend.Close()

	u, _ := url.Parse(backend.URL)
	p, _ := New(Config{
		ReadTimeout: 5 * time.Second,
		CBEnabled:   false,
	}, Static([]*url.URL{u}))

	ts := httptest.NewServer(p.Handler())
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
