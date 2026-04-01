package e2e

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"wafsrv/internal/waf/proxy"
)

// --- 01: Proxy ---

func (s *E2ESuite) Test01_Proxy_BatchRPC() {
	body := `[{"jsonrpc":"2.0","method":"app.About","params":{},"id":1},{"jsonrpc":"2.0","method":"app.About","params":{},"id":2}]`
	resp, err := http.Post(dataURL+"/rpc/", "application/json", strings.NewReader(body))
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusOK, resp.StatusCode)
}

func (s *E2ESuite) Test01_Proxy_GET() {
	resp := s.get(dataURL + "/")
	defer resp.Body.Close()
	s.Equal(http.StatusOK, resp.StatusCode)
}

func (s *E2ESuite) Test01_Proxy_RequestID_Generated() {
	resp := s.get(dataURL + "/")
	defer resp.Body.Close()
	s.NotEmpty(resp.Header.Get("X-Request-ID"))
}

func (s *E2ESuite) Test01_Proxy_RequestID_Passthrough() {
	req, _ := http.NewRequest(http.MethodGet, dataURL+"/", nil)
	req.Header.Set("X-Request-ID", "e2e-custom-id")
	resp, err := http.DefaultClient.Do(req)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal("e2e-custom-id", resp.Header.Get("X-Request-ID"))
}

func (s *E2ESuite) Test01_Proxy_POST_RPC() {
	resp := s.postRPC(dataURL+"/rpc/", "app.About", "{}")
	defer resp.Body.Close()
	s.Equal(http.StatusOK, resp.StatusCode)
	body := s.readBody(resp)
	s.Contains(body, "jsonrpc")
}

// --- 11: Static Bypass ---

func (s *E2ESuite) Test11_Static_CSSBypass() {
	s.assertStatus(dataURL+"/static/style.css?id=1'+OR+1=1--", http.StatusOK)
}

func (s *E2ESuite) Test11_Static_JSBypass() {
	s.assertStatus(dataURL+"/static/app.js", http.StatusOK)
}

func (s *E2ESuite) Test11_Static_NonStaticStillBlocked() {
	s.assertStatus(dataURL+"/api?id=1'+OR+1=1--", http.StatusForbidden)
}

// --- 13: Proxy Status ---

func (s *E2ESuite) Test13_ProxyStatus_CBClosed() {
	result := s.mgmtRPC("status.get", "{}")
	s.Contains(result, `"proxyStatus"`)
	s.Contains(result, `"state":"closed"`)
	s.Contains(result, "19990")
}

func (s *E2ESuite) Test13_ProxyStatus_PerBackendCB() {
	result := s.mgmtRPC("status.get", "{}")
	s.Contains(result, `"state":"closed"`, "per-backend CB should be closed")
}

// --- 17: Dynamic Discovery ---

func (s *E2ESuite) Test17_Discovery_DynamicPool() {
	hits := [2]int{}
	b1 := startBackend(&hits[0])
	defer b1.Close()
	b2 := startBackend(&hits[1])
	defer b2.Close()

	mr := &mockResolver{targets: []proxy.Target{
		{Addr: b1.ln.Addr().String(), Key: "b1"},
	}}

	p, err := proxy.New(proxy.Config{
		ReadTimeout:     5 * time.Second,
		CBEnabled:       true,
		CBThreshold:     5,
		CBTimeout:       1 * time.Second,
		RefreshInterval: 100 * time.Millisecond,
		ResolveTimeout:  1 * time.Second,
	}, mr)
	s.Require().NoError(err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Run(ctx, nil)

	ts := startTestServer(p.Handler())
	defer ts.Close()

	for range 4 {
		resp, err := http.Get(ts.URL + "/")
		s.Require().NoError(err)
		resp.Body.Close()
	}
	s.Equal(4, hits[0], "all requests should go to b1")
	s.Equal(0, hits[1], "b2 should not get requests yet")

	mr.mu.Lock()
	mr.targets = []proxy.Target{
		{Addr: b1.ln.Addr().String(), Key: "b1"},
		{Addr: b2.ln.Addr().String(), Key: "b2"},
	}
	mr.mu.Unlock()

	time.Sleep(300 * time.Millisecond)

	hits = [2]int{}
	for range 10 {
		resp, err := http.Get(ts.URL + "/")
		s.Require().NoError(err)
		resp.Body.Close()
	}

	s.Equal(5, hits[0], "b1 should get half")
	s.Equal(5, hits[1], "b2 should get half")

	mr.mu.Lock()
	mr.targets = []proxy.Target{
		{Addr: b2.ln.Addr().String(), Key: "b2"},
	}
	mr.mu.Unlock()

	time.Sleep(300 * time.Millisecond)

	hits = [2]int{}
	for range 4 {
		resp, err := http.Get(ts.URL + "/")
		s.Require().NoError(err)
		resp.Body.Close()
	}

	s.Equal(0, hits[0], "b1 should no longer get requests")
	s.Equal(4, hits[1], "all requests should go to b2")
}

func (s *E2ESuite) Test17_Discovery_ResolveFailKeepsOldPool() {
	b1 := startBackend(nil)
	defer b1.Close()

	mr := &mockResolver{targets: []proxy.Target{
		{Addr: b1.ln.Addr().String(), Key: "b1"},
	}}

	p, err := proxy.New(proxy.Config{
		ReadTimeout:     5 * time.Second,
		RefreshInterval: 100 * time.Millisecond,
		ResolveTimeout:  1 * time.Second,
	}, mr)
	s.Require().NoError(err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Run(ctx, nil)

	ts := startTestServer(p.Handler())
	defer ts.Close()

	s.assertStatusURL(ts.URL+"/", http.StatusOK)

	mr.mu.Lock()
	mr.targets = nil
	mr.err = errors.New("dns failed")
	mr.mu.Unlock()

	time.Sleep(300 * time.Millisecond)

	s.assertStatusURL(ts.URL+"/", http.StatusOK)
}

func (s *E2ESuite) Test17_Discovery_EmptyPoolReturns503() {
	mr := &mockResolver{err: errors.New("no backends")}

	p, _ := proxy.New(proxy.Config{
		ReadTimeout:     5 * time.Second,
		RefreshInterval: 100 * time.Millisecond,
		ResolveTimeout:  1 * time.Second,
	}, mr)

	ts := startTestServer(p.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/")
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusServiceUnavailable, resp.StatusCode)
}

// --- discovery helpers ---

type mockResolver struct {
	mu      sync.Mutex
	targets []proxy.Target
	err     error
}

func (r *mockResolver) Resolve(_ context.Context) ([]proxy.Target, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return nil, r.err
	}
	return r.targets, nil
}

type testServer struct {
	srv *http.Server
	ln  net.Listener
	URL string
}

func (ts *testServer) Close() {
	ts.srv.Shutdown(context.Background())
}

func startBackend(counter *int) *testServer {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		if counter != nil {
			*counter++
		}
		w.Write([]byte(`{"ok":true}`))
	})
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	return &testServer{srv: srv, ln: ln, URL: "http://" + ln.Addr().String()}
}

func startTestServer(h http.Handler) *testServer {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	srv := &http.Server{Handler: h}
	go srv.Serve(ln)
	return &testServer{srv: srv, ln: ln, URL: "http://" + ln.Addr().String()}
}
