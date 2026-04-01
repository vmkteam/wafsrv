package e2e

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"wafsrv/internal/app"

	"github.com/stretchr/testify/suite"
	"github.com/vmkteam/embedlog"
)

const (
	dataAddr          = "127.0.0.1:18080"
	mgmtAddr          = "127.0.0.1:18081"
	dataURL           = "http://" + dataAddr
	mgmtURL           = "http://" + mgmtAddr
	defaultConfigPath = "cfg/e2e.toml"
)

func e2eConfigPath() string {
	if p := os.Getenv("E2E_CONFIG"); p != "" {
		return p
	}

	return defaultConfigPath
}

type E2ESuite struct {
	suite.Suite
	app     *app.App
	cancel  context.CancelFunc
	backend *http.Server
}

func TestE2E(t *testing.T) {
	suite.Run(t, new(E2ESuite))
}

func (s *E2ESuite) SetupSuite() {
	// start mock backend on :19990
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			body, _ := io.ReadAll(r.Body)
			w.Write(body)
			return
		}
		w.Write([]byte(`{"result":"ok"}`))
	})

	s.backend = &http.Server{Addr: ":19990", Handler: mux}
	go s.backend.ListenAndServe()
	time.Sleep(200 * time.Millisecond)

	cfg, err := app.LoadConfig(e2eConfigPath())
	s.Require().NoError(err, "load e2e config")

	sl := embedlog.NewLogger(false, true)
	a, err := app.New("wafsrv-e2e", sl, cfg)
	s.Require().NoError(err, "create app")

	s.app = a
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel

	go func() {
		_ = a.Run(ctx)
	}()

	s.waitForReady(mgmtURL+"/health", 3*time.Second)
}

func (s *E2ESuite) TearDownSuite() {
	s.cancel()
	_ = s.app.Shutdown(3 * time.Second)
	_ = s.backend.Shutdown(context.Background())
}

func (s *E2ESuite) waitForReady(url string, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			resp.Body.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	s.Require().Fail("server did not become ready", url)
}

// --- helpers ---

func (s *E2ESuite) get(url string) *http.Response {
	s.T().Helper()
	resp, err := http.Get(url)
	s.Require().NoError(err)
	return resp
}

func (s *E2ESuite) readBody(resp *http.Response) string {
	s.T().Helper()
	body, err := io.ReadAll(resp.Body)
	s.Require().NoError(err)
	return string(body)
}

func (s *E2ESuite) assertStatus(url string, expected int) {
	s.T().Helper()
	resp, err := http.Get(url)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(expected, resp.StatusCode, "GET %s", url)
}

func (s *E2ESuite) assertStatusURL(url string, expected int) {
	s.T().Helper()
	resp, err := http.Get(url)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(expected, resp.StatusCode)
}

func (s *E2ESuite) postRPC(url, method, params string) *http.Response {
	s.T().Helper()
	body := fmt.Sprintf(`{"jsonrpc":"2.0","method":"%s","params":%s,"id":1}`, method, params)
	resp, err := http.Post(url, "application/json", strings.NewReader(body))
	s.Require().NoError(err)
	return resp
}

func (s *E2ESuite) mgmtRPC(method, params string) string {
	s.T().Helper()
	resp := s.postRPC(mgmtURL+"/rpc/", method, params)
	defer resp.Body.Close()
	return s.readBody(resp)
}

func (s *E2ESuite) getMetrics() string {
	s.T().Helper()
	resp := s.get(mgmtURL + "/metrics")
	defer resp.Body.Close()
	return s.readBody(resp)
}

func (s *E2ESuite) detectClientIP() string {
	s.T().Helper()

	resp, err := http.Get(dataURL + "/")
	if err == nil {
		resp.Body.Close()
	}

	for _, ip := range []string{"::1", "127.0.0.1"} {
		s.mgmtRPC("block.add", fmt.Sprintf(`{"blockType":"ip","value":"%s","reason":"detect"}`, ip))
		resp, err := http.Get(dataURL + "/")
		if err == nil {
			code := resp.StatusCode
			resp.Body.Close()
			s.mgmtRPC("block.remove", fmt.Sprintf(`{"blockType":"ip","value":"%s"}`, ip))
			if code == http.StatusForbidden {
				return ip
			}
		}
	}

	s.Require().Fail("could not detect client IP")
	return ""
}
