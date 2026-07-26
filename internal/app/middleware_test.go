package app

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"wafsrv/internal/waf/event"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/suite"
)

type MiddlewareSuite struct {
	suite.Suite
}

func TestMiddleware(t *testing.T) {
	suite.Run(t, new(MiddlewareSuite))
}

func (s *MiddlewareSuite) TestParseSize() {
	tests := []struct {
		input    string
		expected int64
	}{
		{"1KB", 1024},
		{"1MB", 1 << 20},
		{"5MB", 5 << 20},
		{"10MB", 10 << 20},
		{"100MB", 100 << 20},
		{"1GB", 1 << 30},
		{"512KB", 512 * 1024},
		{"1B", 1},
		{"1024B", 1024},
		{"1KIB", 1024},
		{"1MIB", 1 << 20},
		{"1K", 1024},
		{"1M", 1 << 20},
		{"1G", 1 << 30},
		{"1 MB", 1 << 20},
		{"0.5MB", (1 << 20) / 2},
	}

	for _, tt := range tests {
		s.Equal(tt.expected, parseSize(tt.input, -1), "parseSize(%q)", tt.input)
	}
}

func (s *MiddlewareSuite) TestParseSizeDefault() {
	s.Equal(int64(42), parseSize("", 42), "empty string should return default")
	s.Equal(int64(42), parseSize("abc", 42), "invalid string should return default")
	s.Equal(int64(42), parseSize("MB", 42), "no number should return default")
	s.Equal(int64(42), parseSize("1XB", 42), "unknown suffix should return default")
}

func (s *MiddlewareSuite) TestStatusBucket() {
	s.Equal("1xx", statusBucket(100))
	s.Equal("2xx", statusBucket(200))
	s.Equal("2xx", statusBucket(204))
	s.Equal("3xx", statusBucket(301))
	s.Equal("4xx", statusBucket(404))
	s.Equal("5xx", statusBucket(500))
	s.Equal("5xx", statusBucket(503))
}

func (s *MiddlewareSuite) TestAccessLogPanicReturns500() {
	cfg := newAccessLogTestConfig()

	handler := accessLog(cfg)(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		panic("boom")
	}))

	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	handler.ServeHTTP(rw, req)

	s.Equal(http.StatusInternalServerError, rw.Code, "panic should produce 500")
}

func (s *MiddlewareSuite) TestAccessLogAbortHandlerRepanic() {
	cfg := newAccessLogTestConfig()

	handler := accessLog(cfg)(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		panic(http.ErrAbortHandler)
	}))

	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	s.PanicsWithValue(http.ErrAbortHandler, func() {
		handler.ServeHTTP(rw, req)
	}, "client abort must be re-raised for net/http, not logged as error")

	s.NotEqual(http.StatusInternalServerError, rw.Code, "client abort must not be rewritten to 500")

	ch := make(chan prometheus.Metric, 10)
	cfg.requestsTotal.Collect(ch)
	s.NotEmpty(ch, "aborted request must still be counted in metrics")
}

func newAccessLogTestConfig() accessLogConfig {
	rec := event.NewRecorder(
		event.NewBuffer(1),
		event.NewSeries(time.Second, 1),
		event.NewTops(time.Minute, 100),
	)

	return accessLogConfig{
		logger:      slog.New(slog.DiscardHandler),
		serviceName: "test",
		requestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "test_requests_total",
			Help: "test counter",
		}, []string{"service", "method", "status", "platform", "traffic_type"}),
		requestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "test_request_duration_seconds",
			Help: "test histogram",
		}, []string{"service", "method", "target"}),
		recorder:    rec,
		platformSet: map[string]struct{}{},
	}
}
