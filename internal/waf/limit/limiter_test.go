package limit

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"wafsrv/internal/waf"
	"wafsrv/internal/waf/storage"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/suite"
	"github.com/vmkteam/embedlog"
)

type LimiterSuite struct {
	suite.Suite
}

func TestLimiter(t *testing.T) {
	suite.Run(t, new(LimiterSuite))
}

func (s *LimiterSuite) TestParseRate() {
	tests := []struct {
		input string
		count int
		dur   time.Duration
	}{
		{"100/min", 100, time.Minute},
		{"10/sec", 10, time.Second},
		{"1000/hour", 1000, time.Hour},
		{"5/second", 5, time.Second},
		{"3/minute", 3, time.Minute},
	}

	for _, tt := range tests {
		r, err := ParseRate(tt.input)
		s.Require().NoError(err, "ParseRate(%q)", tt.input)
		s.Equal(tt.count, r.Count)
		s.Equal(tt.dur, r.Duration)
	}
}

func (s *LimiterSuite) TestParseRateInvalid() {
	invalids := []string{"", "100", "abc/min", "100/weeks"}

	for _, input := range invalids {
		_, err := ParseRate(input)
		s.Error(err, "ParseRate(%q) should fail", input)
	}
}

func (s *LimiterSuite) TestPerIPLimit() {
	l := s.newLimiter(Config{
		PerIP:       Rate{Count: 3, Duration: time.Minute},
		Action:      "block",
		MaxCounters: 1000,
	})

	handler := l.Middleware()(okHandler())

	for i := range 3 {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, s.requestWithIP("1.2.3.4"))
		s.Equal(http.StatusOK, w.Code, "request %d should pass", i+1)
	}

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, s.requestWithIP("1.2.3.4"))
	s.Equal(http.StatusTooManyRequests, w.Code, "4th request should be limited")
	s.NotEmpty(w.Header().Get("Retry-After"))
}

func (s *LimiterSuite) TestDifferentIPsIndependent() {
	l := s.newLimiter(Config{
		PerIP:       Rate{Count: 1, Duration: time.Minute},
		Action:      "block",
		MaxCounters: 1000,
	})

	handler := l.Middleware()(okHandler())

	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, s.requestWithIP("1.1.1.1"))
	s.Equal(http.StatusOK, w1.Code)

	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, s.requestWithIP("2.2.2.2"))
	s.Equal(http.StatusOK, w2.Code)
}

func (s *LimiterSuite) TestWhitelistedSkipped() {
	l := s.newLimiter(Config{
		PerIP:       Rate{Count: 1, Duration: time.Minute},
		Action:      "block",
		MaxCounters: 1000,
	})

	handler := l.Middleware()(okHandler())

	for range 5 {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		rc := &waf.RequestContext{
			ClientIP: netip.MustParseAddr("10.0.0.1"),
			IP:       &waf.IPInfo{Whitelisted: true},
		}
		r = r.WithContext(waf.NewContext(r.Context(), rc))

		handler.ServeHTTP(w, r)
		s.Equal(http.StatusOK, w.Code)
	}
}

func (s *LimiterSuite) TestPerMethodCompositeKey() {
	l := s.newLimiter(Config{
		PerIP:       Rate{Count: 1000, Duration: time.Minute}, // high global limit
		Action:      "block",
		MaxCounters: 1000,
		Rules: []Rule{{
			Name:  "login",
			Match: []string{"auth.login"},
			Limit: Rate{Count: 2, Duration: time.Minute},
		}},
	})

	handler := l.Middleware()(okHandler())

	// Client A (iOS) — exhaust method limit
	for range 2 {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, s.requestWithRPC("iOS:aaa"))
		s.Equal(http.StatusOK, w.Code)
	}

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, s.requestWithRPC("iOS:aaa"))
	s.Equal(http.StatusTooManyRequests, w.Code, "client A should be limited")

	// Client B (Android) — same IP, different discriminator — should pass
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, s.requestWithRPC("Android:bbb"))
	s.Equal(http.StatusOK, w.Code, "client B behind same NAT should not be limited")
}

func (s *LimiterSuite) TestPerMethodSameDiscriminator() {
	l := s.newLimiter(Config{
		PerIP:       Rate{Count: 1000, Duration: time.Minute},
		Action:      "block",
		MaxCounters: 1000,
		Rules: []Rule{{
			Name:  "login",
			Match: []string{"auth.login"},
			Limit: Rate{Count: 2, Duration: time.Minute},
		}},
	})

	handler := l.Middleware()(okHandler())

	// Two users with same UA behind NAT share bucket
	for range 2 {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, s.requestWithRPC(":same_hash"))
		s.Equal(http.StatusOK, w.Code)
	}

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, s.requestWithRPC(":same_hash"))
	s.Equal(http.StatusTooManyRequests, w.Code, "same discriminator shares bucket")
}

func (s *LimiterSuite) TestPerIPGlobalIgnoresDiscriminator() {
	l := s.newLimiter(Config{
		PerIP:       Rate{Count: 2, Duration: time.Minute},
		Action:      "block",
		MaxCounters: 1000,
	})

	handler := l.Middleware()(okHandler())

	// Different discriminators but same IP — global per-IP limit applies
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, s.requestWithDiscriminator("1.1.1.1", "iOS:aaa"))
	s.Equal(http.StatusOK, w.Code)

	w = httptest.NewRecorder()
	handler.ServeHTTP(w, s.requestWithDiscriminator("1.1.1.1", "Android:bbb"))
	s.Equal(http.StatusOK, w.Code)

	// 3rd request — different discriminator but same IP — blocked by global
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, s.requestWithDiscriminator("1.1.1.1", "web:ccc"))
	s.Equal(http.StatusTooManyRequests, w.Code, "global per-IP limit ignores discriminator")
}

func (s *LimiterSuite) requestWithRPC(discriminator string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/rpc/", nil)
	rc := &waf.RequestContext{
		ClientIP:      netip.MustParseAddr("1.1.1.1"),
		Discriminator: discriminator,
		RPC:           &waf.RPCCall{Endpoint: "main", Methods: []string{"auth.login"}},
	}

	return r.WithContext(waf.NewContext(r.Context(), rc))
}

func (s *LimiterSuite) requestWithDiscriminator(ipStr, discriminator string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	rc := &waf.RequestContext{
		ClientIP:      netip.MustParseAddr(ipStr),
		Discriminator: discriminator,
	}

	return r.WithContext(waf.NewContext(r.Context(), rc))
}

func (s *LimiterSuite) newLimiter(cfg Config) *Limiter {
	return New(cfg, storage.NewMemoryCounter(cfg.MaxCounters), embedlog.NewLogger(false, false), newTestMetrics())
}

func (s *LimiterSuite) requestWithIP(ipStr string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	rc := &waf.RequestContext{
		ClientIP: netip.MustParseAddr(ipStr),
	}

	return r.WithContext(waf.NewContext(r.Context(), rc))
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func BenchmarkLimiterAllow(b *testing.B) {
	l := New(Config{
		PerIP:       Rate{Count: 1000000, Duration: time.Second},
		Action:      "block",
		MaxCounters: 10000,
	}, storage.NewMemoryCounter(10000), embedlog.NewLogger(false, false), newTestMetrics())

	ip := "1.2.3.4"

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		l.allowIP(ip)
	}
}

func BenchmarkLimiterAllowParallel(b *testing.B) {
	l := New(Config{
		PerIP:       Rate{Count: 1000000, Duration: time.Second},
		Action:      "block",
		MaxCounters: 10000,
	}, storage.NewMemoryCounter(10000), embedlog.NewLogger(false, false), newTestMetrics())

	b.ResetTimer()
	b.ReportAllocs()

	var counter uint64

	b.RunParallel(func(pb *testing.PB) {
		i := atomic.AddUint64(&counter, 1)
		ip := netip.AddrFrom4([4]byte{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)})

		for pb.Next() {
			l.allowIP(ip.String())
		}
	})
}

func newTestMetrics() Metrics {
	return Metrics{
		ExceededTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "test_ratelimit_exceeded_total",
			Help: "test",
		}, []string{"rule", "action"}),
	}
}
