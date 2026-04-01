package ip

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"wafsrv/internal/waf"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/suite"
	"github.com/vmkteam/embedlog"
)

type ServiceSuite struct {
	suite.Suite
}

func TestService(t *testing.T) {
	suite.Run(t, new(ServiceSuite))
}

// --- Whitelist / Blacklist (static config) ---

func (s *ServiceSuite) TestWhitelistPass() {
	svc := s.newService(Config{
		Whitelist: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
	})

	handler := svc.Middleware()(okHandler())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, s.requestWithIP("10.1.2.3"))
	s.Equal(http.StatusOK, w.Code, "whitelisted IP should pass")
}

func (s *ServiceSuite) TestBlacklistBlock() {
	svc := s.newService(Config{
		Blacklist: []netip.Prefix{netip.MustParsePrefix("1.2.3.0/24")},
	})

	handler := svc.Middleware()(okHandler())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, s.requestWithIP("1.2.3.4"))
	s.Equal(http.StatusForbidden, w.Code, "blacklisted IP should be blocked")
}

func (s *ServiceSuite) TestNonListedPass() {
	svc := s.newService(Config{
		Whitelist: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		Blacklist: []netip.Prefix{netip.MustParsePrefix("1.2.3.0/24")},
	})

	handler := svc.Middleware()(okHandler())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, s.requestWithIP("8.8.8.8"))
	s.Equal(http.StatusOK, w.Code, "non-listed IP should pass")
}

func (s *ServiceSuite) TestWhitelistSetsFlag() {
	svc := s.newService(Config{
		Whitelist: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
	})

	var gotRC *waf.RequestContext

	handler := svc.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRC = waf.FromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, s.requestWithIP("10.0.0.1"))

	s.Require().NotNil(gotRC)
	s.Require().NotNil(gotRC.IP)
	s.True(gotRC.IP.Whitelisted, "whitelisted flag should be set")
}

// --- AddBlock / RemoveBlock / ListBlocks ---

func (s *ServiceSuite) TestAddBlockIP() {
	svc := s.newService(Config{})

	err := svc.AddBlock("ip", "5.5.5.5", "test", 0)
	s.Require().NoError(err)

	handler := svc.Middleware()(okHandler())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, s.requestWithIP("5.5.5.5"))
	s.Equal(http.StatusForbidden, w.Code, "blocked IP should be denied")
}

func (s *ServiceSuite) TestRemoveBlockIP() {
	svc := s.newService(Config{})

	s.Require().NoError(svc.AddBlock("ip", "5.5.5.5", "test", 0))
	s.Require().NoError(svc.RemoveBlock("ip", "5.5.5.5"))

	handler := svc.Middleware()(okHandler())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, s.requestWithIP("5.5.5.5"))
	s.Equal(http.StatusOK, w.Code, "unblocked IP should pass")
}

func (s *ServiceSuite) TestAddBlockCIDR() {
	svc := s.newService(Config{})

	err := svc.AddBlock("cidr", "192.168.1.0/24", "subnet block", 0)
	s.Require().NoError(err)

	handler := svc.Middleware()(okHandler())

	// IP within CIDR → blocked
	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, s.requestWithIP("192.168.1.50"))
	s.Equal(http.StatusForbidden, w1.Code, "IP in blocked CIDR should be denied")

	// IP outside CIDR → pass
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, s.requestWithIP("192.168.2.1"))
	s.Equal(http.StatusOK, w2.Code, "IP outside blocked CIDR should pass")
}

func (s *ServiceSuite) TestRemoveBlockCIDR() {
	svc := s.newService(Config{})

	s.Require().NoError(svc.AddBlock("cidr", "192.168.1.0/24", "test", 0))
	s.Require().NoError(svc.RemoveBlock("cidr", "192.168.1.0/24"))

	handler := svc.Middleware()(okHandler())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, s.requestWithIP("192.168.1.50"))
	s.Equal(http.StatusOK, w.Code, "IP in removed CIDR should pass")
}

func (s *ServiceSuite) TestAddBlockCountry() {
	svc := s.newService(Config{})

	err := svc.AddBlock("country", "XX", "test country", 0)
	s.Require().NoError(err)

	entries := svc.ListBlocks("country")
	s.Require().Len(entries, 1)
	s.Equal("XX", entries[0].Value)
	s.Equal("test country", entries[0].Reason)
}

func (s *ServiceSuite) TestBlockWithDuration() {
	svc := s.newService(Config{})

	err := svc.AddBlock("ip", "6.6.6.6", "temp", 100*time.Millisecond)
	s.Require().NoError(err)

	// immediately → blocked
	handler := svc.Middleware()(okHandler())
	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, s.requestWithIP("6.6.6.6"))
	s.Equal(http.StatusForbidden, w1.Code, "should be blocked before expiry")

	// wait for expiry
	time.Sleep(150 * time.Millisecond)

	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, s.requestWithIP("6.6.6.6"))
	s.Equal(http.StatusOK, w2.Code, "should pass after TTL expires")
}

func (s *ServiceSuite) TestListBlocksIP() {
	svc := s.newService(Config{})

	s.Require().NoError(svc.AddBlock("ip", "1.1.1.1", "reason1", 0))
	s.Require().NoError(svc.AddBlock("ip", "2.2.2.2", "reason2", time.Hour))

	entries := svc.ListBlocks("ip")
	s.Len(entries, 2)

	// check metadata
	found := false
	for _, e := range entries {
		if e.Value == "1.1.1.1" {
			s.Equal("reason1", e.Reason)
			s.False(e.AddedAt.IsZero())
			s.True(e.ExpiresAt.IsZero(), "permanent should have zero expiry")
			found = true
		}
	}
	s.True(found, "should find 1.1.1.1 in list")
}

func (s *ServiceSuite) TestListBlocksExpiredFiltered() {
	svc := s.newService(Config{})

	s.Require().NoError(svc.AddBlock("ip", "7.7.7.7", "expired", 1*time.Millisecond))
	time.Sleep(10 * time.Millisecond)

	entries := svc.ListBlocks("ip")
	s.Empty(entries, "expired entries should not appear in list")
}

func (s *ServiceSuite) TestListBlocksUnknownType() {
	svc := s.newService(Config{})

	entries := svc.ListBlocks("unknown")
	s.Nil(entries)
}

func (s *ServiceSuite) TestAddBlockInvalidIP() {
	svc := s.newService(Config{})

	err := svc.AddBlock("ip", "not-an-ip", "test", 0)
	s.Error(err)
}

func (s *ServiceSuite) TestAddBlockInvalidCIDR() {
	svc := s.newService(Config{})

	err := svc.AddBlock("cidr", "not-a-cidr", "test", 0)
	s.Error(err)
}

func (s *ServiceSuite) TestAddBlockUnknownType() {
	svc := s.newService(Config{})

	err := svc.AddBlock("unknown", "value", "test", 0)
	s.Error(err)
}

// --- Legacy compatibility ---

func (s *ServiceSuite) TestLegacyAddRemoveBlacklist() {
	svc := s.newService(Config{})

	ip := netip.MustParseAddr("9.9.9.9")
	svc.AddBlacklist(ip)

	ips := svc.ListBlacklist()
	s.Contains(ips, ip)

	svc.RemoveBlacklist(ip)

	ips = svc.ListBlacklist()
	s.NotContains(ips, ip)
}

// --- helpers ---

func (s *ServiceSuite) newService(cfg Config) *Service {
	svc, err := New(cfg, embedlog.NewLogger(false, false), newTestMetrics())
	s.Require().NoError(err)

	return svc
}

func (s *ServiceSuite) requestWithIP(ipStr string) *http.Request {
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

func BenchmarkIPMiddleware(b *testing.B) {
	svc, _ := New(Config{
		Whitelist: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		Blacklist: []netip.Prefix{
			netip.MustParsePrefix("1.2.3.0/24"),
			netip.MustParsePrefix("5.6.7.0/24"),
			netip.MustParsePrefix("9.9.9.0/24"),
		},
	}, embedlog.NewLogger(false, false), newTestMetrics())

	handler := svc.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	rc := &waf.RequestContext{ClientIP: netip.MustParseAddr("8.8.8.8")}
	r = r.WithContext(waf.NewContext(r.Context(), rc))

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
	}
}

func BenchmarkIPMiddlewareWhitelisted(b *testing.B) {
	svc, _ := New(Config{
		Whitelist: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
	}, embedlog.NewLogger(false, false), newTestMetrics())

	handler := svc.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	rc := &waf.RequestContext{ClientIP: netip.MustParseAddr("10.1.2.3")}
	r = r.WithContext(waf.NewContext(r.Context(), rc))

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
	}
}

func newTestMetrics() Metrics {
	return Metrics{
		BlockedTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "test_ip_blocked_total",
			Help: "test",
		}, []string{"reason"}),
		WhitelistedTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "test_ip_whitelisted_total",
			Help: "test",
		}),
	}
}
