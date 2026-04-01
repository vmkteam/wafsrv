package decide

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"wafsrv/internal/waf"
	"wafsrv/internal/waf/challenge"
	"wafsrv/internal/waf/storage"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/suite"
	"github.com/vmkteam/embedlog"
)

type DecideSuite struct {
	suite.Suite
}

func TestDecide(t *testing.T) {
	suite.Run(t, new(DecideSuite))
}

func (s *DecideSuite) TestPassBelowThreshold() {
	e := s.newEngine(5, 8)

	handler := e.Middleware()(okHandler())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, s.requestWithScore("1.1.1.1", 2))

	s.Equal(http.StatusOK, w.Code, "score below threshold should pass")
}

func (s *DecideSuite) TestCaptchaAtThreshold() {
	e := s.newEngine(5, 8)

	handler := e.Middleware()(okHandler())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, s.requestWithScore("1.1.1.1", 5))

	s.Equal(499, w.Code, "score at captcha threshold should return 499")
	s.Contains(w.Body.String(), "Captcha required")
}

func (s *DecideSuite) TestBlockAtThreshold() {
	e := s.newEngine(5, 8)

	handler := e.Middleware()(okHandler())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, s.requestWithScore("1.1.1.1", 10))

	s.Equal(http.StatusForbidden, w.Code, "score at block threshold should return 403")
	s.Contains(w.Body.String(), "Access Denied")
}

func (s *DecideSuite) TestWhitelistedBypass() {
	e := s.newEngine(5, 8)

	handler := e.Middleware()(okHandler())

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	rc := &waf.RequestContext{
		ClientIP: netip.MustParseAddr("10.0.0.1"),
		WAFScore: 100,
		IP:       &waf.IPInfo{Whitelisted: true},
	}
	r = r.WithContext(waf.NewContext(r.Context(), rc))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	s.Equal(http.StatusOK, w.Code, "whitelisted should bypass decision")
}

func (s *DecideSuite) TestCaptchaPassCacheBypass() {
	kvStore := storage.NewMemoryKV(1000)

	cache := challenge.NewCache(challenge.CacheConfig{
		CookieName: "waf_pass",
		CookieTTL:  30 * time.Minute,
		IPCacheTTL: 30 * time.Minute,
	}, kvStore)

	// add IP to pass cache
	ip := netip.MustParseAddr("2.2.2.2")
	cache.AddIP(ip)

	e := New(Config{
		CaptchaThreshold:  5,
		BlockThreshold:    8,
		CaptchaStatusCode: 499,
		BlockStatusCode:   http.StatusForbidden,
	}, kvStore, cache, nil, nil, nil, embedlog.NewLogger(false, false), testMetrics())

	handler := e.Middleware()(okHandler())

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	rc := &waf.RequestContext{
		ClientIP: ip,
		WAFScore: 7, // above captcha threshold
	}
	r = r.WithContext(waf.NewContext(r.Context(), rc))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	s.Equal(http.StatusOK, w.Code, "IP in pass cache should bypass decision")
}

func (s *DecideSuite) TestEscalationToSoftBlock() {
	e := s.newEngine(5, 8)
	e.cfg.CaptchaToBlock = 2
	e.cfg.CaptchaToBlockWindow = time.Minute
	e.cfg.SoftBlockDuration = time.Minute

	handler := e.Middleware()(okHandler())

	// trigger 2 captcha decisions (escalation threshold)
	for range 2 {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, s.requestWithScore("3.3.3.3", 6))
		s.Equal(499, w.Code)
	}

	// next request should be soft-blocked
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, s.requestWithScore("3.3.3.3", 0)) // even score 0
	s.Equal(http.StatusForbidden, w.Code, "should be soft-blocked after escalation")
}

func (s *DecideSuite) TestZeroThresholdsPass() {
	e := s.newEngine(0, 0)

	handler := e.Middleware()(okHandler())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, s.requestWithScore("1.1.1.1", 100))

	s.Equal(http.StatusOK, w.Code, "zero thresholds should pass everything")
}

func (s *DecideSuite) newEngine(captchaThreshold, blockThreshold float64) *Engine {
	return New(Config{
		CaptchaThreshold:     captchaThreshold,
		BlockThreshold:       blockThreshold,
		CaptchaStatusCode:    499,
		BlockStatusCode:      http.StatusForbidden,
		CaptchaToBlock:       3,
		CaptchaToBlockWindow: 10 * time.Minute,
		SoftBlockDuration:    10 * time.Minute,
	}, storage.NewMemoryKV(100000), nil, nil, nil, nil, embedlog.NewLogger(false, false), testMetrics())
}

func (s *DecideSuite) requestWithScore(ipStr string, score float64) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	rc := &waf.RequestContext{
		ClientIP: netip.MustParseAddr(ipStr),
		WAFScore: score,
	}

	return r.WithContext(waf.NewContext(r.Context(), rc))
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func testMetrics() Metrics {
	return Metrics{
		DecisionTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "test_decision_total",
			Help: "test",
		}, []string{"action", "platform"}),
	}
}

func BenchmarkDecidePass(b *testing.B) {
	e := New(Config{
		CaptchaThreshold:     5,
		BlockThreshold:       8,
		CaptchaStatusCode:    499,
		BlockStatusCode:      http.StatusForbidden,
		CaptchaToBlock:       3,
		CaptchaToBlockWindow: 10 * time.Minute,
		SoftBlockDuration:    10 * time.Minute,
	}, storage.NewMemoryKV(100000), nil, nil, nil, nil, embedlog.NewLogger(false, false), testMetrics())

	handler := e.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	rc := &waf.RequestContext{
		ClientIP: netip.MustParseAddr("1.1.1.1"),
		WAFScore: 0,
	}
	r = r.WithContext(waf.NewContext(r.Context(), rc))

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
	}
}

func BenchmarkDecidePlatformCheck(b *testing.B) {
	e := New(Config{
		CaptchaThreshold:     5,
		BlockThreshold:       8,
		CaptchaStatusCode:    499,
		BlockStatusCode:      http.StatusForbidden,
		CaptchaToBlock:       3,
		CaptchaToBlockWindow: 10 * time.Minute,
		SoftBlockDuration:    10 * time.Minute,
		CaptchaFallback:      waf.ActionBlock,
		Platforms: []PlatformConfig{
			{Platform: "web", Captcha: true, Fallback: waf.ActionBlock},
			{Platform: "ios", Captcha: true, MinVersion: [3]int{2, 5, 0}, Fallback: waf.ActionPass},
			{Platform: "android", Captcha: true, MinVersion: [3]int{3, 0, 0}, Fallback: waf.ActionPass},
			{Platform: "widget", Captcha: false, Fallback: waf.ActionPass},
		},
	}, storage.NewMemoryKV(100000), nil, nil, nil, nil, embedlog.NewLogger(false, false), testMetrics())

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		e.checkPlatformCaptcha("ios", "3.0.0")
	}
}

// --- Semver tests ---

func (s *DecideSuite) TestParseSemver() {
	tests := []struct {
		input string
		want  [3]int
	}{
		{"2.5.0", [3]int{2, 5, 0}},
		{"0.1.0", [3]int{0, 1, 0}},
		{"10.20.30", [3]int{10, 20, 30}},
		{"1.0", [3]int{1, 0, 0}},
		{"3", [3]int{3, 0, 0}},
		{"", [3]int{}},
		{"abc", [3]int{}},
		{"149bd482", [3]int{}},
		{"1.2.abc", [3]int{}},
	}

	for _, tt := range tests {
		s.Equal(tt.want, ParseSemver(tt.input), "ParseSemver(%q)", tt.input)
	}
}

func (s *DecideSuite) TestcompareSemver() {
	s.Equal(-1, compareSemver([3]int{1, 0, 0}, [3]int{2, 0, 0}))
	s.Equal(1, compareSemver([3]int{2, 0, 0}, [3]int{1, 0, 0}))
	s.Equal(0, compareSemver([3]int{2, 5, 0}, [3]int{2, 5, 0}))
	s.Equal(-1, compareSemver([3]int{2, 4, 9}, [3]int{2, 5, 0}))
	s.Equal(1, compareSemver([3]int{2, 5, 1}, [3]int{2, 5, 0}))
	s.Equal(-1, compareSemver([3]int{0, 0, 0}, [3]int{1, 0, 0}))
}

// --- Platform captcha policy tests ---

func (s *DecideSuite) TestCheckPlatformCaptcha() {
	e := s.newPlatformEngine()

	tests := []struct {
		platform string
		version  string
		want     bool
	}{
		{"web", "", true},           // web: Captcha=true, no MinVersion
		{"web", "1.0.0", true},      // web: version ignored
		{"widget", "", false},       // widget: Captcha=false
		{"ios", "2.5.0", true},      // iOS: exactly MinVersion
		{"ios", "3.0.0", true},      // iOS: above MinVersion
		{"ios", "2.4.0", false},     // iOS: below MinVersion
		{"ios", "", false},          // iOS: no version = not supported
		{"android", "3.0.0", true},  // Android: at MinVersion
		{"android", "2.9.9", false}, // Android: below MinVersion
		{"unknown", "", false},      // unknown platform → fallback
		{"", "", true},              // empty platform = browser → captcha-capable
	}

	for _, tt := range tests {
		got, _ := e.checkPlatformCaptcha(tt.platform, tt.version)
		s.Equal(tt.want, got, "checkPlatformCaptcha(%q, %q)", tt.platform, tt.version)
	}
}

func (s *DecideSuite) TestNoPlatformsConfigured() {
	e := s.newEngine(5, 8)

	// no platforms configured → captcha for everyone (backward compat)
	ok1, _ := e.checkPlatformCaptcha("anything", "")
	s.True(ok1)
	ok2, _ := e.checkPlatformCaptcha("", "")
	s.True(ok2)
}

func (s *DecideSuite) TestCaptchaFallbackPass() {
	e := s.newPlatformEngine()

	handler := e.Middleware()(okHandler())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, s.requestWithPlatformScore("ios", "1.0.0"))

	s.Equal(http.StatusOK, w.Code, "iOS old version: fallback=pass should proxy")
}

func (s *DecideSuite) TestCaptchaFallbackBlock() {
	e := s.newPlatformEngine()

	handler := e.Middleware()(okHandler())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, s.requestWithPlatformScore("unknown_platform", ""))

	s.Equal(http.StatusForbidden, w.Code, "unknown platform: CaptchaFallback=block should 403")
}

func (s *DecideSuite) TestCaptchaFallbackLog() {
	e := s.newPlatformEngine()
	// override widget fallback to log
	for i := range e.cfg.Platforms {
		if e.cfg.Platforms[i].Platform == "widget" {
			e.cfg.Platforms[i].Fallback = waf.ActionLog
		}
	}

	handler := e.Middleware()(okHandler())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, s.requestWithPlatformScore("widget", ""))

	s.Equal(http.StatusOK, w.Code, "widget with fallback=log should proxy")
}

func (s *DecideSuite) TestCaptchaRenderedForSupportedPlatform() {
	e := s.newPlatformEngine()

	handler := e.Middleware()(okHandler())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, s.requestWithPlatformScore("web", ""))

	s.Equal(499, w.Code, "web platform should get captcha")
	s.Contains(w.Body.String(), "Captcha required")
}

func (s *DecideSuite) TestCaptchaRenderedForVersionedPlatform() {
	e := s.newPlatformEngine()

	handler := e.Middleware()(okHandler())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, s.requestWithPlatformScore("ios", "3.0.0"))

	s.Equal(499, w.Code, "iOS 3.0.0 should get captcha")
}

func (s *DecideSuite) TestEmptyPlatformGetsCaptcha() {
	e := s.newPlatformEngine()

	handler := e.Middleware()(okHandler())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, s.requestWithPlatformScore("", ""))

	s.Equal(499, w.Code, "empty platform (browser/SSR) should get captcha")
	s.Contains(w.Body.String(), "Captcha required")
}

// --- Composite key (NAT-aware) tests ---

func (s *DecideSuite) TestEscalationCompositeKey() {
	e := s.newEngine(5, 8)
	e.cfg.CaptchaToBlock = 2
	e.cfg.CaptchaToBlockWindow = time.Minute
	e.cfg.SoftBlockDuration = time.Minute

	handler := e.Middleware()(okHandler())

	// Bot (discriminator "bot:aaa") triggers 2 captcha → soft block
	for range 2 {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, s.requestWithDiscriminator("1.1.1.1", 6, "bot:aaa"))
		s.Equal(499, w.Code)
	}

	// Bot should be soft-blocked
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, s.requestWithDiscriminator("1.1.1.1", 0, "bot:aaa"))
	s.Equal(http.StatusForbidden, w.Code, "bot should be soft-blocked")

	// Legitimate user (discriminator "web:bbb") — same IP — should pass
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, s.requestWithDiscriminator("1.1.1.1", 0, "web:bbb"))
	s.Equal(http.StatusOK, w.Code, "legit user behind same NAT should not be soft-blocked")
}

func (s *DecideSuite) TestSoftBlockPerDiscriminator() {
	e := s.newEngine(5, 8)
	e.cfg.CaptchaToBlock = 1
	e.cfg.CaptchaToBlockWindow = time.Minute
	e.cfg.SoftBlockDuration = time.Minute

	handler := e.Middleware()(okHandler())

	// Trigger soft block for discriminator A
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, s.requestWithDiscriminator("2.2.2.2", 6, "iOS:aaa"))
	s.Equal(499, w.Code)

	// A is now soft-blocked
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, s.requestWithDiscriminator("2.2.2.2", 0, "iOS:aaa"))
	s.Equal(http.StatusForbidden, w.Code)

	// B with same IP is NOT soft-blocked
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, s.requestWithDiscriminator("2.2.2.2", 0, "Android:bbb"))
	s.Equal(http.StatusOK, w.Code)
}

func (s *DecideSuite) requestWithDiscriminator(ipStr string, score float64, discriminator string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	rc := &waf.RequestContext{
		ClientIP:      netip.MustParseAddr(ipStr),
		WAFScore:      score,
		Discriminator: discriminator,
	}

	return r.WithContext(waf.NewContext(r.Context(), rc))
}

func (s *DecideSuite) newPlatformEngine() *Engine {
	return New(Config{
		CaptchaThreshold:     5,
		BlockThreshold:       8,
		CaptchaStatusCode:    499,
		BlockStatusCode:      http.StatusForbidden,
		CaptchaToBlock:       3,
		CaptchaToBlockWindow: 10 * time.Minute,
		SoftBlockDuration:    10 * time.Minute,
		CaptchaFallback:      waf.ActionBlock,
		Platforms: []PlatformConfig{
			{Platform: "web", Captcha: true, Fallback: waf.ActionBlock},
			{Platform: "desktop", Captcha: true, Fallback: waf.ActionBlock},
			{Platform: "mobile", Captcha: true, Fallback: waf.ActionBlock},
			{Platform: "widget", Captcha: false, Fallback: waf.ActionPass},
			{Platform: "ios", Captcha: true, MinVersion: [3]int{2, 5, 0}, Fallback: waf.ActionPass},
			{Platform: "android", Captcha: true, MinVersion: [3]int{3, 0, 0}, Fallback: waf.ActionPass},
		},
	}, storage.NewMemoryKV(100000), nil, nil, nil, nil, embedlog.NewLogger(false, false), testMetrics())
}

func (s *DecideSuite) requestWithPlatformScore(platform, version string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	rc := &waf.RequestContext{
		ClientIP: netip.MustParseAddr("1.1.1.1"),
		WAFScore: 6, // above captcha threshold (5), below block threshold (8)
		Platform: platform,
		Version:  version,
	}

	return r.WithContext(waf.NewContext(r.Context(), rc))
}
