package sign

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"wafsrv/internal/waf"
	"wafsrv/internal/waf/storage"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/suite"
	"github.com/vmkteam/embedlog"
)

type SignSuite struct {
	suite.Suite
}

func TestSign(t *testing.T) {
	suite.Run(t, new(SignSuite))
}

func (s *SignSuite) newVerifier() *Verifier {
	return New(Config{
		Mode:       "detection",
		TTL:        5 * time.Minute,
		NonceCache: 1000,
		Web:        PlatformSecret{Enabled: true, Secret: "web-test-secret"},
		Android:    PlatformSecret{Enabled: true, Secret: "android-test-secret"},
		IOS:        PlatformSecret{Enabled: true, Secret: "ios-test-secret"},
		Methods: []MethodRule{
			{
				Name:       "auth",
				Endpoint:   "main",
				Methods:    []string{"auth.login"},
				Platforms:  []string{"web", "android"},
				SignFields: []string{"phone", "email"},
			},
			{
				Name:       "search",
				Endpoint:   "",
				Methods:    []string{"catalog.search"},
				Platforms:  []string{"web"},
				SignFields: []string{"query"},
			},
		},
	}, storage.NewMemoryKV(1000), embedlog.NewLogger(false, false), testMetrics())
}

func testMetrics() Metrics {
	return Metrics{
		Total: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "test_sign_total",
			Help: "test",
		}, []string{"platform", "result"}),
	}
}

func (s *SignSuite) TestTokenWeb() {
	v := s.newVerifier()
	t1 := v.token("1.2.3.4", "Mozilla/5.0", "desktop")
	t2 := v.token("1.2.3.4", "Mozilla/5.0", "desktop")
	s.Equal(t1, t2, "same input → same token")

	t3 := v.token("5.6.7.8", "Mozilla/5.0", "desktop")
	s.NotEqual(t1, t3, "different IP → different token")
}

func (s *SignSuite) TestTokenMobile() {
	v := s.newVerifier()
	t1 := v.token("1.2.3.4", "App/1.0", "android")
	t2 := v.token("5.6.7.8", "App/2.0", "android")
	s.Equal(t1, t2, "Android: static secret, IP/UA don't matter")

	t3 := v.token("1.2.3.4", "App/1.0", "ios")
	s.NotEqual(t1, t3, "different platform → different token")
}

func (s *SignSuite) TestHMACSHA256() {
	sig := hmacSHA256hex([]byte("secret"), "data")
	s.Len(sig, 64, "HMAC-SHA256 hex = 64 chars")
	s.Equal(sig, hmacSHA256hex([]byte("secret"), "data"), "deterministic")
	s.NotEqual(sig, hmacSHA256hex([]byte("other"), "data"), "different key → different sig")
}

func (s *SignSuite) TestVerify_Unsigned() {
	v := s.newVerifier()
	r := s.newRequest("")
	rc := s.newRC()

	result := v.Verify(r, rc)
	s.Equal("unsigned", result.TrafficType)
	s.Zero(result.Score)
}

func (s *SignSuite) TestVerify_BadFormat() {
	v := s.newVerifier()

	for _, header := range []string{"bad", "v2.1.2.3", "v1.only_two.parts"} {
		r := s.newRequest(header)
		rc := s.newRC()
		result := v.Verify(r, rc)
		s.Equal("invalid", result.TrafficType, "header=%s", header)
		s.InDelta(3.0, result.Score, 0.01)
	}
}

func (s *SignSuite) TestVerify_Expired() {
	v := s.newVerifier()
	oldTS := time.Now().Add(-10 * time.Minute).Unix()
	header := s.signHeader(strconv.FormatInt(oldTS, 10), "abc12345")
	// replace timestamp in header
	parts := splitHeader(header)
	parts[1] = strconv.FormatInt(oldTS, 10)
	// re-sign with old timestamp
	tok := v.token("127.0.0.1", "Mozilla/5.0", "desktop")
	rc := &waf.RequestContext{ClientIP: netip.MustParseAddr("127.0.0.1"), Platform: "desktop", Version: "1.0"}
	canonical := v.buildCanonical("v1", parts[1], parts[2], httptest.NewRequest(http.MethodGet, "/", nil), rc)
	parts[3] = hmacSHA256hex(tok, canonical)

	r := s.newRequest(joinHeader(parts))
	result := v.Verify(r, rc)
	s.Equal("expired", result.TrafficType)
	s.InDelta(3.0, result.Score, 0.01)
}

func (s *SignSuite) TestVerify_Replay() {
	v := s.newVerifier()
	r := s.newRequest("")
	rc := s.newRC()

	header := s.makeValidHeader(v, rc, r)
	r.Header.Set(headerName, header)
	result := v.Verify(r, rc)
	s.True(result.Valid)

	// same nonce again
	r2 := s.newRequest(header)
	result2 := v.Verify(r2, rc)
	s.Equal("replay", result2.TrafficType)
	s.InDelta(5.0, result2.Score, 0.01)
}

func (s *SignSuite) TestVerify_Valid() {
	v := s.newVerifier()
	r := s.newRequest("")
	rc := s.newRC()

	header := s.makeValidHeader(v, rc, r)
	r.Header.Set(headerName, header)
	result := v.Verify(r, rc)
	s.True(result.Valid)
	s.Equal("desktop", result.TrafficType)
}

func (s *SignSuite) TestVerify_Mismatch() {
	v := s.newVerifier()
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	r := s.newRequest("v1." + ts + ".abc12345.0000000000000000000000000000000000000000000000000000000000000000")
	rc := s.newRC()
	result := v.Verify(r, rc)
	s.Equal("invalid", result.TrafficType)
	s.InDelta(5.0, result.Score, 0.01)
	s.Contains(result.Reason, "signature mismatch")
}

func (s *SignSuite) TestFindRule_ExactEndpoint() {
	v := s.newVerifier()
	rule := v.findRule("auth.login", "main")
	s.Require().NotNil(rule)
	s.Equal("auth", rule.Name)
}

func (s *SignSuite) TestFindRule_EmptyEndpoint() {
	v := s.newVerifier()
	rule := v.findRule("catalog.search", "any-endpoint")
	s.Require().NotNil(rule, "empty endpoint matches all")
	s.Equal("search", rule.Name)
}

func (s *SignSuite) TestFindRule_CaseInsensitive() {
	v := s.newVerifier()
	s.NotNil(v.findRule("AUTH.LOGIN", "MAIN"))
	s.NotNil(v.findRule("Auth.Login", "Main"))
}

func (s *SignSuite) TestFindRule_NoMatch() {
	v := s.newVerifier()
	s.Nil(v.findRule("auth.login", "catalog"))
	s.Nil(v.findRule("unknown.method", "main"))
}

func (s *SignSuite) TestExtractFields() {
	body := []byte(`{"jsonrpc":"2.0","method":"auth.login","params":{"phone":"+79991234567","email":"test@test.com","password":"xxx"},"id":1}`)
	fields := extractFields(body, []string{"phone", "email"})
	s.Equal([]string{"email=test@test.com", "phone=+79991234567"}, fields)
}

func (s *SignSuite) TestExtractFields_MissingField() {
	body := []byte(`{"jsonrpc":"2.0","method":"auth.login","params":{"phone":"+79991234567"},"id":1}`)
	fields := extractFields(body, []string{"phone", "email"})
	s.Equal([]string{"phone=+79991234567"}, fields, "missing email skipped")
}

func (s *SignSuite) TestExtractFields_Types() {
	body := []byte(`{"jsonrpc":"2.0","method":"test","params":{"name":"John","age":30,"active":true,"ids":[3,1,2]},"id":1}`)
	fields := extractFields(body, []string{"name", "age", "active", "ids"})
	s.Equal([]string{"active=true", "age=30", "ids=1,2,3", "name=John"}, fields)
}

func (s *SignSuite) TestExtractFields_Empty() {
	s.Nil(extractFields(nil, []string{"a"}))
	s.Nil(extractFields([]byte(`{}`), []string{"a"}))
	s.Empty(extractFields([]byte(`{"params":{}}`), []string{"a"}))
}

func (s *SignSuite) TestExtractFields_CaseInsensitive() {
	body := []byte(`{"jsonrpc":"2.0","method":"test","params":{"Phone":"+7999"},"id":1}`)
	fields := extractFields(body, []string{"phone"})
	s.Equal([]string{"phone=+7999"}, fields, "case-insensitive key match")
}

func (s *SignSuite) TestFormatValue() {
	s.Equal("hello", formatValue("hello"))
	s.Equal("42", formatValue(float64(42)))
	s.Equal("3.14", formatValue(3.14))
	s.Equal("true", formatValue(true))
	s.Equal("1,2,3", formatValue([]any{float64(3), float64(1), float64(2)}))
}

func (s *SignSuite) TestClassifyPlatform() {
	s.Equal("web", classifyPlatform("desktop"))
	s.Equal("web", classifyPlatform("mobile"))
	s.Equal("web", classifyPlatform("widget"))
	s.Equal("android", classifyPlatform("android"))
	s.Equal("ios", classifyPlatform("ios"))
	s.Equal("web", classifyPlatform("unknown"))
	s.Equal("web", classifyPlatform(""))
}

// --- helpers ---

func (s *SignSuite) newRequest(signHeader string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("User-Agent", "Mozilla/5.0")

	if signHeader != "" {
		r.Header.Set(headerName, signHeader)
	}

	return r
}

func (s *SignSuite) newRC() *waf.RequestContext {
	return &waf.RequestContext{
		RequestID: "test-123",
		ClientIP:  netip.MustParseAddr("127.0.0.1"),
		Platform:  "desktop",
		Version:   "1.0",
	}
}

func (s *SignSuite) makeValidHeader(v *Verifier, rc *waf.RequestContext, r *http.Request) string {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := "test1234"
	tok := v.token(rc.ClientIP.String(), r.UserAgent(), rc.Platform)
	canonical := v.buildCanonical(version, ts, nonce, r, rc)
	sig := hmacSHA256hex(tok, canonical)

	return fmt.Sprintf("%s.%s.%s.%s", version, ts, nonce, sig)
}

func (s *SignSuite) signHeader(ts, nonce string) string {
	return fmt.Sprintf("v1.%s.%s.placeholder", ts, nonce)
}

func splitHeader(h string) []string { return strings.SplitN(h, ".", 4) }

func joinHeader(parts []string) string { return strings.Join(parts, ".") }
