package challenge

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"wafsrv/internal/waf/storage"

	"github.com/stretchr/testify/suite"
)

type CacheSuite struct {
	suite.Suite
}

func TestCache(t *testing.T) {
	suite.Run(t, new(CacheSuite))
}

func newTestStore() storage.KVStore {
	return storage.NewMemoryKV(10000)
}

func (s *CacheSuite) TestIPCacheValid() {
	c := NewCache(CacheConfig{
		CookieName: "waf_pass",
		CookieTTL:  30 * time.Minute,
		IPCacheTTL: 30 * time.Minute,
	}, newTestStore())

	ip := netip.MustParseAddr("1.2.3.4")
	c.AddIP(ip)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	s.True(c.IsValid(r, ip), "IP in cache should be valid")
}

func (s *CacheSuite) TestIPCacheMiss() {
	c := NewCache(CacheConfig{
		CookieName: "waf_pass",
		CookieTTL:  30 * time.Minute,
		IPCacheTTL: 30 * time.Minute,
	}, newTestStore())

	ip := netip.MustParseAddr("5.5.5.5")
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	s.False(c.IsValid(r, ip), "IP not in cache should be invalid")
}

func (s *CacheSuite) TestCookieRoundTrip() {
	c := NewCache(CacheConfig{
		Secret:     []byte("test-secret"),
		CookieName: "waf_pass",
		CookieTTL:  30 * time.Minute,
		IPCacheTTL: 30 * time.Minute,
	}, newTestStore())

	// set cookie
	w := httptest.NewRecorder()
	c.SetCookie(w)

	cookies := w.Result().Cookies()
	s.Require().Len(cookies, 1)
	s.Equal("waf_pass", cookies[0].Name)

	// validate cookie
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(cookies[0])

	ip := netip.MustParseAddr("9.9.9.9")
	s.True(c.IsValid(r, ip), "valid cookie should pass")
}

func (s *CacheSuite) TestInvalidCookie() {
	c := NewCache(CacheConfig{
		Secret:     []byte("test-secret"),
		CookieName: "waf_pass",
		CookieTTL:  30 * time.Minute,
		IPCacheTTL: 30 * time.Minute,
	}, newTestStore())

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: "waf_pass", Value: "garbage"})

	ip := netip.MustParseAddr("9.9.9.9")
	s.False(c.IsValid(r, ip), "invalid cookie should fail")
}

func BenchmarkCacheIsValidIP(b *testing.B) {
	c := NewCache(CacheConfig{
		CookieName: "waf_pass",
		CookieTTL:  30 * time.Minute,
		IPCacheTTL: 30 * time.Minute,
	}, newTestStore())

	ip := netip.MustParseAddr("1.2.3.4")
	c.AddIP(ip)

	r := httptest.NewRequest(http.MethodGet, "/", nil)

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		c.IsValid(r, ip)
	}
}

func BenchmarkCacheIsValidMiss(b *testing.B) {
	c := NewCache(CacheConfig{
		CookieName: "waf_pass",
		CookieTTL:  30 * time.Minute,
		IPCacheTTL: 30 * time.Minute,
	}, newTestStore())

	ip := netip.MustParseAddr("5.5.5.5")
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		c.IsValid(r, ip)
	}
}

func BenchmarkCacheIsValidCookie(b *testing.B) {
	c := NewCache(CacheConfig{
		Secret:     []byte("bench-secret"),
		CookieName: "waf_pass",
		CookieTTL:  30 * time.Minute,
		IPCacheTTL: 30 * time.Minute,
	}, newTestStore())

	w := httptest.NewRecorder()
	c.SetCookie(w)

	cookie := w.Result().Cookies()[0]
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(cookie)

	ip := netip.MustParseAddr("9.9.9.9")

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		c.IsValid(r, ip)
	}
}
