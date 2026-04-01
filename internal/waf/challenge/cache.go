package challenge

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"wafsrv/internal/waf/storage"
)

// Cache stores captcha pass state via cookies (HMAC) and IP fallback (KVStore).
type Cache struct {
	secret     []byte
	cookieName string
	cookieTTL  time.Duration
	ipCacheTTL time.Duration
	store      storage.KVStore
}

// CacheConfig holds cache configuration.
type CacheConfig struct {
	Secret     []byte
	CookieName string
	CookieTTL  time.Duration
	IPCacheTTL time.Duration
}

// NewCache creates a new captcha pass cache.
func NewCache(cfg CacheConfig, store storage.KVStore) *Cache {
	if len(cfg.Secret) == 0 {
		cfg.Secret = []byte("wafsrv-default-secret-change-me")
	}

	return &Cache{
		secret:     cfg.Secret,
		cookieName: cfg.CookieName,
		cookieTTL:  cfg.CookieTTL,
		ipCacheTTL: cfg.IPCacheTTL,
		store:      store,
	}
}

// Secret returns the HMAC secret used by this cache.
func (c *Cache) Secret() []byte {
	return c.secret
}

// IsValid checks if the request has a valid captcha pass (cookie or IP).
func (c *Cache) IsValid(r *http.Request, clientIP netip.Addr) bool {
	// check cookie first
	if cookie, err := r.Cookie(c.cookieName); err == nil {
		if c.validateCookie(cookie.Value) {
			return true
		}
	}

	// check IP cache
	exists, _ := c.store.Exists("cap:" + clientIP.String())

	return exists
}

// SetCookie sets a captcha pass cookie on the response.
func (c *Cache) SetCookie(w http.ResponseWriter) {
	value := c.signCookie()

	http.SetCookie(w, &http.Cookie{
		Name:     c.cookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   int(c.cookieTTL.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// AddIP adds an IP to the pass cache (for API clients without cookies).
func (c *Cache) AddIP(ip netip.Addr) {
	_ = c.store.Set("cap:"+ip.String(), []byte("1"), c.ipCacheTTL)
}

func (c *Cache) signCookie() string {
	ts := time.Now().Unix()
	data := []byte(time.Unix(ts, 0).Format(time.RFC3339))

	mac := hmac.New(sha256.New, c.secret)
	mac.Write(data)
	sig := hex.EncodeToString(mac.Sum(nil))

	return hex.EncodeToString(data) + "." + sig
}

func (c *Cache) validateCookie(value string) bool {
	dataHex, sig, ok := strings.Cut(value, ".")
	if !ok {
		return false
	}

	data, err := hex.DecodeString(dataHex)
	if err != nil {
		return false
	}

	// verify HMAC
	mac := hmac.New(sha256.New, c.secret)
	mac.Write(data)
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(sig), []byte(expectedSig)) {
		return false
	}

	// check TTL
	t, err := time.Parse(time.RFC3339, string(data))
	if err != nil {
		return false
	}

	return time.Since(t) < c.cookieTTL
}
