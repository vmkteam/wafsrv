package app

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/suite"
)

type ConfigSuite struct {
	suite.Suite
}

func TestConfig(t *testing.T) {
	suite.Run(t, new(ConfigSuite))
}

func (s *ConfigSuite) TestLoadMinimalConfig() {
	path := s.writeConfig(`
[Proxy]
Targets = ["http://localhost:3000"]
ServiceName = "test-svc"
`)

	cfg, err := LoadConfig(path)

	s.Require().NoError(err, "should load minimal config")
	s.Equal([]string{"http://localhost:3000"}, cfg.Proxy.Targets)
	s.Equal("test-svc", cfg.Proxy.ServiceName)
}

func (s *ConfigSuite) TestDefaults() {
	path := s.writeConfig(`
[Proxy]
Targets = ["http://localhost:3000"]
ServiceName = "test-svc"
`)

	cfg, err := LoadConfig(path)

	s.Require().NoError(err)
	s.Equal(":8080", cfg.Proxy.Listen, "should default Listen to :8080")
	s.Equal("30s", cfg.Proxy.Timeouts.Read, "should default Read timeout")
	s.Equal("30s", cfg.Proxy.Timeouts.Write, "should default Write timeout")
	s.Equal("120s", cfg.Proxy.Timeouts.Idle, "should default Idle timeout")
	s.Equal("1MB", cfg.Proxy.Limits.MaxRequestBody, "should default MaxRequestBody")
	s.Equal("127.0.0.1:8081", cfg.Management.Listen, "should default Management.Listen")
	s.True(cfg.Proxy.CircuitBreaker.cbEnabled(), "should enable circuit breaker by default")
	s.Equal(10, cfg.Proxy.CircuitBreaker.Threshold, "should default CB threshold")
}

func (s *ConfigSuite) TestCircuitBreakerExplicitDisable() {
	path := s.writeConfig(`
[Proxy]
Targets = ["http://localhost:3000"]
ServiceName = "test-svc"

[Proxy.CircuitBreaker]
Enabled = false
`)

	cfg, err := LoadConfig(path)

	s.Require().NoError(err)
	s.False(cfg.Proxy.CircuitBreaker.cbEnabled(), "should respect explicit Enabled = false")
	s.Equal(10, cfg.Proxy.CircuitBreaker.Threshold, "should still apply default threshold")
}

func (s *ConfigSuite) TestRealIPDefaults() {
	path := s.writeConfig(`
[Proxy]
Targets = ["http://localhost:3000"]
ServiceName = "test-svc"
`)

	cfg, err := LoadConfig(path)

	s.Require().NoError(err)
	s.Equal([]string{"CF-Connecting-IP", "X-Real-IP", "X-Forwarded-For"}, cfg.Proxy.RealIP.Headers, "should have default RealIP headers")
	s.Contains(cfg.Proxy.RealIP.TrustedProxies, "10.0.0.0/8", "should have default trusted proxies")
}

func (s *ConfigSuite) TestValidateMissingTargets() {
	path := s.writeConfig(`
[Proxy]
ServiceName = "test-svc"
`)

	_, err := LoadConfig(path)
	s.Require().Error(err, "should fail when Targets is empty")
	s.Contains(err.Error(), "Targets")
}

func (s *ConfigSuite) TestValidateMissingServiceName() {
	path := s.writeConfig(`
[Proxy]
Targets = ["http://localhost:3000"]
`)

	_, err := LoadConfig(path)
	s.Require().Error(err, "should fail when ServiceName is empty")
	s.Contains(err.Error(), "ServiceName")
}

func (s *ConfigSuite) TestValidateInvalidSize() {
	path := s.writeConfig(`
[Proxy]
Targets = ["http://localhost:3000"]
ServiceName = "test-svc"

[Proxy.Limits]
MaxRequestBody = "abc"
`)

	_, err := LoadConfig(path)
	s.Require().Error(err, "should fail on invalid size string")
	s.Contains(err.Error(), "invalid size")
}

func (s *ConfigSuite) TestValidateURLRuleNoFields() {
	path := s.writeConfig(`
[Proxy]
Targets = ["http://localhost:3000"]
ServiceName = "test-svc"

[[RateLimit.URLRules]]
Name = "empty"
Limit = "10/min"
`)

	_, err := LoadConfig(path)
	s.Require().Error(err, "URLRule without Path/Method/Host should fail")
	s.Contains(err.Error(), "Path/Method/Host")
}

func (s *ConfigSuite) TestValidateAdaptiveBoostExceedsCaptchaThreshold() {
	path := s.writeConfig(`
[Proxy]
Targets = ["http://localhost:3000"]
ServiceName = "test-svc"

[Decision]
CaptchaThreshold = 5
BlockThreshold = 8

[Adaptive.AutoAttack]
ScoreBoost = 6
`)

	_, err := LoadConfig(path)
	s.Require().Error(err, "ScoreBoost >= CaptchaThreshold must fail validation")
	s.Contains(err.Error(), "ScoreBoost")
}

func (s *ConfigSuite) TestValidateAdaptiveBoostBelowThresholdOK() {
	path := s.writeConfig(`
[Proxy]
Targets = ["http://localhost:3000"]
ServiceName = "test-svc"

[Decision]
CaptchaThreshold = 5
BlockThreshold = 8

[Adaptive.AutoAttack]
ScoreBoost = 2
`)

	_, err := LoadConfig(path)
	s.Require().NoError(err, "ScoreBoost < CaptchaThreshold should be OK")
}

func (s *ConfigSuite) TestValidateDuplicateRuleName() {
	path := s.writeConfig(`
[Proxy]
Targets = ["http://localhost:3000"]
ServiceName = "test-svc"

[[RateLimit.Rules]]
Name = "shared"
Match = ["auth.login"]
Limit = "10/min"

[[RateLimit.URLRules]]
Name = "shared"
Path = ["/api/"]
Limit = "10/min"
`)

	_, err := LoadConfig(path)
	s.Require().Error(err, "duplicate rule name across Rules/URLRules should fail")
	s.Contains(err.Error(), "duplicated")
}

func (s *ConfigSuite) TestURLRuleLimiterConfig() {
	path := s.writeConfig(`
[Proxy]
Targets = ["http://localhost:3000"]
ServiceName = "test-svc"

[[RateLimit.URLRules]]
Name = "search"
Path = ["/search/"]
Method = ["GET"]
Limit = "10/min"
Action = "block"
`)

	cfg, err := LoadConfig(path)
	s.Require().NoError(err)

	lc, err := cfg.LimiterConfig()
	s.Require().NoError(err)
	s.Require().Len(lc.URLRules, 1)
	s.Equal("search", lc.URLRules[0].Name)
	s.Equal([]string{"/search/"}, lc.URLRules[0].Path)
	s.Equal([]string{"GET"}, lc.URLRules[0].Method)
	s.Equal(10, lc.URLRules[0].Limit.Count)
	s.Equal("block", lc.URLRules[0].Action)
}

func (s *ConfigSuite) TestFullConfig() {
	path := s.writeConfig(`
[Proxy]
Listen = ":9090"
Targets = ["http://backend1:3000", "http://backend2:3000"]
ServiceName = "multi-svc"

[Proxy.Timeouts]
Read = "10s"
Write = "15s"
Idle = "60s"

[Proxy.Limits]
MaxRequestBody = "10MB"

[Proxy.RealIP]
Headers = ["CF-Connecting-IP", "X-Real-IP"]
TrustedProxies = ["10.0.0.0/8"]

[Proxy.CircuitBreaker]
Enabled = true
Threshold = 5
Timeout = "15s"

[Management]
Listen = "0.0.0.0:9091"

`)

	cfg, err := LoadConfig(path)

	s.Require().NoError(err)
	s.Equal(":9090", cfg.Proxy.Listen)
	s.Len(cfg.Proxy.Targets, 2)
	s.Equal("10s", cfg.Proxy.Timeouts.Read)
	s.Equal("10MB", cfg.Proxy.Limits.MaxRequestBody)
	s.Equal([]string{"CF-Connecting-IP", "X-Real-IP"}, cfg.Proxy.RealIP.Headers)
	s.Equal(5, cfg.Proxy.CircuitBreaker.Threshold)
	s.Equal("0.0.0.0:9091", cfg.Management.Listen)
}

func (s *ConfigSuite) TestProxyConfig() {
	path := s.writeConfig(`
[Proxy]
Targets = ["http://localhost:3000"]
ServiceName = "test-svc"
`)

	cfg, err := LoadConfig(path)
	s.Require().NoError(err)

	_, err = cfg.ProxyConfig()
	s.Require().NoError(err, "should build proxy config")

	urls, err := cfg.ProxyTargetURLs()
	s.Require().NoError(err, "should parse target URLs")
	s.Len(urls, 1)
	s.Equal("http", urls[0].Scheme)
	s.Equal("localhost:3000", urls[0].Host)
}

func (s *ConfigSuite) TestInvalidTOML() {
	path := s.writeConfig(`invalid toml {{`)

	_, err := LoadConfig(path)
	s.Error(err, "should fail on invalid TOML")
}

func (s *ConfigSuite) TestCaptchaSecretNotRequiredWhenDisabled() {
	path := s.writeConfig(`
[Proxy]
Targets = ["http://localhost:3000"]
ServiceName = "test-svc"
`)

	_, err := LoadConfig(path)
	s.Require().NoError(err, "captcha disabled (Provider == \"\") must not require Secret")
}

func (s *ConfigSuite) TestCaptchaSecretRequiredWhenProviderSet() {
	path := s.writeConfig(`
[Proxy]
Targets = ["http://localhost:3000"]
ServiceName = "test-svc"

[Captcha]
Provider = "pow"
`)

	_, err := LoadConfig(path)
	s.Require().Error(err, "Captcha.Provider set without Secret must fail")
	s.Contains(err.Error(), "Captcha.Secret is required")
}

func (s *ConfigSuite) TestCaptchaSecretTooShort() {
	path := s.writeConfig(`
[Proxy]
Targets = ["http://localhost:3000"]
ServiceName = "test-svc"

[Captcha]
Provider = "turnstile"
Secret = "short"
`)

	_, err := LoadConfig(path)
	s.Require().Error(err, "secret shorter than 32 bytes must fail")
	s.Contains(err.Error(), "at least 32 bytes")
}

func (s *ConfigSuite) TestCaptchaSecretValid() {
	path := s.writeConfig(`
[Proxy]
Targets = ["http://localhost:3000"]
ServiceName = "test-svc"

[Captcha]
Provider = "pow"
Secret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
`)

	cfg, err := LoadConfig(path)
	s.Require().NoError(err, "valid 64-hex secret with provider must pass validation")
	s.Equal("pow", cfg.Captcha.Provider)
	s.Len(cfg.Captcha.Secret, 64)
}

func (s *ConfigSuite) TestRedacted() {
	cfg := Config{
		Proxy: ProxyConfig{ServiceName: "svc"},
		Captcha: CaptchaConfig{
			Provider:  "turnstile",
			SiteKey:   "public-site-key",
			SecretKey: "captcha-secret-key",
			Secret:    "hmac-secret",
		},
		Signing: SigningConfig{
			Web:     SigningPlatformConfig{Secret: "web-secret"},
			Android: SigningPlatformConfig{Secret: "android-secret"},
			IOS:     SigningPlatformConfig{Secret: "ios-secret"},
		},
		Alerting: AlertingConfig{
			Webhooks: []WebhookConfig{{URL: "https://hooks.slack.com/services/T00/B00/token", Events: []string{"hard_block"}}},
		},
	}

	red := cfg.Redacted()

	s.Empty(red.Captcha.Secret)
	s.Empty(red.Captcha.SecretKey)
	s.Equal("public-site-key", red.Captcha.SiteKey, "site key is public and must be kept")
	s.Empty(red.Signing.Web.Secret)
	s.Empty(red.Signing.Android.Secret)
	s.Empty(red.Signing.IOS.Secret)
	s.Require().Len(red.Alerting.Webhooks, 1)
	s.Empty(red.Alerting.Webhooks[0].URL)
	s.Equal([]string{"hard_block"}, red.Alerting.Webhooks[0].Events, "non-secret webhook fields must be kept")

	// original must be untouched
	s.Equal("hmac-secret", cfg.Captcha.Secret)
	s.Equal("web-secret", cfg.Signing.Web.Secret)
	s.Equal("https://hooks.slack.com/services/T00/B00/token", cfg.Alerting.Webhooks[0].URL)
}

func (s *ConfigSuite) writeConfig(content string) string {
	dir := s.T().TempDir()
	path := filepath.Join(dir, "test.toml")
	err := os.WriteFile(path, []byte(content), 0o644)
	s.Require().NoError(err)
	return path
}
