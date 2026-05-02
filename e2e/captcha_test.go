package e2e

import (
	"net/http"
	"strconv"
	"strings"

	"wafsrv/internal/waf"
)

// --- 07: Captcha (decide) ---
//
// Captcha is triggered via TrafficFilter rule "e2e-captcha-bot" (Action=captcha,
// +5 score) at CaptchaThreshold=5. Each test uses a distinct UA so the
// per-discriminator escalation counter (CaptchaToBlock=3) stays isolated.
//
// Covers commit 27f19a2 (Migrate captcha status code from 499 to 403):
//   - captcha returns 403 (was 499)
//   - captcha sets X-WAF-Action: captcha (disambiguates from block at same status)
//   - captcha never sets Retry-After (semantics: solve, not wait)
//   - block / soft_block / throttle DO set X-WAF-Action and Retry-After
//   - Decision is set in middlewares so isBlocked metric reads from context

func (s *E2ESuite) Test07_Captcha_Headers() {
	req, _ := http.NewRequest(http.MethodGet, dataURL+"/", nil)
	req.Header.Set("User-Agent", "E2ECaptchaBot/1.0")
	resp, err := http.DefaultClient.Do(req)
	s.Require().NoError(err)
	defer resp.Body.Close()

	s.Equal(http.StatusForbidden, resp.StatusCode, "captcha must return 403 (not 499)")
	s.Equal(waf.ActionHeaderCaptcha, resp.Header.Get(waf.HeaderAction),
		"captcha must set X-WAF-Action: captcha to disambiguate from block (both 403)")
	s.Empty(resp.Header.Get("Retry-After"),
		"captcha must NOT set Retry-After (solve, not wait)")
}

func (s *E2ESuite) Test07_Captcha_Body() {
	req, _ := http.NewRequest(http.MethodGet, dataURL+"/", nil)
	req.Header.Set("User-Agent", "E2ECaptchaBody/1.0")
	resp, err := http.DefaultClient.Do(req)
	s.Require().NoError(err)
	defer resp.Body.Close()

	body := s.readBody(resp)
	s.Equal(http.StatusForbidden, resp.StatusCode)
	// no Captcha.Provider configured in e2e.toml → falls back to plain "Captcha required" text
	s.Contains(body, "Captcha required",
		"unconfigured-provider captcha falls back to http.Error")
}

func (s *E2ESuite) Test07_Captcha_PerRequestIsolated() {
	req, _ := http.NewRequest(http.MethodGet, dataURL+"/", nil)
	req.Header.Set("User-Agent", "E2ECaptchaBot/1.0")

	for i := range 2 {
		resp, err := http.DefaultClient.Do(req)
		s.Require().NoError(err)
		s.Equal(http.StatusForbidden, resp.StatusCode, "request %d: captcha", i+1)
		s.Equal(waf.ActionHeaderCaptcha, resp.Header.Get(waf.HeaderAction))
		resp.Body.Close()
	}
}

// Test07_Captcha_EscalationToSoftBlock walks through the captcha→soft_block
// transition end-to-end and asserts the composite key isolates discriminators:
//
//	requests 1..3 with the captcha UA → 403 / X-WAF-Action: captcha
//	on request 3 the engine reaches CaptchaToBlock=3 and arms BlockedUntil
//	request 4 (same UA → same discriminator) → 403 / X-WAF-Action: block
//	  with Retry-After equal to the remaining SoftBlockDuration
//	a sibling UA from the same IP must NOT inherit the soft_block —
//	  the (IP:Platform:fnv32(UA)) key is what makes wafsrv NAT-aware
func (s *E2ESuite) Test07_Captcha_EscalationToSoftBlock() {
	req, _ := http.NewRequest(http.MethodGet, dataURL+"/", nil)
	req.Header.Set("User-Agent", "E2ECapEsc/1.0")

	// CaptchaToBlock = 3 in e2e.toml — drive the counter to escalation.
	for i := range 3 {
		resp, err := http.DefaultClient.Do(req)
		s.Require().NoError(err)
		s.Equal(http.StatusForbidden, resp.StatusCode, "captcha #%d", i+1)
		s.Equal(waf.ActionHeaderCaptcha, resp.Header.Get(waf.HeaderAction),
			"escalation step %d must still render captcha", i+1)
		s.Empty(resp.Header.Get("Retry-After"),
			"captcha must not leak Retry-After mid-escalation")
		resp.Body.Close()
	}

	// Next request with the same discriminator must be soft-blocked.
	resp, err := http.DefaultClient.Do(req)
	s.Require().NoError(err)

	s.Equal(http.StatusForbidden, resp.StatusCode, "post-escalation must 403")
	s.Equal(waf.ActionHeaderBlock, resp.Header.Get(waf.HeaderAction),
		"soft_block must set X-WAF-Action: block (clients can't tell from status)")

	retryAfter := resp.Header.Get("Retry-After")
	s.NotEmpty(retryAfter, "soft_block must surface remaining TTL via Retry-After")

	secs, err := strconv.Atoi(retryAfter)
	s.Require().NoError(err, "Retry-After must be integer seconds")
	s.Positive(secs, "remaining TTL must be positive")
	// SoftBlockDuration=1m → cap at 60 (rounding may inflate by 1)
	s.LessOrEqual(secs, 61, "Retry-After must not exceed SoftBlockDuration")
	resp.Body.Close()

	// Composite-key isolation: a different UA from the same IP must pass.
	// Without the discriminator in the soft-block key, the whole NAT'd IP
	// would lock out behind one bad client.
	other, _ := http.NewRequest(http.MethodGet, dataURL+"/", nil)
	other.Header.Set("User-Agent", "E2EUnrelatedClient/1.0") // not matched by captcha rule

	resp, err = http.DefaultClient.Do(other)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusOK, resp.StatusCode,
		"sibling UA on same IP must not inherit soft_block (composite key isolates discriminators)")
}

func (s *E2ESuite) Test07_Captcha_ZZ_Metrics() {
	// Hit captcha once with a fresh UA so the test is self-contained even when
	// previous test ordering changes (escalation test may have already moved
	// captcha counter forward but metric value is what we assert).
	req, _ := http.NewRequest(http.MethodGet, dataURL+"/", nil)
	req.Header.Set("User-Agent", "E2ECaptchaMetrics/1.0")
	resp, err := http.DefaultClient.Do(req)
	s.Require().NoError(err)
	resp.Body.Close()

	body := s.getMetrics()
	s.Contains(body, `wafsrv_decision_total{action="captcha"`,
		"decision metric must expose captcha action label")
}

// --- 03b: Throttle response shape ---

// Test03_RateLimit_ThrottleHeader extends Test03_RateLimit_PerMethod by asserting
// the X-WAF-Action: throttle header introduced alongside the captcha→403 migration.
// Uses pgd.diff (sibling rule, fresh counter) so the assertion does not depend on
// Test03_RateLimit_PerMethod's execution order.
func (s *E2ESuite) Test03_RateLimit_ThrottleHeader() {
	for range 5 {
		resp := s.postRPC(dataURL+"/rpc/", "pgd.diff", "{}")
		resp.Body.Close()
	}

	resp := s.postRPC(dataURL+"/rpc/", "pgd.diff", "{}")
	defer resp.Body.Close()

	s.Equal(http.StatusTooManyRequests, resp.StatusCode)
	s.Equal(waf.ActionHeaderThrottle, resp.Header.Get(waf.HeaderAction),
		"429 must set X-WAF-Action: throttle to disambiguate from block/captcha 403")
	s.NotEmpty(resp.Header.Get("Retry-After"),
		"throttle must include Retry-After (RateLimit.RetryAfter, default 60s)")
}

// --- 04b: Block response shape ---

// Test04_IP_Block_HeaderAndRetryAfter extends Test04_IP_BlockAndUnblock by
// asserting the new X-WAF-Action: block header (added when both captcha and
// block returned 403, status alone became ambiguous) and that a TTL'd
// blacklist exposes the remaining duration via Retry-After.
func (s *E2ESuite) Test04_IP_Block_HeaderAndRetryAfter() {
	clientIP := s.detectClientIP()

	result := s.mgmtRPC("block.add",
		`{"blockType":"ip","value":"`+clientIP+`","reason":"e2e-headers","duration":"30s"}`)
	s.Contains(result, `"result":true`)

	resp := s.get(dataURL + "/")
	defer resp.Body.Close()
	defer s.mgmtRPC("block.remove", `{"blockType":"ip","value":"`+clientIP+`"}`)

	s.Equal(http.StatusForbidden, resp.StatusCode)
	s.Equal(waf.ActionHeaderBlock, resp.Header.Get(waf.HeaderAction),
		"static/runtime block must set X-WAF-Action: block")

	retryAfter := resp.Header.Get("Retry-After")
	s.NotEmpty(retryAfter,
		"TTL'd blacklist entry must surface remaining duration via Retry-After")

	// duration "30s" was just set; allow a couple of seconds of drift
	secs, err := strconv.Atoi(retryAfter)
	s.Require().NoError(err)
	s.Positive(secs)
	s.LessOrEqual(secs, 31)

	// body should be the block error text (RenderBlock isn't used here — ip middleware
	// uses http.Error). Sanity check we didn't somehow render the captcha body.
	body := s.readBody(resp)
	s.NotContains(strings.ToLower(body), "captcha required",
		"block path must not render captcha body")
}
