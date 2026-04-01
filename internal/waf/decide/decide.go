package decide

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"wafsrv/internal/waf"
	"wafsrv/internal/waf/alerting"
	"wafsrv/internal/waf/challenge"
	"wafsrv/internal/waf/event"
	"wafsrv/internal/waf/storage"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/vmkteam/embedlog"
)

// Config holds decision engine configuration.
type Config struct {
	CaptchaThreshold     float64
	BlockThreshold       float64
	CaptchaStatusCode    int
	BlockStatusCode      int
	CaptchaToBlock       int
	CaptchaToBlockWindow time.Duration
	SoftBlockDuration    time.Duration
	CaptchaProvider      string // "turnstile" | "hcaptcha" | "pow"
	CaptchaSiteKey       string
	CaptchaSecretKey     string
	CaptchaCookieName    string
	CaptchaFallback      waf.Action       // fallback action for unsupported platforms
	Platforms            []PlatformConfig // per-platform captcha policy
	Branding             challenge.Branding
}

// PlatformConfig defines captcha support for a specific platform.
type PlatformConfig struct {
	Platform   string
	Captcha    bool
	MinVersion [3]int     // parsed semver; [0,0,0] = no minimum
	Fallback   waf.Action // resolved fallback (never zero)
}

// Metrics holds decision engine prometheus metrics.
type Metrics struct {
	DecisionTotal *prometheus.CounterVec
	Recorder      *event.Recorder
	PlatformSet   map[string]struct{}
}

// Engine evaluates request score and decides pass/captcha/block.
type Engine struct {
	cfg         Config
	cache       *challenge.Cache
	verifier    *challenge.Verifier
	powVerifier *challenge.PowVerifier
	store       storage.KVStore
	alerter     alerting.Sender
	embedlog.Logger
	metrics Metrics
}

type scoreEntry struct {
	CaptchaCount int       `json:"c"`
	FirstCaptcha time.Time `json:"f"`
	BlockedUntil time.Time `json:"b"`
}

// New creates a new decision engine.
func New(cfg Config, store storage.KVStore, cache *challenge.Cache, verifier *challenge.Verifier, powVerifier *challenge.PowVerifier, alerter alerting.Sender, sl embedlog.Logger, metrics Metrics) *Engine {
	return &Engine{
		cfg:         cfg,
		store:       store,
		cache:       cache,
		verifier:    verifier,
		powVerifier: powVerifier,
		alerter:     alerter,
		Logger:      sl,
		metrics:     metrics,
	}
}

// Middleware returns an HTTP middleware that applies decisions based on score.
func (e *Engine) Middleware() func(http.Handler) http.Handler { //nolint:gocognit
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rc := waf.FromContext(r.Context())
			if rc == nil || rc.Static || rc.SignedLevel >= 2 || (rc.IP != nil && rc.IP.Whitelisted) {
				next.ServeHTTP(w, r)
				return
			}

			// check captcha pass: HMAC cookie or IP cache (fast path — no eKey needed)
			if e.cache != nil && e.cache.IsValid(r, rc.ClientIP) {
				rc.Decision = waf.ActionPass
				next.ServeHTTP(w, r)
				return
			}

			eKey := escalationKey(rc.ClientIP, rc.Discriminator)

			// try verifying captcha token from cookie (PoW or Turnstile/hCaptcha)
			if e.cache != nil && e.verifyCaptchaCookie(r, w, rc.ClientIP, eKey) {
				rc.Decision = waf.ActionPass
				next.ServeHTTP(w, r)
				return
			}

			// check soft block (per discriminator — NAT-aware)
			if e.isSoftBlocked(eKey) {
				rc.Decision = waf.ActionSoftBlock
				e.metrics.DecisionTotal.WithLabelValues("soft_block", e.metricPlatform(rc.Platform)).Inc()
				e.metrics.Recorder.RecordDecision("soft_block")
				e.addEvent(r.Context(), rc.ClientIP.String(), r.URL.Path, "soft_block")
				e.metrics.Recorder.RecordBlocked(rc.ClientIP.String(), r.URL.Path, "", rc.Platform)
				challenge.RenderBlock(w, e.cfg.BlockStatusCode, rc.RequestID, e.cfg.Branding)

				return
			}

			score := rc.WAFScore

			// no thresholds configured — pass through
			if e.cfg.BlockThreshold == 0 && e.cfg.CaptchaThreshold == 0 {
				rc.Decision = waf.ActionPass
				e.metrics.DecisionTotal.WithLabelValues("pass", e.metricPlatform(rc.Platform)).Inc()
				e.metrics.Recorder.RecordDecision("pass")
				next.ServeHTTP(w, r)
				return
			}

			// block
			if e.cfg.BlockThreshold > 0 && score >= e.cfg.BlockThreshold {
				rc.Decision = waf.ActionBlock
				e.metrics.DecisionTotal.WithLabelValues("block", e.metricPlatform(rc.Platform)).Inc()
				e.metrics.Recorder.RecordDecision("block")
				e.addEvent(r.Context(), rc.ClientIP.String(), r.URL.Path, "block")
				e.metrics.Recorder.RecordBlocked(rc.ClientIP.String(), r.URL.Path, "", rc.Platform)
				e.sendAlert(r.Context(), rc, alerting.EventHardBlock, fmt.Sprintf("score %.0f >= %.0f", score, e.cfg.BlockThreshold))
				challenge.RenderBlock(w, e.cfg.BlockStatusCode, rc.RequestID, e.cfg.Branding)

				return
			}

			// captcha
			if e.cfg.CaptchaThreshold > 0 && score >= e.cfg.CaptchaThreshold { //nolint:nestif
				ok, fallback := e.checkPlatformCaptcha(rc.Platform, rc.Version)
				if ok {
					rc.Decision = waf.ActionCaptcha
					e.metrics.DecisionTotal.WithLabelValues("captcha", e.metricPlatform(rc.Platform)).Inc()
					e.metrics.Recorder.RecordDecision("captcha")
					e.recordCaptcha(r.Context(), eKey)
					e.addEvent(r.Context(), rc.ClientIP.String(), r.URL.Path, "captcha")

					switch {
					case e.powVerifier != nil:
						ch := e.powVerifier.GenerateChallenge(rc.ClientIP.String(), r.UserAgent())
						challenge.RenderPowCaptcha(w, e.cfg.CaptchaStatusCode, ch, e.cfg.CaptchaCookieName, rc.RequestID, e.powVerifier.Timeout(), e.cfg.Branding)
					case e.cfg.CaptchaSiteKey != "":
						challenge.RenderCaptcha(w, e.cfg.CaptchaStatusCode, e.cfg.CaptchaProvider, e.cfg.CaptchaSiteKey, e.cfg.CaptchaCookieName, rc.RequestID, e.cfg.Branding)
					default:
						http.Error(w, "Captcha required", e.cfg.CaptchaStatusCode)
					}

					return
				}

				// platform doesn't support captcha — apply fallback
				e.applyCaptchaFallback(w, r, rc, next, fallback)

				return
			}

			rc.Decision = waf.ActionPass
			e.metrics.DecisionTotal.WithLabelValues("pass", e.metricPlatform(rc.Platform)).Inc()
			e.metrics.Recorder.RecordDecision("pass")
			next.ServeHTTP(w, r)
		})
	}
}

func (e *Engine) isSoftBlocked(key string) bool {
	data, exists, err := e.store.Get("esc:" + key)
	if err != nil || !exists {
		return false
	}

	var entry scoreEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return false
	}

	if !entry.BlockedUntil.IsZero() && time.Now().Before(entry.BlockedUntil) {
		return true
	}

	// clear expired block
	if !entry.BlockedUntil.IsZero() {
		_ = e.store.Delete("esc:" + key)
	}

	return false
}

// verifyCaptchaCookie checks if the captcha cookie contains a valid token
// (PoW solution or Turnstile/hCaptcha token) and replaces with HMAC pass cookie.
func (e *Engine) verifyCaptchaCookie(r *http.Request, w http.ResponseWriter, clientIP netip.Addr, eKey string) bool {
	cookie, err := r.Cookie(e.cfg.CaptchaCookieName)
	if err != nil || cookie.Value == "" {
		return false
	}

	// try PoW verification first (local, fast)
	if e.powVerifier != nil {
		payload, decErr := challenge.DecodePowPayload(cookie.Value)
		if decErr == nil && e.powVerifier.VerifySolution(payload, clientIP.String(), r.UserAgent()) {
			e.acceptCaptchaPass(r.Context(), w, clientIP, eKey, "pow_pass")
			return true
		}

		return false
	}

	// Turnstile/hCaptcha verification (HTTP call)
	if e.verifier == nil || e.cfg.CaptchaSecretKey == "" {
		return false
	}

	ok, verifyErr := e.verifier.Verify(r.Context(), cookie.Value, clientIP.String(), e.cfg.CaptchaSecretKey)
	if verifyErr != nil {
		e.Print(r.Context(), "captcha_verify_error", "clientIp", clientIP.String(), "error", verifyErr.Error())

		return false
	}

	if !ok {
		return false
	}

	e.acceptCaptchaPass(r.Context(), w, clientIP, eKey, "captcha_pass")

	return true
}

// acceptCaptchaPass handles the common success path for all captcha providers.
func (e *Engine) acceptCaptchaPass(ctx context.Context, w http.ResponseWriter, clientIP netip.Addr, eKey, logAction string) {
	e.cache.SetCookie(w)
	e.cache.AddIP(clientIP)
	e.clearCaptchaCount(eKey)

	e.Print(ctx, logAction, "clientIp", clientIP.String())

	e.metrics.Recorder.RecordCaptchaPass()
}

func (e *Engine) clearCaptchaCount(key string) {
	_ = e.store.Delete("esc:" + key)
}

func (e *Engine) addEvent(ctx context.Context, clientIP, path, action string) {
	e.Print(ctx, "decision", "clientIp", clientIP, "action", action)

	e.metrics.Recorder.AddEvent(event.Event{
		Type:     "decision",
		ClientIP: clientIP,
		Path:     path,
		Detail:   action,
	})

	if action == "captcha" {
		e.metrics.Recorder.RecordCaptcha()
	}
}

func (e *Engine) recordCaptcha(ctx context.Context, key string) {
	storeKey := "esc:" + key

	var entry scoreEntry

	data, exists, _ := e.store.Get(storeKey)
	if exists {
		_ = json.Unmarshal(data, &entry)
	}

	now := time.Now()

	// reset window if expired
	if !entry.FirstCaptcha.IsZero() && now.Sub(entry.FirstCaptcha) > e.cfg.CaptchaToBlockWindow {
		entry.CaptchaCount = 0
		entry.FirstCaptcha = time.Time{}
	}

	if entry.CaptchaCount == 0 {
		entry.FirstCaptcha = now
	}

	entry.CaptchaCount++

	ttl := e.cfg.CaptchaToBlockWindow

	// escalate to soft block
	if entry.CaptchaCount >= e.cfg.CaptchaToBlock {
		entry.BlockedUntil = now.Add(e.cfg.SoftBlockDuration)
		ttl = e.cfg.SoftBlockDuration

		e.Print(ctx, "escalation", "key", key, "captchaCount", entry.CaptchaCount, "blockedUntil", entry.BlockedUntil.Format(time.RFC3339))

		if e.alerter != nil {
			e.alerter.Send(ctx, alerting.Event{
				Type:    alerting.EventSoftBlock,
				Message: fmt.Sprintf("escalation: %d captcha failures -> soft block %s", entry.CaptchaCount, e.cfg.SoftBlockDuration),
				IP:      key,
			})
		}
	}

	if data, err := json.Marshal(entry); err == nil {
		_ = e.store.Set(storeKey, data, ttl)
	}
}

func (e *Engine) metricPlatform(platform string) string {
	if platform == "" {
		return ""
	}

	if _, ok := e.metrics.PlatformSet[platform]; ok {
		return platform
	}

	return "other"
}

// escalationKey returns composite key for captcha escalation and soft block.
func escalationKey(ip netip.Addr, discriminator string) string {
	return ip.String() + ":" + discriminator
}

// checkPlatformCaptcha checks if the platform+version supports captcha rendering.
// Returns (true, 0) if captcha is supported, or (false, fallbackAction) otherwise.
// When no platforms are configured, returns true for backward compatibility.
// Empty platform means browser (SSR) or suspicious RPC client — both can render captcha.
func (e *Engine) checkPlatformCaptcha(platform, version string) (bool, waf.Action) {
	if len(e.cfg.Platforms) == 0 {
		return true, 0
	}

	if platform == "" {
		return true, 0 // browser or missing header → captcha-capable
	}

	pc := e.findPlatform(platform)
	if pc == nil {
		return false, e.cfg.CaptchaFallback // unknown platform → global fallback
	}

	if !pc.Captcha {
		return false, pc.Fallback
	}

	if pc.MinVersion != [3]int{} {
		if version == "" {
			return false, pc.Fallback // no version header → can't confirm support
		}

		if compareSemver(ParseSemver(version), pc.MinVersion) < 0 {
			return false, pc.Fallback
		}
	}

	return true, 0
}

func (e *Engine) findPlatform(platform string) *PlatformConfig {
	for i := range e.cfg.Platforms {
		if e.cfg.Platforms[i].Platform == platform {
			return &e.cfg.Platforms[i]
		}
	}

	return nil
}

// applyCaptchaFallback applies the fallback action when captcha is not supported by the platform.
func (e *Engine) applyCaptchaFallback(w http.ResponseWriter, r *http.Request, rc *waf.RequestContext, next http.Handler, fallback waf.Action) {
	mp := e.metricPlatform(rc.Platform)

	switch fallback { //nolint:exhaustive // only block/log/pass are valid fallback actions
	case waf.ActionBlock:
		rc.Decision = waf.ActionBlock
		e.metrics.DecisionTotal.WithLabelValues("captcha_fallback_block", mp).Inc()
		e.metrics.Recorder.RecordDecision("captcha_fallback_block")
		e.addEvent(r.Context(), rc.ClientIP.String(), r.URL.Path, "captcha_fallback_block")
		e.sendAlert(r.Context(), rc, alerting.EventHardBlock, "captcha fallback block (platform: "+rc.Platform+")")
		challenge.RenderBlock(w, e.cfg.BlockStatusCode, rc.RequestID, e.cfg.Branding)
	case waf.ActionLog:
		rc.Decision = waf.ActionLog
		e.metrics.DecisionTotal.WithLabelValues("captcha_fallback_log", mp).Inc()
		e.metrics.Recorder.RecordDecision("captcha_fallback_log")
		e.addEvent(r.Context(), rc.ClientIP.String(), r.URL.Path, "captcha_fallback_log")
		next.ServeHTTP(w, r)
	default: // waf.ActionPass
		rc.Decision = waf.ActionPass
		e.metrics.DecisionTotal.WithLabelValues("captcha_fallback_pass", mp).Inc()
		e.metrics.Recorder.RecordDecision("captcha_fallback_pass")
		next.ServeHTTP(w, r)
	}
}

func (e *Engine) sendAlert(ctx context.Context, rc *waf.RequestContext, eventType, detail string) {
	if e.alerter == nil {
		return
	}

	ev := alerting.Event{
		Type:      eventType,
		Message:   detail,
		IP:        rc.ClientIP.String(),
		Score:     rc.WAFScore,
		RequestID: rc.RequestID,
	}

	if rc.IP != nil {
		ev.Country = rc.IP.Country
		if rc.IP.ASN > 0 {
			ev.ASN = rc.IP.ASNOrg
		}
	}

	e.alerter.Send(ctx, ev)
}

// ParseSemver parses "major.minor.patch" into [3]int. Returns [0,0,0] on error.
func ParseSemver(s string) [3]int {
	var v [3]int
	if s == "" {
		return v
	}

	parts := strings.SplitN(s, ".", 3)
	for i := 0; i < len(parts) && i < 3; i++ {
		n, err := strconv.Atoi(parts[i])
		if err != nil {
			return [3]int{}
		}

		v[i] = n
	}

	return v
}

// compareSemver returns -1 if a < b, 0 if a == b, 1 if a > b.
func compareSemver(a, b [3]int) int {
	for i := range 3 {
		if a[i] < b[i] {
			return -1
		}

		if a[i] > b[i] {
			return 1
		}
	}

	return 0
}
