package engine

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"

	"wafsrv/internal/waf"
	"wafsrv/internal/waf/event"

	"github.com/corazawaf/coraza-coreruleset"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/vmkteam/embedlog"
)

const modeBlocking = "blocking"

// Config holds WAF engine configuration.
type Config struct {
	Mode          string // "detection" | "blocking"
	ParanoiaLevel int    // 1-4
}

// Metrics holds WAF prometheus metrics.
type Metrics struct {
	BlockedTotal *prometheus.CounterVec // labels: rule_id
	Recorder     *event.Recorder
}

const maxBodySize = 1 << 20 // 1MB limit for WAF body inspection

var bodyBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, maxBodySize)
		return &b
	},
}

// Engine wraps Coraza WAF.
type Engine struct {
	embedlog.Logger
	waf     coraza.WAF
	mode    string
	metrics Metrics
}

// New creates a new WAF engine with OWASP CRS.
func New(cfg Config, sl embedlog.Logger, metrics Metrics) (*Engine, error) {
	wafCfg := coraza.NewWAFConfig().
		WithRootFS(coreruleset.FS).
		WithDirectives(`Include @coraza.conf-recommended`).
		WithDirectives(fmt.Sprintf("SecRuleEngine %s", ruleEngine(cfg.Mode))).
		WithDirectives(`Include @crs-setup.conf.example`).
		WithDirectives(fmt.Sprintf(`SecAction "id:900000,phase:1,pass,t:none,nolog,setvar:tx.blocking_paranoia_level=%d"`, cfg.ParanoiaLevel)).
		WithDirectives(fmt.Sprintf(`SecAction "id:900001,phase:1,pass,t:none,nolog,setvar:tx.detection_paranoia_level=%d"`, cfg.ParanoiaLevel)).
		// allow application/json for JSON-RPC APIs
		WithDirectives(`SecAction "id:900220,phase:1,pass,t:none,nolog,setvar:'tx.allowed_request_content_type=|application/x-www-form-urlencoded| |multipart/form-data| |multipart/related| |text/xml| |application/xml| |application/soap+xml| |application/json| |application/cloudevents+json| |application/cloudevents-batch+json|'"`).
		WithDirectives(`Include @owasp_crs/*.conf`)

	w, err := coraza.NewWAF(wafCfg)
	if err != nil {
		return nil, fmt.Errorf("engine: %w", err)
	}

	return &Engine{
		Logger:  sl,
		waf:     w,
		mode:    cfg.Mode,
		metrics: metrics,
	}, nil
}

// Middleware returns an HTTP middleware that runs WAF inspection.
func (e *Engine) Middleware() func(http.Handler) http.Handler { //nolint:gocognit
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if rc := waf.FromContext(r.Context()); rc != nil && rc.Static {
				next.ServeHTTP(w, r)
				return
			}

			tx := e.waf.NewTransaction()
			defer func() {
				tx.ProcessLogging()
				_ = tx.Close()
			}()

			// Phase 1: request headers
			tx.ProcessConnection(r.RemoteAddr, 0, "", 0)
			tx.ProcessURI(r.URL.String(), r.Method, r.Proto)

			for k, vv := range r.Header {
				for _, v := range vv {
					tx.AddRequestHeader(k, v)
				}
			}

			if it := tx.ProcessRequestHeaders(); it != nil {
				e.logInterruption(r, it)

				if e.mode == modeBlocking {
					http.Error(w, "Forbidden", it.Status)
					return
				}
			}

			// feed request body to Coraza for inspection
			if r.Body != nil && r.ContentLength != 0 && r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
				bufp, _ := bodyBufPool.Get().(*[]byte)
				buf := (*bufp)[:0]

				n, readErr := io.ReadFull(io.LimitReader(r.Body, maxBodySize), buf[:cap(buf)])
				buf = buf[:n]

				if n > 0 {
					if _, _, err := tx.WriteRequestBody(buf); err == nil {
						// copy data out of pooled buffer before returning it
						body := make([]byte, len(buf))
						copy(body, buf)
						r.Body = io.NopCloser(bytes.NewReader(body))
					}
				} else if readErr != nil && readErr != io.EOF && readErr != io.ErrUnexpectedEOF {
					r.Body = io.NopCloser(bytes.NewReader(nil))
				}

				*bufp = buf[:0]
				bodyBufPool.Put(bufp)
			}

			if it, _ := tx.ProcessRequestBody(); it != nil {
				e.logInterruption(r, it)

				if e.mode == modeBlocking {
					http.Error(w, "Forbidden", it.Status)
					return
				}
			}

			// detection mode: check matched rules for scoring
			if e.mode != modeBlocking {
				e.scoreFromMatchedRules(r, tx)
			}

			next.ServeHTTP(w, r)
		})
	}
}

func (e *Engine) logInterruption(r *http.Request, it *types.Interruption) {
	ruleID := strconv.Itoa(it.RuleID)

	e.metrics.BlockedTotal.WithLabelValues(ruleID).Inc()

	args := []any{ //nolint:prealloc
		"ruleId", it.RuleID,
		"action", it.Action,
		"status", it.Status,
		"mode", e.mode,
		"uri", r.URL.Path,
	}

	for _, a := range waf.SecurityAttrs(r) {
		args = append(args, a.Key, a.Value.Any())
	}

	e.Print(r.Context(), "waf_match", args...)
}

const wafMatchScore = 5.0

func (e *Engine) scoreFromMatchedRules(r *http.Request, tx types.Transaction) {
	matched := tx.MatchedRules()

	if len(matched) == 0 {
		return
	}

	// In detection mode, Coraza marks all rules as non-disruptive.
	// Look for the anomaly score evaluation rule (949110) which means
	// the inbound anomaly score threshold was exceeded.
	hasMatch := false

	for _, mr := range matched {
		ruleID := mr.Rule().ID()

		// 949110 = CRS inbound anomaly score exceeded
		if ruleID == 949110 {
			hasMatch = true
			rid := strconv.Itoa(ruleID)
			e.metrics.BlockedTotal.WithLabelValues(rid).Inc()
			e.recordWAFRule(rid)

			e.logWAFMatch(r, ruleID, mr.Message())

			continue
		}

		// log individual attack rules (9xx1xx series) for observability
		if mr.Message() != "" && ruleID >= 920000 && ruleID < 950000 {
			tags := mr.Rule().Tags()
			if containsAttackTag(tags) {
				rid := strconv.Itoa(ruleID)
				e.metrics.BlockedTotal.WithLabelValues(rid).Inc()
				e.recordWAFRule(rid)
				e.logWAFMatch(r, ruleID, mr.Message())
			}
		}
	}

	if hasMatch {
		if rc := waf.FromContext(r.Context()); rc != nil {
			rc.WAFScore += wafMatchScore
		}
	}
}

func (e *Engine) logWAFMatch(r *http.Request, ruleID int, message string) {
	args := []any{ //nolint:prealloc
		"ruleId", ruleID,
		"message", message,
		"mode", e.mode,
		"uri", r.URL.Path,
	}

	for _, a := range waf.SecurityAttrs(r) {
		args = append(args, a.Key, a.Value.Any())
	}

	e.Print(r.Context(), "waf_match", args...)
}

func (e *Engine) recordWAFRule(ruleID string) {
	e.metrics.Recorder.RecordWAFRule(ruleID)
}

func containsAttackTag(tags []string) bool {
	for _, t := range tags {
		if len(t) > 7 && t[:7] == "attack-" {
			return true
		}
	}

	return false
}

func ruleEngine(mode string) string {
	if mode == modeBlocking {
		return "On"
	}

	return "DetectionOnly"
}
