package sign

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"wafsrv/internal/waf"
	"wafsrv/internal/waf/storage"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/vmkteam/embedlog"
)

const (
	headerName = "X-Waf-Sign"
	version    = "v1"
)

// Config holds signing verification configuration.
type Config struct {
	Mode       string // "detection" | "blocking"
	TTL        time.Duration
	NonceCache int
	Web        PlatformSecret
	Android    PlatformSecret
	IOS        PlatformSecret
	Methods    []MethodRule
}

// PlatformSecret holds per-platform signing secret.
type PlatformSecret struct {
	Enabled    bool
	Secret     string
	MinVersion string
	NotifyOnly bool
}

// MethodRule defines which RPC methods require field signing.
type MethodRule struct {
	Name       string
	Endpoint   string // JSONRPC.Endpoints[].Name, "" = all
	Methods    []string
	Platforms  []string
	SignFields []string // top-level param keys
}

// Metrics holds signing prometheus metrics.
type Metrics struct {
	Total    *prometheus.CounterVec // labels: platform, result
	Recorder interface {
		RecordSignInvalid()
		RecordSignResult(result string)
	}
}

// VerifyResult is the outcome of a signing verification.
type VerifyResult struct {
	Valid       bool
	FieldSigned bool   // true if SignFields were included in signature
	TrafficType string // platform, "unsigned", "invalid", "expired", "replay"
	Score       float64
	Reason      string
}

// Verifier performs request signing verification.
type Verifier struct {
	embedlog.Logger
	cfg       Config
	store     storage.KVStore
	methodIdx map[string][]*MethodRule // lowercase method → rules
	metrics   Metrics
}

// New creates a new signing verifier.
func New(cfg Config, store storage.KVStore, sl embedlog.Logger, metrics Metrics) *Verifier {
	v := &Verifier{
		Logger:  sl,
		cfg:     cfg,
		store:   store,
		metrics: metrics,
	}

	v.methodIdx = v.buildMethodIndex()

	return v
}

func (v *Verifier) buildMethodIndex() map[string][]*MethodRule {
	idx := make(map[string][]*MethodRule)

	for i := range v.cfg.Methods {
		rule := &v.cfg.Methods[i]
		for _, m := range rule.Methods {
			key := strings.ToLower(m)
			idx[key] = append(idx[key], rule)
		}
	}

	return idx
}

// Middleware returns an HTTP middleware that verifies request signatures.
func (v *Verifier) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rc := waf.FromContext(r.Context())
			if rc == nil || rc.Static || (rc.IP != nil && rc.IP.Whitelisted) {
				next.ServeHTTP(w, r)
				return
			}

			result := v.Verify(r, rc)
			rc.TrafficType = result.TrafficType

			platform := rc.Platform
			if platform == "" {
				platform = "unknown"
			}

			v.recordResult(result)

			switch {
			case result.Valid:
				v.metrics.Total.WithLabelValues(platform, "valid").Inc()

				if result.FieldSigned {
					rc.SignedLevel = 2 // full trust: skip rate limit + captcha
				} else {
					rc.SignedLevel = 1 // fingerprint only: score bonus
					rc.WAFScore -= 2   // reduce score for signed requests
					if rc.WAFScore < 0 {
						rc.WAFScore = 0
					}
				}
			case result.TrafficType == "unsigned":
				v.metrics.Total.WithLabelValues(platform, "unsigned").Inc()
			default:
				v.metrics.Total.WithLabelValues(platform, result.TrafficType).Inc()
				rc.WAFScore += result.Score

				if v.metrics.Recorder != nil {
					v.metrics.Recorder.RecordSignInvalid()
				}

				args := []any{"reason", result.Reason, "trafficType", result.TrafficType, "score", result.Score} //nolint:prealloc
				for _, a := range waf.SecurityAttrs(r) {
					args = append(args, a.Key, a.Value.Any())
				}

				v.Print(r.Context(), "sign_"+result.TrafficType, args...)
			}

			if v.cfg.Mode == "blocking" && result.Score > 0 {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func (v *Verifier) recordResult(result VerifyResult) {
	if v.metrics.Recorder != nil {
		v.metrics.Recorder.RecordSignResult(result.TrafficType)
	}
}

// Verify checks the X-Waf-Sign header.
func (v *Verifier) Verify(r *http.Request, rc *waf.RequestContext) VerifyResult {
	header := r.Header.Get(headerName)
	if header == "" {
		return VerifyResult{TrafficType: "unsigned"}
	}

	// parse "v1.<ts>.<nonce>.<sig>"
	parts := strings.SplitN(header, ".", 4)
	if len(parts) != 4 || parts[0] != version {
		return VerifyResult{Score: 3, TrafficType: "invalid", Reason: "bad format"}
	}

	ts, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return VerifyResult{Score: 3, TrafficType: "invalid", Reason: "bad timestamp"}
	}

	nonce := parts[2]
	sig := parts[3]

	// timestamp check
	age := time.Since(time.Unix(ts, 0))
	if age < 0 {
		age = -age
	}

	if age > v.cfg.TTL {
		return VerifyResult{Score: 3, TrafficType: "expired", Reason: fmt.Sprintf("age=%s", age.Truncate(time.Second))}
	}

	// nonce dedup
	if exists, _ := v.store.Exists("nonce:" + nonce); exists {
		return VerifyResult{Score: 5, TrafficType: "replay", Reason: "nonce=" + nonce}
	}

	_ = v.store.Set("nonce:"+nonce, []byte("1"), v.cfg.TTL)

	// check platform enabled
	if !v.platformEnabled(rc.Platform) {
		return VerifyResult{Valid: true, TrafficType: rc.Platform}
	}

	// verify HMAC
	tok := v.token(rc.ClientIP.String(), r.UserAgent(), rc.Platform)
	canonical := v.buildCanonical(parts[0], parts[1], nonce, r, rc)
	expected := hmacSHA256hex(tok, canonical)

	if !hmac.Equal([]byte(sig), []byte(expected)) {
		return VerifyResult{Score: 5, TrafficType: "invalid", Reason: "signature mismatch"}
	}

	// check if SignFields were included
	fieldSigned := false
	if rc.RPC != nil && !rc.RPC.IsBatch && len(rc.RPC.Methods) == 1 {
		if rule := v.findRule(rc.RPC.Methods[0], rc.RPC.Endpoint); rule != nil && len(rule.SignFields) > 0 {
			fieldSigned = true
		}
	}

	return VerifyResult{Valid: true, FieldSigned: fieldSigned, TrafficType: rc.Platform}
}

func (v *Verifier) token(ip, ua, platform string) []byte {
	p := classifyPlatform(platform)

	switch p {
	case platformClassWeb:
		mac := hmac.New(sha256.New, []byte(v.cfg.Web.Secret))
		mac.Write([]byte(ip + "\n" + ua))
		return mac.Sum(nil)[:32]
	case platformClassAndroid:
		return []byte(v.cfg.Android.Secret)
	case platformClassIOS:
		return []byte(v.cfg.IOS.Secret)
	}

	// unknown platform — use web secret
	if v.cfg.Web.Secret != "" {
		mac := hmac.New(sha256.New, []byte(v.cfg.Web.Secret))
		mac.Write([]byte(ip + "\n" + ua))
		return mac.Sum(nil)[:32]
	}

	return nil
}

func (v *Verifier) buildCanonical(ver, ts, nonce string, r *http.Request, rc *waf.RequestContext) string {
	var b strings.Builder

	b.WriteString(ver)
	b.WriteByte('\n')
	b.WriteString(ts)
	b.WriteByte('\n')
	b.WriteString(nonce)
	b.WriteByte('\n')
	b.WriteString(r.Method)
	b.WriteByte('\n')
	b.WriteString(r.URL.RequestURI())
	b.WriteByte('\n')
	b.WriteString(r.UserAgent())
	b.WriteByte('\n')
	b.WriteString(rc.Platform)
	b.WriteByte('\n')
	b.WriteString(rc.Version)

	if rc.RPC != nil {
		methods := sortedCopy(rc.RPC.Methods)
		b.WriteByte('\n')
		b.WriteString(strings.Join(methods, ","))

		// sign fields (single RPC only, not batch)
		if !rc.RPC.IsBatch && len(rc.RPC.Methods) == 1 {
			if rule := v.findRule(rc.RPC.Methods[0], rc.RPC.Endpoint); rule != nil && len(rule.SignFields) > 0 {
				fields := extractFields(rc.RPC.Body, rule.SignFields)
				for _, f := range fields {
					b.WriteByte('\n')
					b.WriteString(f)
				}
			}
		}
	}

	return b.String()
}

func (v *Verifier) findRule(method, endpoint string) *MethodRule {
	rules := v.methodIdx[strings.ToLower(method)]
	for _, r := range rules {
		if r.Endpoint == "" || strings.EqualFold(r.Endpoint, endpoint) {
			return r
		}
	}

	return nil
}

func (v *Verifier) platformEnabled(platform string) bool {
	p := classifyPlatform(platform)

	switch p {
	case platformClassWeb:
		return v.cfg.Web.Enabled
	case platformClassAndroid:
		return v.cfg.Android.Enabled
	case platformClassIOS:
		return v.cfg.IOS.Enabled
	}

	return v.cfg.Web.Enabled // unknown → web
}

// --- field extraction ---

func extractFields(body []byte, signFields []string) []string {
	if len(body) == 0 || len(signFields) == 0 {
		return nil
	}

	var req struct {
		Params json.RawMessage `json:"params"`
	}

	if err := json.Unmarshal(body, &req); err != nil {
		return nil
	}

	var params map[string]any
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil
	}

	sorted := make([]string, len(signFields))
	copy(sorted, signFields)
	sort.Strings(sorted)

	fields := make([]string, 0, len(sorted))

	for _, key := range sorted {
		val := findParamCI(params, key)
		if val == nil {
			continue
		}

		fields = append(fields, key+"="+formatValue(val))
	}

	return fields
}

func findParamCI(params map[string]any, key string) any {
	// exact match first
	if v, ok := params[key]; ok {
		return v
	}

	// case-insensitive
	for k, v := range params {
		if strings.EqualFold(k, key) {
			return v
		}
	}

	return nil
}

func formatValue(v any) string {
	switch val := v.(type) {
	case string:
		return val
	case float64:
		if val == math.Trunc(val) {
			return strconv.FormatInt(int64(val), 10)
		}

		return strconv.FormatFloat(val, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(val)
	case []any:
		parts := make([]string, len(val))
		for i, item := range val {
			parts[i] = formatValue(item)
		}

		sort.Strings(parts)

		return strings.Join(parts, ",")
	default:
		return fmt.Sprint(val)
	}
}

// --- helpers ---

func hmacSHA256hex(key []byte, data string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))

	return hex.EncodeToString(mac.Sum(nil))
}

const (
	platformClassWeb     = "web"
	platformClassAndroid = "android"
	platformClassIOS     = "ios"
)

// classifyPlatform maps a lowercase platform name to a signing class (web/android/ios).
func classifyPlatform(platform string) string {
	switch platform {
	case "desktop", "mobile", "widget", "web":
		return platformClassWeb
	case platformClassAndroid:
		return platformClassAndroid
	case platformClassIOS:
		return platformClassIOS
	}

	return platformClassWeb
}

func sortedCopy(s []string) []string {
	c := make([]string, len(s))
	copy(c, s)
	sort.Strings(c)

	return c
}
