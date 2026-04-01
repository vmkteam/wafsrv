package event

import "time"

// Recorder combines event Buffer, time Series, and Tops tracking.
// All methods are nil-safe on both receiver and underlying fields.
type Recorder struct {
	buf           *Buffer
	ser           *Series
	tops          *Tops
	targetLatency *LatencyTracker
	methodLatency *LatencyTracker
	targetErrors  *ErrorTracker
}

// NewRecorder creates a new Recorder wrapping the given components.
func NewRecorder(buf *Buffer, ser *Series, tops *Tops) *Recorder {
	return &Recorder{
		buf:           buf,
		ser:           ser,
		tops:          tops,
		targetLatency: NewLatencyTracker(),
		methodLatency: NewLatencyTracker(),
		targetErrors:  NewErrorTracker(),
	}
}

// Series returns the underlying time series (for adaptive engine).
func (r *Recorder) Series() *Series {
	if r == nil {
		return nil
	}

	return r.ser
}

// --- write: events ---

// AddEvent adds a security event to the circular buffer.
func (r *Recorder) AddEvent(e Event) {
	if r != nil && r.buf != nil {
		r.buf.Add(e)
	}
}

// --- write: series ---

// RecordIncoming records an incoming request before any blocking middleware.
func (r *Recorder) RecordIncoming() {
	if r != nil && r.ser != nil {
		r.ser.RecordIncoming()
	}
}

// RecordRequest records a proxied request that reached the backend.
func (r *Recorder) RecordRequest(is5xx bool) {
	if r != nil && r.ser != nil {
		r.ser.RecordRequest(is5xx)
	}
}

// RecordLatency records a response latency.
func (r *Recorder) RecordLatency(d time.Duration) {
	if r != nil && r.ser != nil {
		r.ser.RecordLatency(d)
	}
}

// RecordBlocked records an IP/country block to series and tops.
func (r *Recorder) RecordBlocked(ip, path, country, platform string) {
	if r == nil {
		return
	}

	if r.ser != nil {
		r.ser.RecordBlocked()
	}

	if r.tops != nil {
		r.tops.RecordBlocked(ip, path, country, platform)
	}
}

// RecordFiltered records a traffic filter match.
func (r *Recorder) RecordFiltered() {
	if r != nil && r.ser != nil {
		r.ser.RecordFiltered()
	}
}

// RecordRateLimited records a rate-limited request to series and tops.
func (r *Recorder) RecordRateLimited(ip, path, platform string) {
	if r == nil {
		return
	}

	if r.ser != nil {
		r.ser.RecordRateLimited()
	}

	if r.tops != nil {
		r.tops.RecordBlocked(ip, path, "", platform)
	}
}

// RecordCaptcha records a captcha decision.
func (r *Recorder) RecordCaptcha() {
	if r != nil && r.ser != nil {
		r.ser.RecordCaptcha()
	}
}

// RecordCaptchaPass records a successful captcha verification.
func (r *Recorder) RecordCaptchaPass() {
	if r != nil && r.ser != nil {
		r.ser.RecordCaptchaPass()
	}
}

// RecordSignInvalid records an invalid signing attempt.
func (r *Recorder) RecordSignInvalid() {
	if r != nil && r.ser != nil {
		r.ser.RecordSignInvalid()
	}
}

// RecordWAFRule records a WAF rule match to tops.
func (r *Recorder) RecordWAFRule(ruleID string) {
	if r != nil && r.tops != nil {
		r.tops.RecordWAFRule(ruleID)
	}
}

// RecordBotVerified records a verified bot to tops.
func (r *Recorder) RecordBotVerified(botName string) {
	if r != nil && r.tops != nil {
		r.tops.RecordBotVerified(botName)
	}
}

// RecordBotFake records a fake bot to tops.
func (r *Recorder) RecordBotFake() {
	if r != nil && r.tops != nil {
		r.tops.RecordBotFake()
	}
}

// RecordUA records a user agent to tops.
func (r *Recorder) RecordUA(ua string) {
	if r != nil && r.tops != nil {
		r.tops.RecordUA(ua)
	}
}

// RecordReferer records a referer to tops.
func (r *Recorder) RecordReferer(ref string) {
	if r != nil && r.tops != nil {
		r.tops.RecordReferer(ref)
	}
}

// RecordRPCMethod records an RPC method to tops.
func (r *Recorder) RecordRPCMethod(method string) {
	if r != nil && r.tops != nil {
		r.tops.RecordRPCMethod(method)
	}
}

// RecordASN records an ASN organization to tops.
func (r *Recorder) RecordASN(asnOrg string) {
	if r != nil && r.tops != nil {
		r.tops.RecordASN(asnOrg)
	}
}

// RecordSignResult records a signing result to tops.
func (r *Recorder) RecordSignResult(result string) {
	if r != nil && r.tops != nil {
		r.tops.RecordSignResult(result)
	}
}

// RecordDecision records a decision action to tops.
func (r *Recorder) RecordDecision(action string) {
	if r != nil && r.tops != nil {
		r.tops.RecordDecision(action)
	}
}

// RecordBytesSent records response bytes to series.
func (r *Recorder) RecordBytesSent(n int) {
	if r != nil && r.ser != nil {
		r.ser.RecordBytesSent(n)
	}
}

// RecordTops records a request to tops (blocked or normal based on status).
func (r *Recorder) RecordTops(ip, path, country, platform string, blocked bool) {
	if r == nil || r.tops == nil {
		return
	}

	if blocked {
		r.tops.RecordBlocked(ip, path, country, platform)
	} else {
		r.tops.Record(ip, path, country, platform)
	}
}

// TopPlatforms returns top-N platforms sorted by total desc.
func (r *Recorder) TopPlatforms(n int) []TopEntry {
	if r != nil && r.tops != nil {
		return r.tops.TopPlatforms(n)
	}

	return nil
}

// --- write: per-key latency ---

// RecordTargetLatency records a latency sample for a backend target.
func (r *Recorder) RecordTargetLatency(target string, d time.Duration) {
	if r != nil && r.targetLatency != nil {
		r.targetLatency.Record(target, d)
	}
}

// RecordTargetResult records a request result for per-target error tracking.
func (r *Recorder) RecordTargetResult(target string, is5xx bool) {
	if r != nil && r.targetErrors != nil {
		r.targetErrors.Record(target, is5xx)
	}
}

// RecordMethodLatency records a latency sample for an RPC method.
func (r *Recorder) RecordMethodLatency(method string, d time.Duration) {
	if r != nil && r.methodLatency != nil {
		r.methodLatency.Record(method, d)
	}
}

// --- read: dashboard ---

// RecentEvents returns the last n events, newest first.
func (r *Recorder) RecentEvents(n int) []Event {
	if r != nil && r.buf != nil {
		return r.buf.Recent(n)
	}

	return nil
}

// History returns the last n time series points, oldest first.
func (r *Recorder) History(n int) []Point {
	if r != nil && r.ser != nil {
		return r.ser.History(n)
	}

	return nil
}

// RPS returns the current requests per second.
func (r *Recorder) RPS() float64 {
	if r != nil && r.ser != nil {
		return r.ser.RPS()
	}

	return 0
}

// TopIPs returns top-N IPs sorted by total desc.
func (r *Recorder) TopIPs(n int) []TopEntry {
	if r != nil && r.tops != nil {
		return r.tops.TopIPs(n)
	}

	return nil
}

// TopPaths returns top-N paths sorted by total desc.
func (r *Recorder) TopPaths(n int) []TopEntry {
	if r != nil && r.tops != nil {
		return r.tops.TopPaths(n)
	}

	return nil
}

// TopCountries returns top-N countries sorted by total desc.
func (r *Recorder) TopCountries(n int) []TopEntry {
	if r != nil && r.tops != nil {
		return r.tops.TopCountries(n)
	}

	return nil
}

// TopBlockedIPs returns top-N IPs sorted by blocked desc.
func (r *Recorder) TopBlockedIPs(n int) []TopEntry {
	if r != nil && r.tops != nil {
		return r.tops.TopBlockedIPs(n)
	}

	return nil
}

// TopUserAgents returns top-N user agents sorted by total desc.
func (r *Recorder) TopUserAgents(n int) []TopEntry {
	if r != nil && r.tops != nil {
		return r.tops.TopUserAgents(n)
	}

	return nil
}

// TopReferers returns top-N referers sorted by total desc.
func (r *Recorder) TopReferers(n int) []TopEntry {
	if r != nil && r.tops != nil {
		return r.tops.TopReferers(n)
	}

	return nil
}

// TopRPCMethods returns top-N RPC methods sorted by total desc.
func (r *Recorder) TopRPCMethods(n int) []TopEntry {
	if r != nil && r.tops != nil {
		return r.tops.TopRPCMethods(n)
	}

	return nil
}

// TopASNs returns top-N ASN organizations sorted by total desc.
func (r *Recorder) TopASNs(n int) []TopEntry {
	if r != nil && r.tops != nil {
		return r.tops.TopASNs(n)
	}

	return nil
}

// TopSignResults returns top-N sign results sorted by total desc.
func (r *Recorder) TopSignResults(n int) []TopEntry {
	if r != nil && r.tops != nil {
		return r.tops.TopSignResults(n)
	}

	return nil
}

// TopDecisions returns top-N decisions sorted by total desc.
func (r *Recorder) TopDecisions(n int) []TopEntry {
	if r != nil && r.tops != nil {
		return r.tops.TopDecisions(n)
	}

	return nil
}

// TopWAFRules returns top-N WAF rules sorted by total desc.
func (r *Recorder) TopWAFRules(n int) []TopEntry {
	if r != nil && r.tops != nil {
		return r.tops.TopWAFRules(n)
	}

	return nil
}

// TopBots returns verified bot counts sorted by total desc.
func (r *Recorder) TopBots(n int) []TopEntry {
	if r != nil && r.tops != nil {
		return r.tops.TopBots(n)
	}

	return nil
}

// FakeBotCount returns current fake bot count.
func (r *Recorder) FakeBotCount() int64 {
	if r != nil && r.tops != nil {
		return r.tops.FakeBotCount()
	}

	return 0
}

// TargetLatencies returns latency stats per backend target.
func (r *Recorder) TargetLatencies() []LatencyEntry {
	if r != nil && r.targetLatency != nil {
		return r.targetLatency.Snapshot()
	}

	return nil
}

// TargetErrors returns per-target error statistics.
func (r *Recorder) TargetErrors() []ErrorEntry {
	if r != nil && r.targetErrors != nil {
		return r.targetErrors.Snapshot()
	}

	return nil
}

// MethodLatencies returns latency stats per RPC method.
func (r *Recorder) MethodLatencies() []LatencyEntry {
	if r != nil && r.methodLatency != nil {
		return r.methodLatency.Snapshot()
	}

	return nil
}
