package filter

import (
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"sync"

	"wafsrv/internal/waf"
	"wafsrv/internal/waf/event"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/vmkteam/embedlog"
)

const trafficFilterScore = 5.0

// TrafficRule defines a static traffic filter rule with AND-semantics.
type TrafficRule struct {
	Name       string   // rule identifier
	Action     string   // "block" | "captcha" | "log"
	IP         []string // exact IP or CIDR
	UAExact    []string // exact User-Agent match
	UAPrefix   []string // User-Agent prefix match
	UAExclude  []string // skip rule if UA matches
	Country    []string // ISO 3166-1 country code
	Platform   []string // request header Platform
	Version    []string // request header Version
	Host       []string // HTTP Host header
	Path       []string // URL path prefix
	Method     []string // HTTP method (GET, POST)
	UAContains []string // User-Agent substring match
	ASN        []uint32 // Autonomous System Number
	RPCMethod  []string // JSON-RPC method prefix match (e.g. "admin." or "auth.login")
	Referer    []string // Referer header prefix match

	nFields    int            // precomputed filledFields count (set by init)
	parsedIPs  []netip.Addr   // pre-parsed exact IPs
	parsedNets []netip.Prefix // pre-parsed CIDRs
}

// Init precomputes fields count and parses IP/CIDR values. Must be called after construction.
func (r *TrafficRule) Init() {
	r.nFields = r.countFields()
	r.parseIPs()
}

func (r *TrafficRule) parseIPs() {
	for _, s := range r.IP {
		if prefix, err := netip.ParsePrefix(s); err == nil {
			r.parsedNets = append(r.parsedNets, prefix)
		} else if addr, err := netip.ParseAddr(s); err == nil {
			r.parsedIPs = append(r.parsedIPs, addr)
		}
	}
}

// RuleInfo is a TrafficRule with source annotation.
type RuleInfo struct {
	TrafficRule
	Source string // "config" | "api"
}

// RuleMatch describes a matched rule for test results.
type RuleMatch struct {
	Name   string `json:"name"`
	Action string `json:"action"`
	Source string `json:"source"`
}

// Metrics holds traffic filter prometheus metrics.
type Metrics struct {
	MatchedTotal *prometheus.CounterVec // labels: rule, action
	Recorder     *event.Recorder
}

// MatchRequest holds extracted request fields for rule matching.
type MatchRequest struct {
	IP         string
	UA         string
	Country    string
	Platform   string
	Version    string
	Host       string
	Path       string
	Method     string
	ASN        uint32
	RPCMethods []string
	Referer    string
}

// TrafficFilter evaluates static and dynamic rules against requests.
type TrafficFilter struct {
	mu           sync.RWMutex
	staticRules  []TrafficRule
	dynamicRules []TrafficRule
	embedlog.Logger
	metrics Metrics
}

// New creates a new TrafficFilter with static rules from config.
func New(rules []TrafficRule, sl embedlog.Logger, metrics Metrics) *TrafficFilter {
	for i := range rules {
		rules[i].Init()
	}

	return &TrafficFilter{
		staticRules: rules,
		Logger:      sl,
		metrics:     metrics,
	}
}

// AddRule adds a dynamic rule. Returns error if name is empty or duplicate.
func (f *TrafficFilter) AddRule(rule TrafficRule) error {
	if rule.Name == "" {
		return errEmptyName
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	for _, r := range f.dynamicRules {
		if r.Name == rule.Name {
			return errDuplicateName
		}
	}

	rule.Init()
	f.dynamicRules = append(f.dynamicRules, rule)

	return nil
}

// RemoveRule removes a dynamic rule by name.
func (f *TrafficFilter) RemoveRule(name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	for i, r := range f.dynamicRules {
		if r.Name == name {
			f.dynamicRules = append(f.dynamicRules[:i], f.dynamicRules[i+1:]...)
			return nil
		}
	}

	return errNotFound
}

// ListRules returns all rules (static + dynamic) with source annotation.
func (f *TrafficFilter) ListRules() []RuleInfo {
	f.mu.RLock()
	defer f.mu.RUnlock()

	result := make([]RuleInfo, 0, len(f.staticRules)+len(f.dynamicRules))

	for _, r := range f.staticRules {
		result = append(result, RuleInfo{TrafficRule: r, Source: "config"})
	}

	for _, r := range f.dynamicRules {
		result = append(result, RuleInfo{TrafficRule: r, Source: "api"})
	}

	return result
}

// TestRequest checks which rules would fire for given params.
func (f *TrafficFilter) TestRequest(req MatchRequest) []RuleMatch {
	f.mu.RLock()
	defer f.mu.RUnlock()

	var matches []RuleMatch

	for _, r := range f.staticRules {
		if r.isActive(req) {
			matches = append(matches, RuleMatch{Name: r.Name, Action: r.Action, Source: "config"})
		}
	}

	for _, r := range f.dynamicRules {
		if r.isActive(req) {
			matches = append(matches, RuleMatch{Name: r.Name, Action: r.Action, Source: "api"})
		}
	}

	return matches
}

// Middleware returns an HTTP middleware that evaluates traffic rules.
func (f *TrafficFilter) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rc := waf.FromContext(r.Context())
			if rc == nil || rc.Static || (rc.IP != nil && rc.IP.Whitelisted) {
				next.ServeHTTP(w, r)
				return
			}

			req := MatchRequest{
				IP:       rc.ClientIP.String(),
				UA:       r.UserAgent(),
				Platform: r.Header.Get("Platform"),
				Version:  r.Header.Get("Version"),
				Host:     r.Host,
				Path:     r.URL.Path,
				Method:   r.Method,
			}

			if rc.IP != nil {
				req.Country = rc.IP.Country
				req.ASN = rc.IP.ASN
			}

			if rc.RPC != nil {
				req.RPCMethods = rc.RPC.Methods
			}

			req.Referer = r.Referer()

			if f.evalRules(r, rc, req, f.staticRules) {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			f.mu.RLock()
			dynamic := f.dynamicRules
			f.mu.RUnlock()

			if f.evalRules(r, rc, req, dynamic) {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// evalRules evaluates rules, returns true if a block action fired.
func (f *TrafficFilter) evalRules(r *http.Request, rc *waf.RequestContext, req MatchRequest, rules []TrafficRule) bool {
	for _, rule := range rules {
		if !rule.isActive(req) {
			continue
		}

		f.metrics.MatchedTotal.WithLabelValues(rule.Name, rule.Action).Inc()

		switch rule.Action {
		case "block":
			f.logMatch(r, rc, rule)

			return true
		case "captcha":
			rc.WAFScore += trafficFilterScore
			f.logMatch(r, rc, rule)
		case "log":
			f.Print(r.Context(), "traffic_filter",
				"rule", rule.Name,
				"action", "log",
				"clientIp", rc.ClientIP.String(),
			)
		}
	}

	return false
}

func (f *TrafficFilter) logMatch(r *http.Request, rc *waf.RequestContext, rule TrafficRule) {
	f.Print(r.Context(), "traffic_filter",
		"rule", rule.Name,
		"action", rule.Action,
		"clientIp", rc.ClientIP.String(),
		"userAgent", r.UserAgent(),
	)

	f.metrics.Recorder.AddEvent(event.Event{
		Type:     "traffic_filter",
		ClientIP: rc.ClientIP.String(),
		Path:     r.URL.Path,
		Detail:   rule.Name + ":" + rule.Action,
	})
	f.metrics.Recorder.RecordFiltered()
}

// --- rule matching (AND-semantics) ---

func (r *TrafficRule) isActive(req MatchRequest) bool {
	n := r.nFields
	if n == 0 {
		r.Init()
		n = r.nFields
		if n == 0 {
			return false
		}
	}

	// exclude check first
	for _, ua := range r.UAExclude {
		if ua == req.UA {
			return false
		}
	}

	return r.matchAllFields(req)
}

func (r *TrafficRule) countFields() int {
	return b2i(len(r.IP) > 0) +
		b2i(len(r.UAExact) > 0) +
		b2i(len(r.UAPrefix) > 0) +
		b2i(len(r.Country) > 0) +
		b2i(len(r.Platform) > 0) +
		b2i(len(r.Version) > 0) +
		b2i(len(r.Host) > 0) +
		b2i(len(r.Path) > 0) +
		b2i(len(r.Method) > 0) +
		b2i(len(r.UAContains) > 0) +
		b2i(len(r.ASN) > 0) +
		b2i(len(r.RPCMethod) > 0) +
		b2i(len(r.Referer) > 0)
}

// matchAllFields checks all non-empty conditions with short-circuit on first miss.
func (r *TrafficRule) matchAllFields(req MatchRequest) bool {
	return (len(r.IP) == 0 || r.matchIP(req.IP)) &&
		(len(r.UAExact) == 0 || r.matchUAExact(req.UA)) &&
		(len(r.UAPrefix) == 0 || r.matchUAPrefix(req.UA)) &&
		(len(r.Country) == 0 || r.matchList(r.Country, req.Country)) &&
		(len(r.Platform) == 0 || r.matchList(r.Platform, req.Platform)) &&
		(len(r.Version) == 0 || r.matchList(r.Version, req.Version)) &&
		(len(r.Host) == 0 || r.matchList(r.Host, req.Host)) &&
		(len(r.Path) == 0 || r.matchPath(req.Path)) &&
		(len(r.Method) == 0 || r.matchList(r.Method, req.Method)) &&
		(len(r.UAContains) == 0 || r.matchUAContains(req.UA)) &&
		(len(r.ASN) == 0 || r.matchASN(req.ASN)) &&
		(len(r.RPCMethod) == 0 || r.matchRPCMethod(req.RPCMethods)) &&
		(len(r.Referer) == 0 || r.matchReferer(req.Referer))
}

func (r *TrafficRule) matchIP(ipStr string) bool {
	if len(r.parsedIPs) == 0 && len(r.parsedNets) == 0 {
		return false
	}

	parsed, err := netip.ParseAddr(ipStr)
	if err != nil {
		return false
	}

	for _, addr := range r.parsedIPs {
		if addr == parsed {
			return true
		}
	}

	for _, prefix := range r.parsedNets {
		if prefix.Contains(parsed) {
			return true
		}
	}

	return false
}

func (r *TrafficRule) matchUAExact(ua string) bool {
	if len(r.UAExact) == 0 {
		return false
	}

	for _, v := range r.UAExact {
		if v == ua {
			return true
		}
	}

	return false
}

func (r *TrafficRule) matchUAPrefix(ua string) bool {
	if len(r.UAPrefix) == 0 {
		return false
	}

	for _, v := range r.UAPrefix {
		if strings.HasPrefix(ua, v) {
			return true
		}
	}

	return false
}

func (r *TrafficRule) matchPath(path string) bool {
	return matchPrefix(r.Path, path)
}

func (r *TrafficRule) matchList(list []string, value string) bool {
	if len(list) == 0 {
		return false
	}

	for _, v := range list {
		if v == value {
			return true
		}
	}

	return false
}

func (r *TrafficRule) matchUAContains(ua string) bool {
	if len(r.UAContains) == 0 {
		return false
	}

	for _, v := range r.UAContains {
		if strings.Contains(ua, v) {
			return true
		}
	}

	return false
}

func (r *TrafficRule) matchASN(asn uint32) bool {
	if len(r.ASN) == 0 {
		return false
	}

	for _, v := range r.ASN {
		if v == asn {
			return true
		}
	}

	return false
}

func (r *TrafficRule) matchRPCMethod(methods []string) bool {
	if len(r.RPCMethod) == 0 {
		return false
	}

	for _, pattern := range r.RPCMethod {
		for _, m := range methods {
			if m == pattern || strings.HasPrefix(m, pattern) {
				return true
			}
		}
	}

	return false
}

func (r *TrafficRule) matchReferer(referer string) bool {
	return matchPrefix(r.Referer, referer)
}

func matchPrefix(list []string, value string) bool {
	if len(list) == 0 {
		return false
	}

	for _, v := range list {
		if strings.HasPrefix(value, v) {
			return true
		}
	}

	return false
}

func b2i(b bool) int {
	if b {
		return 1
	}

	return 0
}

var (
	errEmptyName     = errors.New("filter: rule name is required")
	errDuplicateName = errors.New("filter: rule with this name already exists")
	errNotFound      = errors.New("filter: rule not found")
)
