package event

import (
	"sort"
	"sync"
	"time"
)

// TopEntry represents a key with total and blocked counts.
type TopEntry struct {
	Key     string `json:"key"`
	Total   int64  `json:"total"`
	Blocked int64  `json:"blocked"`
}

type topCounter struct {
	total   int64
	blocked int64
}

// Tops tracks top-N IPs, paths, countries, platforms, WAF rules, bots, user agents, referers,
// RPC methods, ASNs, sign results, and decisions in a rolling time window.
type Tops struct {
	mu          sync.Mutex
	ips         map[string]*topCounter
	paths       map[string]*topCounter
	countries   map[string]*topCounter
	platforms   map[string]*topCounter
	wafRules    map[string]*topCounter
	bots        map[string]*topCounter
	userAgents  map[string]*topCounter
	referers    map[string]*topCounter
	rpcMethods  map[string]*topCounter
	asns        map[string]*topCounter
	signResults map[string]*topCounter
	decisions   map[string]*topCounter
	fakeBots    int64
	lastReset   time.Time
	window      time.Duration
	maxKeys     int
}

// NewTops creates a new top-N tracker.
// window defines the rolling window duration (e.g. 5 min).
func NewTops(window time.Duration, maxKeys int) *Tops {
	if maxKeys <= 0 {
		maxKeys = 10000
	}

	return &Tops{
		ips:         make(map[string]*topCounter),
		paths:       make(map[string]*topCounter),
		countries:   make(map[string]*topCounter),
		platforms:   make(map[string]*topCounter),
		wafRules:    make(map[string]*topCounter),
		bots:        make(map[string]*topCounter),
		userAgents:  make(map[string]*topCounter),
		referers:    make(map[string]*topCounter),
		rpcMethods:  make(map[string]*topCounter),
		asns:        make(map[string]*topCounter),
		signResults: make(map[string]*topCounter),
		decisions:   make(map[string]*topCounter),
		lastReset:   time.Now(),
		window:      window,
		maxKeys:     maxKeys,
	}
}

// Record records a request for IP, path, country, and platform.
func (t *Tops) Record(ip, path, country, platform string) {
	t.mu.Lock()
	t.resetIfExpired()
	t.inc(t.ips, ip, false)
	t.inc(t.paths, path, false)
	t.inc(t.countries, country, false)
	t.inc(t.platforms, platform, false)
	t.mu.Unlock()
}

// RecordBlocked records a blocked request.
func (t *Tops) RecordBlocked(ip, path, country, platform string) {
	t.mu.Lock()
	t.resetIfExpired()
	t.inc(t.ips, ip, true)
	t.inc(t.paths, path, true)
	t.inc(t.countries, country, true)
	t.inc(t.platforms, platform, true)
	t.mu.Unlock()
}

// TopPlatforms returns top-N platforms sorted by total desc.
func (t *Tops) TopPlatforms(n int) []TopEntry {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.resetIfExpired()

	return topN(t.platforms, n)
}

// TopIPs returns top-N IPs sorted by total desc.
func (t *Tops) TopIPs(n int) []TopEntry {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.resetIfExpired()

	return topN(t.ips, n)
}

// TopPaths returns top-N paths sorted by total desc.
func (t *Tops) TopPaths(n int) []TopEntry {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.resetIfExpired()

	return topN(t.paths, n)
}

// RecordWAFRule records a WAF rule match.
func (t *Tops) RecordWAFRule(ruleID string) {
	t.mu.Lock()
	t.resetIfExpired()
	t.inc(t.wafRules, ruleID, false)
	t.mu.Unlock()
}

// RecordBotVerified records a verified bot.
func (t *Tops) RecordBotVerified(botName string) {
	t.mu.Lock()
	t.resetIfExpired()
	t.inc(t.bots, botName, false)
	t.mu.Unlock()
}

// RecordBotFake records a fake bot.
func (t *Tops) RecordBotFake() {
	t.mu.Lock()
	t.resetIfExpired()
	t.fakeBots++
	t.mu.Unlock()
}

// TopWAFRules returns top-N WAF rules sorted by total desc.
func (t *Tops) TopWAFRules(n int) []TopEntry {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.resetIfExpired()

	return topN(t.wafRules, n)
}

// TopBots returns verified bot counts sorted by total desc.
func (t *Tops) TopBots(n int) []TopEntry {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.resetIfExpired()

	return topN(t.bots, n)
}

// FakeBotCount returns current fake bot count.
func (t *Tops) FakeBotCount() int64 {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.resetIfExpired()

	return t.fakeBots
}

// RecordUA records a user agent string.
func (t *Tops) RecordUA(ua string) {
	t.mu.Lock()
	t.resetIfExpired()
	t.inc(t.userAgents, ua, false)
	t.mu.Unlock()
}

// RecordReferer records a referer.
func (t *Tops) RecordReferer(ref string) {
	t.mu.Lock()
	t.resetIfExpired()
	t.inc(t.referers, ref, false)
	t.mu.Unlock()
}

// RecordRPCMethod records an RPC method call.
func (t *Tops) RecordRPCMethod(method string) {
	t.mu.Lock()
	t.resetIfExpired()
	t.inc(t.rpcMethods, method, false)
	t.mu.Unlock()
}

// RecordASN records an ASN organization.
func (t *Tops) RecordASN(asnOrg string) {
	t.mu.Lock()
	t.resetIfExpired()
	t.inc(t.asns, asnOrg, false)
	t.mu.Unlock()
}

// RecordSignResult records a signing verification result.
func (t *Tops) RecordSignResult(result string) {
	t.mu.Lock()
	t.resetIfExpired()
	t.inc(t.signResults, result, false)
	t.mu.Unlock()
}

// RecordDecision records a decision action.
func (t *Tops) RecordDecision(action string) {
	t.mu.Lock()
	t.resetIfExpired()
	t.inc(t.decisions, action, false)
	t.mu.Unlock()
}

// TopBlockedIPs returns top-N IPs sorted by blocked desc.
func (t *Tops) TopBlockedIPs(n int) []TopEntry {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.resetIfExpired()

	return topNByBlocked(t.ips, n)
}

// TopUserAgents returns top-N user agents sorted by total desc.
func (t *Tops) TopUserAgents(n int) []TopEntry {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.resetIfExpired()

	return topN(t.userAgents, n)
}

// TopReferers returns top-N referers sorted by total desc.
func (t *Tops) TopReferers(n int) []TopEntry {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.resetIfExpired()

	return topN(t.referers, n)
}

// TopRPCMethods returns top-N RPC methods sorted by total desc.
func (t *Tops) TopRPCMethods(n int) []TopEntry {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.resetIfExpired()

	return topN(t.rpcMethods, n)
}

// TopASNs returns top-N ASN organizations sorted by total desc.
func (t *Tops) TopASNs(n int) []TopEntry {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.resetIfExpired()

	return topN(t.asns, n)
}

// TopSignResults returns top-N sign results sorted by total desc.
func (t *Tops) TopSignResults(n int) []TopEntry {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.resetIfExpired()

	return topN(t.signResults, n)
}

// TopDecisions returns top-N decisions sorted by total desc.
func (t *Tops) TopDecisions(n int) []TopEntry {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.resetIfExpired()

	return topN(t.decisions, n)
}

// TopCountries returns top-N countries sorted by total desc.
func (t *Tops) TopCountries(n int) []TopEntry {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.resetIfExpired()

	return topN(t.countries, n)
}

func (t *Tops) resetIfExpired() {
	if time.Since(t.lastReset) < t.window {
		return
	}

	t.ips = make(map[string]*topCounter)
	t.paths = make(map[string]*topCounter)
	t.countries = make(map[string]*topCounter)
	t.platforms = make(map[string]*topCounter)
	t.wafRules = make(map[string]*topCounter)
	t.bots = make(map[string]*topCounter)
	t.userAgents = make(map[string]*topCounter)
	t.referers = make(map[string]*topCounter)
	t.rpcMethods = make(map[string]*topCounter)
	t.asns = make(map[string]*topCounter)
	t.signResults = make(map[string]*topCounter)
	t.decisions = make(map[string]*topCounter)
	t.fakeBots = 0
	t.lastReset = time.Now()
}

func (t *Tops) inc(m map[string]*topCounter, key string, isBlocked bool) {
	if key == "" {
		return
	}

	c, ok := m[key]
	if !ok {
		if len(m) >= t.maxKeys {
			return // cap reached, skip new keys
		}

		c = &topCounter{}
		m[key] = c
	}

	c.total++

	if isBlocked {
		c.blocked++
	}
}

func topNByBlocked(m map[string]*topCounter, n int) []TopEntry {
	entries := make([]TopEntry, 0, len(m))
	for k, v := range m {
		if v.blocked > 0 {
			entries = append(entries, TopEntry{Key: k, Total: v.total, Blocked: v.blocked})
		}
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Blocked > entries[j].Blocked
	})

	if n > 0 && n < len(entries) {
		entries = entries[:n]
	}

	return entries
}

func topN(m map[string]*topCounter, n int) []TopEntry {
	entries := make([]TopEntry, 0, len(m))
	for k, v := range m {
		entries = append(entries, TopEntry{Key: k, Total: v.total, Blocked: v.blocked})
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Total > entries[j].Total
	})

	if n > 0 && n < len(entries) {
		entries = entries[:n]
	}

	return entries
}
