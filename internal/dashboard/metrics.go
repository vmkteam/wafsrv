package dashboard

import (
	"context"
	"net/netip"

	"wafsrv/internal/waf/event"
	"wafsrv/internal/waf/ip"

	"github.com/vmkteam/zenrpc/v2"
)

// IPTopEntry is a top IP entry enriched with GeoIP data.
type IPTopEntry struct {
	IP      string `json:"ip"`
	Total   int64  `json:"total"`
	Blocked int64  `json:"blocked"`
	Country string `json:"country,omitempty"`
	ASNOrg  string `json:"asnOrg,omitempty"`
}

// TopsResult holds top-N results for IPs, paths, countries, platforms, WAF rules, bots, and more.
type TopsResult struct {
	IPs         []IPTopEntry     `json:"ips"`
	BlockedIPs  []IPTopEntry     `json:"blockedIps"`
	Paths       []event.TopEntry `json:"paths"`
	Countries   []event.TopEntry `json:"countries"`
	Platforms   []event.TopEntry `json:"platforms"`
	WAFRules    []event.TopEntry `json:"wafRules"`
	Bots        []event.TopEntry `json:"bots"`
	FakeBots    int64            `json:"fakeBots"`
	UserAgents  []event.TopEntry `json:"userAgents"`
	Referers    []event.TopEntry `json:"referers"`
	RPCMethods  []event.TopEntry `json:"rpcMethods"`
	ASNs        []event.TopEntry `json:"asns"`
	SignResults []event.TopEntry `json:"signResults"`
	Decisions   []event.TopEntry `json:"decisions"`
}

// MetricsService provides time series metrics.
type MetricsService struct {
	zenrpc.Service
	recorder  *event.Recorder
	ipService *ip.Service
}

// NewMetricsService creates a new MetricsService.
func NewMetricsService(recorder *event.Recorder, ipService *ip.Service) *MetricsService {
	return &MetricsService{recorder: recorder, ipService: ipService}
}

// History returns time series data points for the last N minutes.
//
//zenrpc:minutes=5 Number of minutes of history (max 30)
//zenrpc:return []event.Point
func (s MetricsService) History(_ context.Context, minutes int) []event.Point {
	if minutes <= 0 || minutes > 30 {
		minutes = 5
	}

	// 5-second intervals → 12 points per minute
	n := minutes * 12

	return s.recorder.History(n)
}

// RPS returns the current requests per second.
//
//zenrpc:return float64
func (s MetricsService) RPS(_ context.Context) float64 {
	return s.recorder.RPS()
}

// Tops returns top-N IPs, paths, and countries for the current window.
//
//zenrpc:n=10 Number of top entries
//zenrpc:return TopsResult
func (s MetricsService) Tops(_ context.Context, n int) TopsResult {
	if n <= 0 || n > 100 {
		n = 10
	}

	return TopsResult{
		IPs:         s.enrichIPs(s.recorder.TopIPs(n)),
		BlockedIPs:  s.enrichIPs(s.recorder.TopBlockedIPs(n)),
		Paths:       s.recorder.TopPaths(n),
		Countries:   s.recorder.TopCountries(n),
		Platforms:   s.recorder.TopPlatforms(n),
		WAFRules:    s.recorder.TopWAFRules(n),
		Bots:        s.recorder.TopBots(n),
		FakeBots:    s.recorder.FakeBotCount(),
		UserAgents:  s.recorder.TopUserAgents(n),
		Referers:    s.recorder.TopReferers(n),
		RPCMethods:  s.recorder.TopRPCMethods(n),
		ASNs:        s.recorder.TopASNs(n),
		SignResults: s.recorder.TopSignResults(n),
		Decisions:   s.recorder.TopDecisions(n),
	}
}

// CaptchaRateResult holds captcha solve rate statistics.
type CaptchaRateResult struct {
	Captcha     int64   `json:"captcha"`
	CaptchaPass int64   `json:"captchaPass"`
	SolveRate   float64 `json:"solveRate"` // CaptchaPass / Captcha * 100
}

// CaptchaRate returns captcha solve rate for the last N minutes.
//
//zenrpc:minutes=5 Number of minutes of history (max 30)
//zenrpc:return CaptchaRateResult
func (s MetricsService) CaptchaRate(_ context.Context, minutes int) CaptchaRateResult {
	if minutes <= 0 || minutes > 30 {
		minutes = 5
	}

	n := minutes * 12
	points := s.recorder.History(n)

	var result CaptchaRateResult

	for _, p := range points {
		result.Captcha += p.Captcha
		result.CaptchaPass += p.CaptchaPass
	}

	if result.Captcha > 0 {
		result.SolveRate = float64(result.CaptchaPass) / float64(result.Captcha) * 100
	}

	return result
}

// LatenciesResult holds per-target and per-method latency stats.
type LatenciesResult struct {
	Targets      []event.LatencyEntry `json:"targets"`
	Methods      []event.LatencyEntry `json:"methods"`
	TargetErrors []event.ErrorEntry   `json:"targetErrors"`
}

// Latencies returns per-target and per-method latency statistics.
//
//zenrpc:return LatenciesResult
func (s MetricsService) Latencies(_ context.Context) LatenciesResult {
	return LatenciesResult{
		Targets:      s.recorder.TargetLatencies(),
		Methods:      s.recorder.MethodLatencies(),
		TargetErrors: s.recorder.TargetErrors(),
	}
}

func (s MetricsService) enrichIPs(entries []event.TopEntry) []IPTopEntry {
	result := make([]IPTopEntry, len(entries))

	for i, e := range entries {
		result[i] = IPTopEntry{
			IP:      e.Key,
			Total:   e.Total,
			Blocked: e.Blocked,
		}

		if s.ipService != nil {
			if addr, err := netip.ParseAddr(e.Key); err == nil {
				info := s.ipService.LookupIP(addr)
				result[i].Country = info.Country
				result[i].ASNOrg = info.ASNOrg
			}
		}
	}

	return result
}
