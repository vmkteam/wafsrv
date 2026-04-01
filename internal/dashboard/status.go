package dashboard

import (
	"context"
	"time"

	"wafsrv/internal/waf/proxy"

	"github.com/vmkteam/zenrpc/v2"
)

// StatusInfo holds static service info for status responses.
type StatusInfo struct {
	Service          string
	Targets          []string
	Listen           string
	WAFEnabled       bool
	WAFMode          string
	WAFParanoiaLevel int
	RateLimitEnabled bool
	RateLimitPerIP   string
	RateLimitRules   []RuleInfo
	BotVerifyEnabled bool
	StartedAt        time.Time
}

// RuleInfo describes a rate limit rule.
type RuleInfo struct {
	Name     string   `json:"name"`
	Endpoint string   `json:"endpoint,omitempty"`
	Match    []string `json:"match"`
	Limit    string   `json:"limit"`
	Action   string   `json:"action"`
}

// StatusService provides service status information.
type StatusService struct {
	zenrpc.Service
	info  StatusInfo
	proxy *proxy.Proxy
}

// NewStatusService creates a new StatusService.
func NewStatusService(info StatusInfo, p *proxy.Proxy) *StatusService {
	return &StatusService{info: info, proxy: p}
}

// StatusResponse is the response for status.get.
type StatusResponse struct {
	Service          string             `json:"service"`
	Targets          []string           `json:"targets"`
	Listen           string             `json:"listen"`
	UptimeSeconds    int64              `json:"uptimeSeconds"`
	WAFEnabled       bool               `json:"wafEnabled"`
	WAFMode          string             `json:"wafMode"`
	WAFParanoiaLevel int                `json:"wafParanoiaLevel,omitempty"`
	RateLimitEnabled bool               `json:"rateLimitEnabled"`
	RateLimitPerIP   string             `json:"rateLimitPerIP,omitempty"`
	BotVerifyEnabled bool               `json:"botVerifyEnabled"`
	ProxyStatus      *proxy.ProxyStatus `json:"proxyStatus,omitempty"`
}

// Get returns the current service status.
//
//zenrpc:return StatusResponse
func (s StatusService) Get(_ context.Context) StatusResponse {
	resp := StatusResponse{
		Service:          s.info.Service,
		Targets:          s.info.Targets,
		Listen:           s.info.Listen,
		UptimeSeconds:    int64(time.Since(s.info.StartedAt).Seconds()),
		WAFEnabled:       s.info.WAFEnabled,
		WAFMode:          s.info.WAFMode,
		WAFParanoiaLevel: s.info.WAFParanoiaLevel,
		RateLimitEnabled: s.info.RateLimitEnabled,
		RateLimitPerIP:   s.info.RateLimitPerIP,
		BotVerifyEnabled: s.info.BotVerifyEnabled,
	}

	if s.proxy != nil {
		ps := s.proxy.Status()
		resp.ProxyStatus = &ps
	}

	return resp
}

// Rules returns the current rate limit rules.
//
//zenrpc:return []RuleInfo
func (s StatusService) Rules(_ context.Context) []RuleInfo {
	return s.info.RateLimitRules
}
