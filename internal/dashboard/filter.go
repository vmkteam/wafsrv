package dashboard

import (
	"wafsrv/internal/waf/filter"

	"github.com/vmkteam/zenrpc/v2"
)

// FilterService provides traffic filter management via JSON-RPC.
type FilterService struct {
	zenrpc.Service
	filter *filter.TrafficFilter
}

// NewFilterService creates a new FilterService.
func NewFilterService(f *filter.TrafficFilter) *FilterService {
	return &FilterService{filter: f}
}

// FilterRuleParams defines a traffic filter rule for add/test.
type FilterRuleParams struct {
	Name       string   `json:"name"`
	Action     string   `json:"action"` // "block" | "captcha" | "log"
	IP         []string `json:"ip,omitempty"`
	UAExact    []string `json:"uaExact,omitempty"`
	UAPrefix   []string `json:"uaPrefix,omitempty"`
	UAExclude  []string `json:"uaExclude,omitempty"`
	Country    []string `json:"country,omitempty"`
	Platform   []string `json:"platform,omitempty"`
	Version    []string `json:"version,omitempty"`
	Host       []string `json:"host,omitempty"`
	Path       []string `json:"path,omitempty"`
	Method     []string `json:"method,omitempty"`
	UAContains []string `json:"uaContains,omitempty"`
	ASN        []uint32 `json:"asn,omitempty"`
	RPCMethod  []string `json:"rpcMethod,omitempty"`
	Referer    []string `json:"referer,omitempty"`
}

// FilterRuleInfo is a rule with source annotation.
type FilterRuleInfo struct {
	FilterRuleParams
	Source string `json:"source"` // "config" | "api"
}

// Add adds a dynamic traffic filter rule. //zenrpc
func (s FilterService) Add(rule FilterRuleParams) (string, error) {
	if s.filter == nil {
		return "", ErrBadRequest
	}

	err := s.filter.AddRule(filter.TrafficRule{
		Name: rule.Name, Action: rule.Action,
		IP: rule.IP, UAExact: rule.UAExact, UAPrefix: rule.UAPrefix, UAExclude: rule.UAExclude,
		Country: rule.Country, Platform: rule.Platform, Version: rule.Version,
		Host: rule.Host, Path: rule.Path, Method: rule.Method,
		UAContains: rule.UAContains, ASN: rule.ASN, RPCMethod: rule.RPCMethod, Referer: rule.Referer,
	})
	if err != nil {
		return "", ErrBadRequest
	}

	return "ok", nil
}

// Remove removes a dynamic traffic filter rule by name. //zenrpc
func (s FilterService) Remove(name string) (string, error) {
	if s.filter == nil {
		return "", ErrBadRequest
	}

	if err := s.filter.RemoveRule(name); err != nil {
		return "", ErrNotFound
	}

	return "ok", nil
}

// List returns all traffic filter rules (static + dynamic). //zenrpc
func (s FilterService) List() []FilterRuleInfo {
	if s.filter == nil {
		return nil
	}

	rules := s.filter.ListRules()
	result := make([]FilterRuleInfo, len(rules))

	for i, r := range rules {
		result[i] = FilterRuleInfo{
			FilterRuleParams: FilterRuleParams{
				Name: r.Name, Action: r.Action,
				IP: r.IP, UAExact: r.UAExact, UAPrefix: r.UAPrefix, UAExclude: r.UAExclude,
				Country: r.Country, Platform: r.Platform, Version: r.Version,
				Host: r.Host, Path: r.Path, Method: r.Method,
				UAContains: r.UAContains, ASN: r.ASN, RPCMethod: r.RPCMethod, Referer: r.Referer,
			},
			Source: r.Source,
		}
	}

	return result
}
