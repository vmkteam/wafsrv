package app

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"wafsrv/internal/waf/filter"
	"wafsrv/internal/waf/ip"
	"wafsrv/internal/waf/limit"
	"wafsrv/internal/waf/proxy"

	"github.com/BurntSushi/toml"
)

// Config is the top-level configuration.
type Config struct {
	Proxy         ProxyConfig
	Management    ManagementConfig
	JSONRPC       JSONRPCConfig
	WAF           WAFConfig
	RateLimit     RateLimitConfig
	IP            IPConfig
	TrafficFilter TrafficFilterConfig
	Signing       SigningConfig
	Decision      DecisionConfig
	Captcha       CaptchaConfig
	Alerting      AlertingConfig
	Adaptive      AdaptiveConfig
	Storage       StorageConfig
}

const (
	StorageMemory    = "memory"
	StorageAerospike = "aerospike"
)

// StorageConfig configures shared storage backend.
type StorageConfig struct {
	Backend   string // "memory" (default) | "aerospike"
	Aerospike AerospikeStorageConfig
}

// AerospikeStorageConfig holds Aerospike connection settings.
type AerospikeStorageConfig struct {
	Hosts          []string
	Namespace      string
	KeyPrefix      string // optional prefix for all keys (e.g. ServiceName), enables multi-tenant on shared cluster
	ConnectTimeout string // default "5s"
	OperTimeout    string // default "50ms"
}

// AdaptiveConfig configures the adaptive engine.
type AdaptiveConfig struct {
	Enabled        *bool
	Mode           string // "notify" | "auto"
	EvalInterval   string // default "10s"
	WarmupDuration string // default "2m"
	AutoAttack     AutoAttackConfig
}

// AdaptiveEnabled returns whether adaptive engine is enabled.
func (c *AdaptiveConfig) AdaptiveEnabled() bool {
	return c.Enabled != nil && *c.Enabled
}

// AutoAttackConfig holds auto-attack trigger thresholds.
type AutoAttackConfig struct {
	RPSMultiplier         float64 // default 3.0
	RPSRecoveryMultiplier float64 // default 1.5
	MinRPS                float64 // default 10
	ErrorRateThreshold    float64 // default 20
	LatencyThresholdMs    float64 // default 500
	BlockedRateThreshold  float64 // default 50
	Window                string  // default "1m"
	Cooldown              string  // default "5m"
	Duration              string  // default "10m"
}

// SigningConfig configures request signing verification.
type SigningConfig struct {
	Enabled    *bool
	Mode       string // "detection" | "blocking"
	TTL        string // default "5m"
	NonceCache int    // default 100000
	Web        SigningPlatformConfig
	Android    SigningPlatformConfig
	IOS        SigningPlatformConfig
	Methods    []SigningMethodConfig
}

// SigningEnabled returns whether signing is enabled.
func (c *SigningConfig) SigningEnabled() bool {
	return c.Enabled != nil && *c.Enabled
}

// SigningPlatformConfig holds per-platform signing secret.
type SigningPlatformConfig struct {
	Enabled    *bool
	Secret     string
	MinVersion string
	NotifyOnly bool
}

// SigningMethodConfig defines per-method field signing.
type SigningMethodConfig struct {
	Name       string
	Endpoint   string // JSONRPC.Endpoints[].Name, "" = all
	Methods    []string
	Platforms  []string
	SignFields []string
}

// TrafficFilterConfig configures static traffic filter rules.
type TrafficFilterConfig struct {
	Enabled *bool
	Rules   []filter.TrafficRule
}

// TrafficFilterEnabled returns whether traffic filter is enabled.
func (c *TrafficFilterConfig) TrafficFilterEnabled() bool {
	return c.Enabled != nil && *c.Enabled
}

// DecisionConfig configures the decision engine.
type DecisionConfig struct {
	CaptchaThreshold     float64 // default 5
	BlockThreshold       float64 // default 8
	CaptchaStatusCode    int     // default 499
	BlockStatusCode      int     // default 403
	CaptchaToBlock       int     // default 3
	CaptchaToBlockWindow string  // default "10m"
	SoftBlockDuration    string  // default "10m"
	CaptchaFallback      string  // default "block"; "pass" | "block" | "log"
	Platforms            []PlatformCaptchaConfig
}

// PlatformCaptchaConfig configures captcha support per platform.
type PlatformCaptchaConfig struct {
	Platform   string // Platform header value (normalized to lowercase)
	Captcha    bool   // whether platform supports captcha
	MinVersion string // minimum semver version with captcha support
	Fallback   string // override fallback: "pass" | "block" | "log"; empty = Decision.CaptchaFallback
}

// CaptchaConfig configures the CAPTCHA provider.
type CaptchaConfig struct {
	Provider     string // "turnstile" | "hcaptcha" | "pow"
	SiteKey      string
	SecretKey    string
	CookieName   string // default "waf_pass"
	CookieTTL    string // default "30m"
	IPCacheTTL   string // default "30m"
	MaxCacheSize int    // default 50000
	PoW          PowCaptchaConfig
}

// PowCaptchaConfig configures the PoW challenge provider.
type PowCaptchaConfig struct {
	Difficulty       int    // maxNumber for normal mode (default 50000)
	AttackDifficulty int    // maxNumber for Under Attack Mode (default 500000)
	Timeout          string // client-side timeout (default "10s")
	SaltTTL          string // default "5m"
}

// AlertingConfig configures webhook alerting.
type AlertingConfig struct {
	Enabled  *bool
	Webhooks []WebhookConfig
}

// AlertingEnabled returns whether alerting is enabled.
func (c *AlertingConfig) AlertingEnabled() bool {
	if c.Enabled != nil {
		return *c.Enabled
	}

	return false
}

// WebhookConfig defines a webhook endpoint.
type WebhookConfig struct {
	URL         string
	Events      []string
	MinInterval string // default "5m"
}

// WAFConfig configures the Coraza WAF engine.
type WAFConfig struct {
	Enabled       *bool
	Mode          string // "detection" | "blocking"
	ParanoiaLevel int    // 1-4
}

// WAFEnabled returns whether WAF is enabled (default false).
func (c *WAFConfig) WAFEnabled() bool {
	if c.Enabled != nil {
		return *c.Enabled
	}

	return false
}

// RateLimitConfig configures rate limiting.
type RateLimitConfig struct {
	Enabled     *bool
	PerIP       string // "100/min"
	Action      string // "block" | "throttle"
	MaxCounters int    // LRU eviction
	Rules       []RateLimitRule
}

// RateLimitEnabled returns whether rate limiting is enabled (default false).
func (c *RateLimitConfig) RateLimitEnabled() bool {
	if c.Enabled != nil {
		return *c.Enabled
	}

	return false
}

// RateLimitRule defines a per-method rate limit.
type RateLimitRule struct {
	Name     string
	Endpoint string   // JSONRPC.Endpoints[].Name, "" = all
	Match    []string // method names
	Limit    string   // "10/min"
	Action   string   // "block" | "throttle"
}

// IPConfig configures IP intelligence.
type IPConfig struct {
	GeoDatabase string
	ASNDatabase string
	Whitelist   WhitelistConfig
	Blacklist   BlacklistConfig
	Countries   CountriesConfig
	Reputation  ReputationConfig
}

// ReputationConfig configures IP reputation feeds.
type ReputationConfig struct {
	Enabled         *bool
	UpdateInterval  string  // default "1h"
	ScoreAdjustment float64 // default 3.0
	FireHOL         FireHOLConfig
	Tor             TorConfig
	Datacenter      DatacenterConfig
	Feeds           []CustomFeedConfig
}

// ReputationEnabled returns whether reputation feeds are enabled (default false).
func (c *ReputationConfig) ReputationEnabled() bool {
	return c.Enabled != nil && *c.Enabled
}

// FireHOLConfig configures FireHOL IP lists.
type FireHOLConfig struct {
	Enabled *bool // default true (when Reputation.Enabled)
	Level   int   // 1 or 2, default 1
}

// IsEnabled returns whether FireHOL feed is enabled (default true).
func (c *FireHOLConfig) IsEnabled() bool { return c.Enabled == nil || *c.Enabled }

// TorConfig configures Tor exit node handling.
type TorConfig struct {
	Enabled *bool  // default true (when Reputation.Enabled)
	Action  string // "score" | "captcha" | "block", default "score"
}

// IsEnabled returns whether Tor feed is enabled (default true).
func (c *TorConfig) IsEnabled() bool { return c.Enabled == nil || *c.Enabled }

// DatacenterConfig configures datacenter/hosting IP detection via ASN.
type DatacenterConfig struct {
	Enabled         *bool   // default true (when Reputation.Enabled)
	ScoreAdjustment float64 // default 2.0
	ExtraASNs       []uint32
}

// IsEnabled returns whether datacenter detection is enabled (default true).
func (c *DatacenterConfig) IsEnabled() bool { return c.Enabled == nil || *c.Enabled }

// CustomFeedConfig defines an external IP feed URL.
type CustomFeedConfig struct {
	Name   string
	URL    string
	Action string // "score" | "block", default "score"
}

// WhitelistConfig configures IP whitelisting.
type WhitelistConfig struct {
	CIDRs      []string
	VerifyBots *bool
	BotDomains []string
	BotVerify  BotVerifyConfig
}

// BotVerifyConfig configures bot verification parameters.
type BotVerifyConfig struct {
	CacheSize     int
	CacheTTL      string
	DNSTimeout    string
	RangesRefresh string
	FakeBotScore  float64
}

// VerifyBotsEnabled returns whether bot verification is enabled (default true).
func (c *WhitelistConfig) VerifyBotsEnabled() bool {
	if c.VerifyBots != nil {
		return *c.VerifyBots
	}

	return true
}

// BlacklistConfig configures IP blacklisting.
type BlacklistConfig struct {
	CIDRs []string
}

// CountriesConfig configures country-based actions.
type CountriesConfig struct {
	Block   []string // ISO 3166-1 codes → 403
	Captcha []string // ISO 3166-1 codes → captcha via score
	Log     []string // ISO 3166-1 codes → log only, pass
}

// JSONRPCConfig configures JSON-RPC endpoint detection.
type JSONRPCConfig struct {
	Endpoints []JSONRPCEndpoint
}

// JSONRPCEndpoint defines a JSON-RPC endpoint path.
type JSONRPCEndpoint struct {
	Path            string
	Name            string
	SchemaURL       string // URL to fetch schema (SMD/OpenRPC). Relative = Proxy.Targets[0] + path
	SchemaRefresh   string // refresh interval, default "5m"
	MethodWhitelist bool   // block unknown methods
	MaxBatchSize    int    // max batch size, 0 = no limit
}

// ProxyConfig configures the reverse proxy.
type ProxyConfig struct {
	Listen          string
	Targets         []string
	ServiceName     string
	Platforms       []string // known platform names for metrics normalization
	Timeouts        TimeoutsConfig
	Limits          LimitsConfig
	RealIP          RealIPConfig
	CircuitBreaker  CBConfig
	Static          StaticConfig
	TargetDiscovery TargetDiscoveryConfig
}

// TargetDiscoveryConfig configures dynamic backend discovery via DNS SRV.
type TargetDiscoveryConfig struct {
	Enabled         *bool
	Hostname        string // SRV record name (e.g. "apisrv.service.consul")
	Service         string // SRV service field (e.g. "http"), empty = direct lookup
	Proto           string // SRV proto field (e.g. "tcp"), empty = direct lookup
	Scheme          string // URL scheme (default "http")
	DNSServer       string // custom DNS server (e.g. "127.0.0.1:8600")
	RefreshInterval string // default "1s"
	ResolveTimeout  string // default "3s"
}

// TargetDiscoveryEnabled returns whether target discovery is enabled.
func (c *TargetDiscoveryConfig) TargetDiscoveryEnabled() bool {
	return c.Enabled != nil && *c.Enabled
}

// StaticConfig configures static asset bypass.
type StaticConfig struct {
	Paths      []string // path prefixes, e.g. ["/assets/", "/static/"]
	Extensions []string // file extensions with dot, e.g. [".css", ".js", ".png"]
}

// TimeoutsConfig configures HTTP server timeouts.
type TimeoutsConfig struct {
	Read  string
	Write string
	Idle  string
}

// LimitsConfig configures request limits.
type LimitsConfig struct {
	MaxRequestBody string
}

// RealIPConfig configures real IP extraction.
type RealIPConfig struct {
	Headers        []string
	TrustedProxies []string
}

// CBConfig configures the circuit breaker.
type CBConfig struct {
	Enabled   *bool
	Threshold int
	Timeout   string
}

// ManagementConfig configures the management port.
type ManagementConfig struct {
	Listen string
}

// cbEnabled returns whether circuit breaker is enabled (default true).
func (c *CBConfig) cbEnabled() bool {
	if c.Enabled != nil {
		return *c.Enabled
	}

	return true
}

// LoadConfig loads and validates configuration from a TOML file.
func LoadConfig(path string) (Config, error) {
	var cfg Config
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return cfg, fmt.Errorf("config: %w", err)
	}

	applyDefaults(&cfg)

	if err := cfg.Validate(); err != nil {
		return cfg, err
	}

	return cfg, nil
}

// Validate checks required fields and format.
func (c *Config) Validate() error {
	discovery := c.Proxy.TargetDiscovery.TargetDiscoveryEnabled()
	hasTargets := len(c.Proxy.Targets) > 0

	if !discovery && !hasTargets {
		return errors.New("config: either Proxy.Targets or Proxy.TargetDiscovery is required")
	}

	if discovery && hasTargets {
		return errors.New("config: Proxy.Targets and Proxy.TargetDiscovery are mutually exclusive")
	}

	if discovery && c.Proxy.TargetDiscovery.Hostname == "" {
		return errors.New("config: Proxy.TargetDiscovery.Hostname is required when discovery enabled")
	}

	if c.Proxy.ServiceName == "" {
		return errors.New("config: Proxy.ServiceName is required")
	}

	if err := parseSizeString(c.Proxy.Limits.MaxRequestBody, "Proxy.Limits.MaxRequestBody"); err != nil {
		return err
	}

	if err := c.Decision.validate(); err != nil {
		return err
	}

	if err := c.Captcha.validate(); err != nil {
		return err
	}

	// validate duration fields
	durationFields := []struct {
		value string
		name  string
	}{
		{c.Proxy.Timeouts.Read, "Proxy.Timeouts.Read"},
		{c.Proxy.Timeouts.Write, "Proxy.Timeouts.Write"},
		{c.Proxy.Timeouts.Idle, "Proxy.Timeouts.Idle"},
		{c.Proxy.CircuitBreaker.Timeout, "Proxy.CircuitBreaker.Timeout"},
		{c.IP.Whitelist.BotVerify.CacheTTL, "IP.Whitelist.BotVerify.CacheTTL"},
		{c.IP.Whitelist.BotVerify.DNSTimeout, "IP.Whitelist.BotVerify.DNSTimeout"},
		{c.IP.Whitelist.BotVerify.RangesRefresh, "IP.Whitelist.BotVerify.RangesRefresh"},
		{c.Captcha.CookieTTL, "Captcha.CookieTTL"},
		{c.Captcha.IPCacheTTL, "Captcha.IPCacheTTL"},
		{c.Decision.CaptchaToBlockWindow, "Decision.CaptchaToBlockWindow"},
		{c.Decision.SoftBlockDuration, "Decision.SoftBlockDuration"},
		{c.IP.Reputation.UpdateInterval, "IP.Reputation.UpdateInterval"},
	}

	for _, f := range durationFields {
		if err := validateDuration(f.value, f.name); err != nil {
			return err
		}
	}

	for i, wh := range c.Alerting.Webhooks {
		if err := validateDuration(wh.MinInterval, fmt.Sprintf("Alerting.Webhooks[%d].MinInterval", i)); err != nil {
			return err
		}
	}

	if err := c.IP.Reputation.validate(); err != nil {
		return err
	}

	return nil
}

var validCaptchaProviders = map[string]bool{"turnstile": true, "hcaptcha": true, "pow": true, "": true}

func (c *CaptchaConfig) validate() error {
	if !validCaptchaProviders[c.Provider] {
		return fmt.Errorf("config: Captcha.Provider must be turnstile, hcaptcha or pow, got %q", c.Provider)
	}

	if err := validateDuration(c.PoW.Timeout, "Captcha.PoW.Timeout"); err != nil {
		return err
	}

	if err := validateDuration(c.PoW.SaltTTL, "Captcha.PoW.SaltTTL"); err != nil {
		return err
	}

	return nil
}

const defaultAction = "block"

var validFallbacks = map[string]bool{"pass": true, defaultAction: true, "log": true}

func (c *DecisionConfig) validate() error {
	if !validFallbacks[c.CaptchaFallback] {
		return fmt.Errorf("config: Decision.CaptchaFallback must be pass/block/log, got %q", c.CaptchaFallback)
	}

	for i, p := range c.Platforms {
		if p.Platform == "" {
			return fmt.Errorf("config: Decision.Platforms[%d].Platform is required", i)
		}

		if p.Fallback != "" && !validFallbacks[p.Fallback] {
			return fmt.Errorf("config: Decision.Platforms[%d].Fallback must be pass/block/log, got %q", i, p.Fallback)
		}
	}

	return nil
}

// ProxyConfig returns a proxy.Config from the app config.
func (c *Config) ProxyConfig() (proxy.Config, error) {
	td := c.Proxy.TargetDiscovery
	scheme := td.Scheme
	if scheme == "" {
		scheme = "http"
	}

	return proxy.Config{
		Scheme:          scheme,
		ReadTimeout:     parseDuration(c.Proxy.Timeouts.Read, 30*time.Second),
		WriteTimeout:    parseDuration(c.Proxy.Timeouts.Write, 30*time.Second),
		IdleTimeout:     parseDuration(c.Proxy.Timeouts.Idle, 120*time.Second),
		MaxRequestBody:  parseSize(c.Proxy.Limits.MaxRequestBody, 1<<20),
		CBEnabled:       c.Proxy.CircuitBreaker.cbEnabled(),
		CBThreshold:     uint32(c.Proxy.CircuitBreaker.Threshold),
		CBTimeout:       parseDuration(c.Proxy.CircuitBreaker.Timeout, 30*time.Second),
		TrustedProxies:  c.Proxy.RealIP.TrustedProxies,
		RealIPHeaders:   c.Proxy.RealIP.Headers,
		RefreshInterval: parseDuration(td.RefreshInterval, 0),
		ResolveTimeout:  parseDuration(td.ResolveTimeout, 3*time.Second),
	}, nil
}

// ProxyTargetURLs parses Proxy.Targets strings into url.URL slice.
func (c *Config) ProxyTargetURLs() ([]*url.URL, error) {
	targets := make([]*url.URL, 0, len(c.Proxy.Targets))
	for _, t := range c.Proxy.Targets {
		u, err := url.Parse(t)
		if err != nil {
			return nil, fmt.Errorf("config: invalid target %q: %w", t, err)
		}

		targets = append(targets, u)
	}

	return targets, nil
}

// IPServiceConfig builds ip.Config from app config.
func (c *Config) IPServiceConfig() (ip.Config, error) {
	whitelist, err := proxy.ParseTrustedProxies(c.IP.Whitelist.CIDRs)
	if err != nil {
		return ip.Config{}, fmt.Errorf("config: invalid whitelist CIDR: %w", err)
	}

	blacklist, err := proxy.ParseTrustedProxies(c.IP.Blacklist.CIDRs)
	if err != nil {
		return ip.Config{}, fmt.Errorf("config: invalid blacklist CIDR: %w", err)
	}

	cfg := ip.Config{
		GeoDatabase:      c.IP.GeoDatabase,
		ASNDatabase:      c.IP.ASNDatabase,
		Whitelist:        whitelist,
		Blacklist:        blacklist,
		BlockCountries:   c.IP.Countries.Block,
		CaptchaCountries: c.IP.Countries.Captcha,
		LogCountries:     c.IP.Countries.Log,
		VerifyBots:       c.IP.Whitelist.VerifyBotsEnabled(),
		BotDomains:       c.IP.Whitelist.BotDomains,
		BotVerify: ip.BotVerifyConfig{
			CacheSize:     c.IP.Whitelist.BotVerify.CacheSize,
			CacheTTL:      parseDuration(c.IP.Whitelist.BotVerify.CacheTTL, time.Hour),
			DNSTimeout:    parseDuration(c.IP.Whitelist.BotVerify.DNSTimeout, 2*time.Second),
			RangesRefresh: parseDuration(c.IP.Whitelist.BotVerify.RangesRefresh, 24*time.Hour),
			FakeBotScore:  c.IP.Whitelist.BotVerify.FakeBotScore,
		},
	}

	if c.IP.Reputation.ReputationEnabled() {
		rep := c.IP.Reputation

		feeds := make([]ip.CustomFeed, len(rep.Feeds))
		for i, f := range rep.Feeds {
			feeds[i] = ip.CustomFeed{Name: f.Name, URL: f.URL, Action: f.Action}
		}

		cfg.Reputation = ip.ReputationConfig{
			Enabled:         true,
			UpdateInterval:  parseDuration(rep.UpdateInterval, time.Hour),
			ScoreAdjustment: rep.ScoreAdjustment,
			FireHOL: ip.FireHOLReputationConfig{
				Enabled: rep.FireHOL.IsEnabled(),
				Level:   rep.FireHOL.Level,
			},
			Tor: ip.TorReputationConfig{
				Enabled: rep.Tor.IsEnabled(),
				Action:  rep.Tor.Action,
			},
			Datacenter: ip.DatacenterReputationConfig{
				Enabled:         rep.Datacenter.IsEnabled(),
				ScoreAdjustment: rep.Datacenter.ScoreAdjustment,
				ExtraASNs:       rep.Datacenter.ExtraASNs,
			},
			Feeds: feeds,
		}
	}

	return cfg, nil
}

// LimiterConfig builds limit.Config from app config.
func (c *Config) LimiterConfig() (limit.Config, error) {
	perIP, err := limit.ParseRate(c.RateLimit.PerIP)
	if err != nil {
		return limit.Config{}, fmt.Errorf("config: %w", err)
	}

	rules := make([]limit.Rule, 0, len(c.RateLimit.Rules))
	for _, r := range c.RateLimit.Rules {
		rt, err := limit.ParseRate(r.Limit)
		if err != nil {
			return limit.Config{}, fmt.Errorf("config: rule %q: %w", r.Name, err)
		}

		action := r.Action
		if action == "" {
			action = c.RateLimit.Action
		}

		rules = append(rules, limit.Rule{
			Name:     r.Name,
			Endpoint: r.Endpoint,
			Match:    r.Match,
			Limit:    rt,
			Action:   action,
		})
	}

	return limit.Config{
		PerIP:       perIP,
		Action:      c.RateLimit.Action,
		MaxCounters: c.RateLimit.MaxCounters,
		Rules:       rules,
	}, nil
}

const (
	defaultTimeout  = "30s"
	defaultWindow10 = "10m"
)

func applyDefaults(c *Config) {
	applyProxyDefaults(c)
	applyWAFDefaults(c)
	applySigningDefaults(c)
	applyDecisionDefaults(c)
	applyAdaptiveDefaults(c)
	applyStorageDefaults(c)
	applyReputationDefaults(c)
}

var (
	validTorActions  = map[string]bool{"score": true, "captcha": true, "block": true}
	validFeedActions = map[string]bool{"score": true, "block": true}
)

func (c *ReputationConfig) validate() error {
	if !c.ReputationEnabled() {
		return nil
	}

	if c.Tor.Action != "" && !validTorActions[c.Tor.Action] {
		return fmt.Errorf("config: IP.Reputation.Tor.Action must be score/captcha/block, got %q", c.Tor.Action)
	}

	if c.FireHOL.Level < 1 || c.FireHOL.Level > 2 {
		return fmt.Errorf("config: IP.Reputation.FireHOL.Level must be 1 or 2, got %d", c.FireHOL.Level)
	}

	for i, f := range c.Feeds {
		if f.URL == "" {
			return fmt.Errorf("config: IP.Reputation.Feeds[%d].URL is required", i)
		}

		if f.Action != "" && !validFeedActions[f.Action] {
			return fmt.Errorf("config: IP.Reputation.Feeds[%d].Action must be score/block, got %q", i, f.Action)
		}
	}

	return nil
}

func applyReputationDefaults(c *Config) {
	if !c.IP.Reputation.ReputationEnabled() {
		return
	}

	if c.IP.Reputation.UpdateInterval == "" {
		c.IP.Reputation.UpdateInterval = "1h"
	}

	if c.IP.Reputation.ScoreAdjustment == 0 {
		c.IP.Reputation.ScoreAdjustment = 3.0
	}

	if c.IP.Reputation.FireHOL.Enabled == nil {
		c.IP.Reputation.FireHOL.Enabled = &trueVal
	}

	if c.IP.Reputation.FireHOL.Level == 0 {
		c.IP.Reputation.FireHOL.Level = 1
	}

	if c.IP.Reputation.Tor.Enabled == nil {
		c.IP.Reputation.Tor.Enabled = &trueVal
	}

	if c.IP.Reputation.Tor.Action == "" {
		c.IP.Reputation.Tor.Action = "score"
	}

	if c.IP.Reputation.Datacenter.Enabled == nil {
		c.IP.Reputation.Datacenter.Enabled = &trueVal
	}

	if c.IP.Reputation.Datacenter.ScoreAdjustment == 0 {
		c.IP.Reputation.Datacenter.ScoreAdjustment = 2.0
	}

	for i := range c.IP.Reputation.Feeds {
		if c.IP.Reputation.Feeds[i].Action == "" {
			c.IP.Reputation.Feeds[i].Action = "score"
		}
	}
}

func applyStorageDefaults(c *Config) {
	if c.Storage.Backend == "" {
		c.Storage.Backend = StorageMemory
	}

	if c.Storage.Aerospike.Namespace == "" {
		c.Storage.Aerospike.Namespace = "wafsrv"
	}

	if c.Storage.Aerospike.ConnectTimeout == "" {
		c.Storage.Aerospike.ConnectTimeout = "5s"
	}

	if c.Storage.Aerospike.OperTimeout == "" {
		c.Storage.Aerospike.OperTimeout = "50ms"
	}
}

func applyAdaptiveDefaults(c *Config) {
	if c.Adaptive.Mode == "" {
		c.Adaptive.Mode = "auto"
	}

	if c.Adaptive.EvalInterval == "" {
		c.Adaptive.EvalInterval = "10s"
	}

	if c.Adaptive.WarmupDuration == "" {
		c.Adaptive.WarmupDuration = "2m"
	}

	aa := &c.Adaptive.AutoAttack

	if aa.RPSMultiplier == 0 {
		aa.RPSMultiplier = 3.0
	}

	if aa.RPSRecoveryMultiplier == 0 {
		aa.RPSRecoveryMultiplier = 1.5
	}

	if aa.MinRPS == 0 {
		aa.MinRPS = 10
	}

	if aa.ErrorRateThreshold == 0 {
		aa.ErrorRateThreshold = 20
	}

	if aa.LatencyThresholdMs == 0 {
		aa.LatencyThresholdMs = 500
	}

	if aa.BlockedRateThreshold == 0 {
		aa.BlockedRateThreshold = 50
	}

	if aa.Window == "" {
		aa.Window = "1m"
	}

	if aa.Cooldown == "" {
		aa.Cooldown = "5m"
	}

	if aa.Duration == "" {
		aa.Duration = defaultWindow10
	}
}

func applyProxyDefaults(c *Config) {
	if c.Proxy.Listen == "" {
		c.Proxy.Listen = ":8080"
	}

	if c.Proxy.Timeouts.Read == "" {
		c.Proxy.Timeouts.Read = defaultTimeout
	}

	if c.Proxy.Timeouts.Write == "" {
		c.Proxy.Timeouts.Write = defaultTimeout
	}

	if c.Proxy.Timeouts.Idle == "" {
		c.Proxy.Timeouts.Idle = "120s"
	}

	if c.Proxy.Limits.MaxRequestBody == "" {
		c.Proxy.Limits.MaxRequestBody = "1MB"
	}

	if len(c.Proxy.RealIP.Headers) == 0 {
		c.Proxy.RealIP.Headers = []string{"CF-Connecting-IP", "X-Real-IP", "X-Forwarded-For"}
	}

	if len(c.Proxy.RealIP.TrustedProxies) == 0 {
		c.Proxy.RealIP.TrustedProxies = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
	}

	if c.Proxy.CircuitBreaker.Threshold == 0 {
		c.Proxy.CircuitBreaker.Threshold = 10
	}

	if c.Proxy.CircuitBreaker.Timeout == "" {
		c.Proxy.CircuitBreaker.Timeout = defaultTimeout
	}

	if c.Proxy.TargetDiscovery.TargetDiscoveryEnabled() {
		td := &c.Proxy.TargetDiscovery
		if td.Scheme == "" {
			td.Scheme = "http"
		}

		if td.RefreshInterval == "" {
			td.RefreshInterval = "1s"
		}

		if td.ResolveTimeout == "" {
			td.ResolveTimeout = "3s"
		}
	}

	if c.Management.Listen == "" {
		c.Management.Listen = "127.0.0.1:8081"
	}

	if len(c.JSONRPC.Endpoints) == 0 {
		c.JSONRPC.Endpoints = []JSONRPCEndpoint{{Path: "/rpc/", Name: "main"}}
	}
}

func applyWAFDefaults(c *Config) {
	if c.WAF.Mode == "" {
		c.WAF.Mode = "detection"
	}

	if c.WAF.ParanoiaLevel == 0 {
		c.WAF.ParanoiaLevel = 1
	}

	if c.RateLimit.PerIP == "" {
		c.RateLimit.PerIP = "100/min"
	}

	if c.RateLimit.Action == "" {
		c.RateLimit.Action = defaultAction
	}

	if c.RateLimit.MaxCounters == 0 {
		c.RateLimit.MaxCounters = 100000
	}

	if c.IP.Whitelist.BotVerify.CacheSize == 0 {
		c.IP.Whitelist.BotVerify.CacheSize = 10000
	}

	if c.IP.Whitelist.BotVerify.CacheTTL == "" {
		c.IP.Whitelist.BotVerify.CacheTTL = "1h"
	}

	if c.IP.Whitelist.BotVerify.DNSTimeout == "" {
		c.IP.Whitelist.BotVerify.DNSTimeout = "2s"
	}

	if c.IP.Whitelist.BotVerify.RangesRefresh == "" {
		c.IP.Whitelist.BotVerify.RangesRefresh = "24h"
	}

	if c.IP.Whitelist.BotVerify.FakeBotScore == 0 {
		c.IP.Whitelist.BotVerify.FakeBotScore = 5.0
	}
}

func applySigningDefaults(c *Config) {
	if c.Signing.Mode == "" {
		c.Signing.Mode = "detection"
	}

	if c.Signing.TTL == "" {
		c.Signing.TTL = "5m"
	}

	if c.Signing.NonceCache == 0 {
		c.Signing.NonceCache = 100000
	}
}

func applyDecisionDefaults(c *Config) {
	if c.Decision.CaptchaThreshold == 0 {
		c.Decision.CaptchaThreshold = 5
	}

	if c.Decision.BlockThreshold == 0 {
		c.Decision.BlockThreshold = 8
	}

	if c.Decision.CaptchaStatusCode == 0 {
		c.Decision.CaptchaStatusCode = 499
	}

	if c.Decision.BlockStatusCode == 0 {
		c.Decision.BlockStatusCode = http.StatusForbidden
	}

	if c.Decision.CaptchaToBlock == 0 {
		c.Decision.CaptchaToBlock = 3
	}

	if c.Decision.CaptchaToBlockWindow == "" {
		c.Decision.CaptchaToBlockWindow = defaultWindow10
	}

	if c.Decision.SoftBlockDuration == "" {
		c.Decision.SoftBlockDuration = defaultWindow10
	}

	if c.Decision.CaptchaFallback == "" {
		c.Decision.CaptchaFallback = defaultAction
	}

	if c.Captcha.CookieName == "" {
		c.Captcha.CookieName = "waf_pass"
	}

	if c.Captcha.CookieTTL == "" {
		c.Captcha.CookieTTL = "30m"
	}

	if c.Captcha.IPCacheTTL == "" {
		c.Captcha.IPCacheTTL = "30m"
	}

	if c.Captcha.MaxCacheSize == 0 {
		c.Captcha.MaxCacheSize = 50000
	}

	if c.Captcha.PoW.Difficulty == 0 {
		c.Captcha.PoW.Difficulty = 50000
	}

	if c.Captcha.PoW.AttackDifficulty == 0 {
		c.Captcha.PoW.AttackDifficulty = 500000
	}

	if c.Captcha.PoW.Timeout == "" {
		c.Captcha.PoW.Timeout = "10s"
	}

	if c.Captcha.PoW.SaltTTL == "" {
		c.Captcha.PoW.SaltTTL = "5m"
	}
}

var trueVal = true

// validateDuration validates a duration string. Empty strings are OK (defaults apply).
func validateDuration(s, field string) error {
	if s == "" {
		return nil
	}

	if _, err := time.ParseDuration(s); err != nil {
		return fmt.Errorf("config: invalid duration %q for %s: %w", s, field, err)
	}

	return nil
}
