package dashboard

import (
	"context"

	"github.com/vmkteam/zenrpc/v2"
)

// ConfigService provides read-only configuration view.
type ConfigService struct {
	zenrpc.Service
	resp ConfigResponse
}

// NewConfigService creates a ConfigService with a pre-built response.
func NewConfigService(resp ConfigResponse) *ConfigService {
	return &ConfigService{resp: resp}
}

// Get returns the full configuration (secrets masked).
//
//zenrpc:return ConfigResponse
func (s ConfigService) Get(_ context.Context) ConfigResponse {
	return s.resp
}

// ConfigResponse is the full config view (secrets masked).
type ConfigResponse struct {
	Proxy         ProxySection         `json:"proxy"`
	Management    ManagementSection    `json:"management"`
	JSONRPC       JSONRPCSection       `json:"jsonrpc"`
	WAF           WAFSection           `json:"waf"`
	RateLimit     RateLimitSection     `json:"rateLimit"`
	IP            IPSection            `json:"ip"`
	TrafficFilter TrafficFilterSection `json:"trafficFilter"`
	Signing       SigningSection       `json:"signing"`
	Decision      DecisionSection      `json:"decision"`
	Captcha       CaptchaSection       `json:"captcha"`
	Alerting      AlertingSection      `json:"alerting"`
	Adaptive      AdaptiveSection      `json:"adaptive"`
	Storage       StorageSection       `json:"storage"`
}

type ProxySection struct {
	Listen         string   `json:"listen"`
	Targets        []string `json:"targets"`
	ServiceName    string   `json:"serviceName"`
	Platforms      []string `json:"platforms,omitempty"`
	ReadTimeout    string   `json:"readTimeout"`
	WriteTimeout   string   `json:"writeTimeout"`
	IdleTimeout    string   `json:"idleTimeout"`
	MaxRequestBody string   `json:"maxRequestBody"`
	RealIPHeaders  []string `json:"realIpHeaders"`
	TrustedProxies []string `json:"trustedProxies"`
	CBEnabled      bool     `json:"cbEnabled"`
	CBThreshold    int      `json:"cbThreshold"`
	CBTimeout      string   `json:"cbTimeout"`
	StaticPaths    []string `json:"staticPaths,omitempty"`
	StaticExts     []string `json:"staticExts,omitempty"`

	// target discovery (DNS SRV)
	TargetDiscoveryEnabled bool   `json:"targetDiscoveryEnabled"`
	TargetDiscoveryHost    string `json:"targetDiscoveryHost,omitempty"`
	TargetDiscoveryScheme  string `json:"targetDiscoveryScheme,omitempty"`
	TargetDiscoveryDNS     string `json:"targetDiscoveryDns,omitempty"`
	TargetDiscoveryRefresh string `json:"targetDiscoveryRefresh,omitempty"`
	TargetDiscoveryTimeout string `json:"targetDiscoveryTimeout,omitempty"`
}

type ManagementSection struct {
	Listen string `json:"listen"`
}

type JSONRPCSection struct {
	Endpoints []JSONRPCEndpointInfo `json:"endpoints"`
}

type JSONRPCEndpointInfo struct {
	Path            string `json:"path"`
	Name            string `json:"name"`
	SchemaURL       string `json:"schemaUrl,omitempty"`
	SchemaRefresh   string `json:"schemaRefresh,omitempty"`
	MethodWhitelist bool   `json:"methodWhitelist"`
	MaxBatchSize    int    `json:"maxBatchSize"`
}

type WAFSection struct {
	Enabled       bool   `json:"enabled"`
	Mode          string `json:"mode"`
	ParanoiaLevel int    `json:"paranoiaLevel"`
}

type RateLimitSection struct {
	Enabled     bool       `json:"enabled"`
	PerIP       string     `json:"perIp"`
	Action      string     `json:"action"`
	MaxCounters int        `json:"maxCounters"`
	Rules       []RuleInfo `json:"rules"`
}

type IPSection struct {
	GeoDatabase      bool           `json:"geoDatabase"`
	ASNDatabase      bool           `json:"asnDatabase"`
	WhitelistCIDRs   int            `json:"whitelistCidrs"`
	BlacklistCIDRs   int            `json:"blacklistCidrs"`
	VerifyBots       bool           `json:"verifyBots"`
	BotDomains       []string       `json:"botDomains,omitempty"`
	FakeBotScore     float64        `json:"fakeBotScore,omitempty"`
	BlockCountries   []string       `json:"blockCountries,omitempty"`
	CaptchaCountries []string       `json:"captchaCountries,omitempty"`
	LogCountries     []string       `json:"logCountries,omitempty"`
	Reputation       ReputationInfo `json:"reputation"`
}

type ReputationInfo struct {
	Enabled         bool    `json:"enabled"`
	UpdateInterval  string  `json:"updateInterval,omitempty"`
	ScoreAdjustment float64 `json:"scoreAdjustment,omitempty"`
	FireHOL         bool    `json:"firehol"`
	FireHOLLevel    int     `json:"fireholLevel,omitempty"`
	Tor             bool    `json:"tor"`
	TorAction       string  `json:"torAction,omitempty"`
	Datacenter      bool    `json:"datacenter"`
	DcScore         float64 `json:"dcScore,omitempty"`
	FeedCount       int     `json:"feedCount,omitempty"`
}

type TrafficFilterSection struct {
	Enabled   bool `json:"enabled"`
	RuleCount int  `json:"ruleCount"`
}

type SigningSection struct {
	Enabled    bool   `json:"enabled"`
	Mode       string `json:"mode"`
	TTL        string `json:"ttl"`
	NonceCache int    `json:"nonceCache"`
	Web        bool   `json:"web"`
	Android    bool   `json:"android"`
	IOS        bool   `json:"ios"`
	Methods    int    `json:"methods"`
}

type DecisionSection struct {
	CaptchaThreshold     float64               `json:"captchaThreshold"`
	BlockThreshold       float64               `json:"blockThreshold"`
	CaptchaStatusCode    int                   `json:"captchaStatusCode"`
	BlockStatusCode      int                   `json:"blockStatusCode"`
	CaptchaToBlock       int                   `json:"captchaToBlock"`
	CaptchaToBlockWindow string                `json:"captchaToBlockWindow"`
	SoftBlockDuration    string                `json:"softBlockDuration"`
	CaptchaFallback      string                `json:"captchaFallback"`
	Platforms            []PlatformCaptchaInfo `json:"platforms,omitempty"`
}

type PlatformCaptchaInfo struct {
	Platform   string `json:"platform"`
	Captcha    bool   `json:"captcha"`
	MinVersion string `json:"minVersion,omitempty"`
	Fallback   string `json:"fallback,omitempty"`
}

type CaptchaSection struct {
	Provider   string `json:"provider,omitempty"`
	HasKeys    bool   `json:"hasKeys"`
	CookieName string `json:"cookieName"`
	CookieTTL  string `json:"cookieTtl"`
	IPCacheTTL string `json:"ipCacheTtl"`
}

type AlertingSection struct {
	Enabled      bool `json:"enabled"`
	WebhookCount int  `json:"webhookCount"`
}

type AdaptiveSection struct {
	Enabled        bool    `json:"enabled"`
	Mode           string  `json:"mode"`
	EvalInterval   string  `json:"evalInterval"`
	WarmupDuration string  `json:"warmupDuration"`
	RPSMultiplier  float64 `json:"rpsMultiplier"`
	RPSRecovery    float64 `json:"rpsRecovery"`
	MinRPS         float64 `json:"minRps"`
	ErrorRate      float64 `json:"errorRate"`
	LatencyMs      float64 `json:"latencyMs"`
	BlockedRate    float64 `json:"blockedRate"`
	Window         string  `json:"window"`
	Cooldown       string  `json:"cooldown"`
	Duration       string  `json:"duration"`
}

type StorageSection struct {
	Backend   string `json:"backend"`
	Hosts     int    `json:"hosts,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	KeyPrefix string `json:"keyPrefix,omitempty"`
}
