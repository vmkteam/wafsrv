package waf

import "net/netip"

// Action represents a WAF decision action.
type Action int

const (
	ActionPass      Action = iota
	ActionLog              // detection mode: log but pass
	ActionThrottle         // 429
	ActionCaptcha          // 499 — captcha required
	ActionSoftBlock        // 403, temporary (with TTL)
	ActionHardBlock        // 403, permanent (until manual unblock)
	ActionBlock            // 403, generic
)

// String returns the string representation of the action.
func (a Action) String() string {
	switch a {
	case ActionPass:
		return "pass"
	case ActionLog:
		return "log"
	case ActionThrottle:
		return "throttle"
	case ActionCaptcha:
		return "captcha"
	case ActionSoftBlock:
		return "soft_block"
	case ActionHardBlock:
		return "hard_block"
	case ActionBlock:
		return "block"
	default:
		return "unknown"
	}
}

// RequestContext contains per-request data passed through context.Context.
type RequestContext struct {
	RequestID     string
	ClientIP      netip.Addr
	Static        bool // true → skip heavy middleware (WAF, rate limit, decision)
	SignedLevel   int  // 0=unsigned, 1=fingerprint only (score bonus), 2=fingerprint+fields (skip ratelimit+captcha)
	Platform      string
	Version       string
	Discriminator string // Platform + ":" + fnv32(UA), computed in initContext
	RPC           *RPCCall
	IP            *IPInfo // filled by ip.Middleware
	WAFScore      float64 // filled by engine.Middleware
	Decision      Action  // filled by decide.Middleware
	TrafficType   string  // filled by sign.Middleware
	Target        string  // filled by proxy handler (backend URL)
}

// RPCCall contains parsed JSON-RPC call info.
type RPCCall struct {
	Endpoint  string
	Methods   []string
	IsBatch   bool
	BatchSize int    // number of items in batch (may differ from len(Methods) if some have empty method)
	Body      []byte // raw JSON-RPC body (for sign field extraction)
}

// IPInfo contains IP intelligence data.
type IPInfo struct {
	Country         string // ISO 3166-1 alpha-2, e.g. "RU"
	ASN             uint32
	ASNOrg          string
	Whitelisted     bool
	VerifiedBot     bool     // true if PTR/IP ranges verification passed
	BotName         string   // "google", "yandex", etc.
	IsDatacenter    bool     // true if ASN belongs to known hosting/cloud provider
	IsTor           bool     // true if IP is a Tor exit node
	ReputationFeeds []string // matched feed names, e.g. ["firehol_l1", "tor"]
}
