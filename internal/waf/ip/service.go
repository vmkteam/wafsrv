package ip

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"wafsrv/internal/waf"
	"wafsrv/internal/waf/event"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/vmkteam/embedlog"
)

// Config holds IP intelligence configuration.
type Config struct {
	GeoDatabase      string
	ASNDatabase      string
	Whitelist        []netip.Prefix
	Blacklist        []netip.Prefix
	BlockCountries   []string // → 403
	CaptchaCountries []string // → score bump → captcha
	LogCountries     []string // → log only, pass
	VerifyBots       bool
	BotDomains       []string
	BotVerify        BotVerifyConfig
	Reputation       ReputationConfig
}

// ReputationConfig holds parsed reputation feed settings (no TOML tags).
type ReputationConfig struct {
	Enabled         bool
	UpdateInterval  time.Duration
	ScoreAdjustment float64
	FireHOL         FireHOLReputationConfig
	Tor             TorReputationConfig
	Datacenter      DatacenterReputationConfig
	Feeds           []CustomFeed
}

// FireHOLReputationConfig holds FireHOL feed settings.
type FireHOLReputationConfig struct {
	Enabled bool
	Level   int // 1 or 2
}

// TorReputationConfig holds Tor exit node feed settings.
type TorReputationConfig struct {
	Enabled bool
	Action  string // "score" | "captcha" | "block"
}

// DatacenterReputationConfig holds datacenter ASN detection settings.
type DatacenterReputationConfig struct {
	Enabled         bool
	ScoreAdjustment float64
	ExtraASNs       []uint32
}

// CustomFeed defines an external IP feed.
type CustomFeed struct {
	Name   string
	URL    string
	Action string // "score" | "block"
}

// Metrics holds IP service prometheus metrics.
type Metrics struct {
	BlockedTotal     *prometheus.CounterVec
	WhitelistedTotal prometheus.Counter
	Recorder         *event.Recorder
}

// BlockEntry represents a runtime block rule with metadata.
type BlockEntry struct {
	Value     string
	Reason    string
	AddedAt   time.Time
	ExpiresAt time.Time // zero = permanent
}

// Service provides IP intelligence lookups.
type Service struct {
	embedlog.Logger
	cfg              Config
	geo              *geoReader
	botVerifier      *BotVerifier
	botRanges        *BotRanges
	reputation       *Reputation
	rangesCancel     context.CancelFunc
	mu               sync.RWMutex
	blockedIPs       map[netip.Addr]*BlockEntry
	blockedCIDRs     map[netip.Prefix]*BlockEntry
	blockedCountries map[string]*BlockEntry
	blockedASNs      map[uint32]*BlockEntry
	metrics          Metrics
}

// New creates a new IP intelligence service.
func New(cfg Config, sl embedlog.Logger, metrics Metrics) (*Service, error) {
	s := &Service{
		Logger:           sl,
		cfg:              cfg,
		blockedIPs:       make(map[netip.Addr]*BlockEntry),
		blockedCIDRs:     make(map[netip.Prefix]*BlockEntry),
		blockedCountries: make(map[string]*BlockEntry),
		blockedASNs:      make(map[uint32]*BlockEntry),
		metrics:          metrics,
	}

	// GeoIP: use external files if configured, otherwise fall back to embedded databases
	if cfg.GeoDatabase != "" || cfg.ASNDatabase != "" || len(embeddedCountryDB) > 0 {
		var err error

		s.geo, err = newGeoReader(cfg.GeoDatabase, cfg.ASNDatabase)
		if err != nil {
			return nil, err
		}
	}

	if cfg.VerifyBots {
		s.botRanges = NewBotRanges(sl)

		ctx, cancel := context.WithCancel(context.Background())
		s.rangesCancel = cancel

		go s.botRanges.Start(ctx, knownBots, cfg.BotVerify.RangesRefresh)

		s.botVerifier = NewBotVerifier(cfg.BotVerify, cfg.BotDomains, s.botRanges, sl)
	}

	if cfg.Reputation.Enabled {
		s.reputation = NewReputation(cfg.Reputation, sl)
	}

	return s, nil
}

// Start launches background goroutines (reputation feed refresh).
// Call from app.Run() after New().
func (s *Service) Start(ctx context.Context) {
	if s.reputation != nil {
		go s.reputation.Start(ctx)
	}
}

// Metrics returns the service metrics for registration.
func (s *Service) Metrics() Metrics {
	return s.metrics
}

// LookupIP returns GeoIP info for an IP address.
func (s *Service) LookupIP(addr netip.Addr) *waf.IPInfo {
	info := &waf.IPInfo{}
	if s.geo != nil {
		s.geo.lookup(addr, info)
	}

	return info
}

// Close releases resources.
func (s *Service) Close() error {
	if s.rangesCancel != nil {
		s.rangesCancel()
	}

	if s.geo != nil {
		return s.geo.close()
	}

	return nil
}

// AddBlock adds a runtime block rule. Type: "ip", "cidr", "country", "asn".
func (s *Service) AddBlock(blockType, value, reason string, duration time.Duration) error {
	entry := &BlockEntry{
		Value:   value,
		Reason:  reason,
		AddedAt: time.Now(),
	}

	if duration > 0 {
		entry.ExpiresAt = entry.AddedAt.Add(duration)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	switch blockType {
	case blockTypeIP:
		addr, err := netip.ParseAddr(value)
		if err != nil {
			return err
		}

		s.blockedIPs[addr] = entry
	case blockTypeCIDR:
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return err
		}

		s.blockedCIDRs[prefix] = entry
	case blockTypeCountry:
		s.blockedCountries[value] = entry
	case blockTypeASN:
		return errUnknownBlockType // ASN blocking not implemented yet
	default:
		return errUnknownBlockType
	}

	return nil
}

// RemoveBlock removes a runtime block rule.
func (s *Service) RemoveBlock(blockType, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch blockType {
	case blockTypeIP:
		addr, err := netip.ParseAddr(value)
		if err != nil {
			return err
		}

		delete(s.blockedIPs, addr)
	case blockTypeCIDR:
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return err
		}

		delete(s.blockedCIDRs, prefix)
	case blockTypeCountry:
		delete(s.blockedCountries, value)
	case blockTypeASN:
		// not implemented yet
	default:
		return errUnknownBlockType
	}

	return nil
}

// ListBlocks returns all runtime block entries of given type.
func (s *Service) ListBlocks(blockType string) []BlockEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now()

	switch blockType {
	case blockTypeIP:
		return s.collectEntries(s.blockedIPs, now)
	case blockTypeCIDR:
		result := make([]BlockEntry, 0, len(s.blockedCIDRs))
		for _, e := range s.blockedCIDRs {
			if !e.isExpired(now) {
				result = append(result, *e)
			}
		}

		return result
	case blockTypeCountry:
		result := make([]BlockEntry, 0, len(s.blockedCountries))
		for _, e := range s.blockedCountries {
			if !e.isExpired(now) {
				result = append(result, *e)
			}
		}

		return result
	default:
		return nil
	}
}

func (s *Service) collectEntries(m map[netip.Addr]*BlockEntry, now time.Time) []BlockEntry {
	result := make([]BlockEntry, 0, len(m))
	for _, e := range m {
		if !e.isExpired(now) {
			result = append(result, *e)
		}
	}

	return result
}

func (e *BlockEntry) isExpired(now time.Time) bool {
	return !e.ExpiresAt.IsZero() && now.After(e.ExpiresAt)
}

// Legacy methods for backward compatibility.

// AddBlacklist adds an IP to the runtime blacklist (no metadata).
func (s *Service) AddBlacklist(ip netip.Addr) {
	_ = s.AddBlock("ip", ip.String(), "", 0)
}

// RemoveBlacklist removes an IP from the runtime blacklist.
func (s *Service) RemoveBlacklist(ip netip.Addr) {
	_ = s.RemoveBlock("ip", ip.String())
}

// ListBlacklist returns all runtime-blacklisted IPs.
func (s *Service) ListBlacklist() []netip.Addr {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now()
	result := make([]netip.Addr, 0, len(s.blockedIPs))

	for addr, e := range s.blockedIPs {
		if !e.isExpired(now) {
			result = append(result, addr)
		}
	}

	return result
}

const (
	blockTypeIP      = "ip"
	blockTypeCIDR    = "cidr"
	blockTypeCountry = "country"
	blockTypeASN     = "asn"
)

var errUnknownBlockType = errors.New("ip: unknown block type")

// Middleware returns an HTTP middleware that performs IP checks.
func (s *Service) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rc := waf.FromContext(r.Context())
			if rc == nil {
				next.ServeHTTP(w, r)
				return
			}

			info := &waf.IPInfo{}
			rc.IP = info

			if s.isWhitelisted(rc.ClientIP) {
				info.Whitelisted = true
				s.metrics.WhitelistedTotal.Inc()
				next.ServeHTTP(w, r)
				return
			}

			// bot verification (after whitelist, before blacklist)
			if s.checkBotVerify(r, rc, info) {
				next.ServeHTTP(w, r)
				return
			}

			if s.isBlacklisted(rc.ClientIP) {
				s.metrics.BlockedTotal.WithLabelValues("blacklist").Inc()
				s.addEvent(r, rc, "ip_blocked", "blacklist")
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			if s.geo != nil {
				s.geo.lookup(rc.ClientIP, info)

				if s.isCountryBlocked(info.Country) {
					s.metrics.BlockedTotal.WithLabelValues("country").Inc()
					s.addEvent(r, rc, "ip_blocked", "country:"+info.Country)
					http.Error(w, "Forbidden", http.StatusForbidden)

					return
				}
			}

			// reputation feeds check
			if s.reputation != nil {
				if blocked := s.checkReputation(w, r, rc, info); blocked {
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// checkBotVerify returns true if the request is from a verified bot (whitelisted).
func (s *Service) checkBotVerify(r *http.Request, rc *waf.RequestContext, info *waf.IPInfo) bool {
	if s.botVerifier == nil || rc.Static {
		return false
	}

	botName := s.botVerifier.MatchUA(r.UserAgent())
	if botName == "" {
		return false
	}

	result := s.botVerifier.Verify(r.Context(), rc.ClientIP)

	if result.Verified {
		info.Whitelisted = true
		info.VerifiedBot = true
		info.BotName = result.BotName
		s.metrics.WhitelistedTotal.Inc()
		s.metrics.Recorder.RecordBotVerified(result.BotName)

		s.Print(r.Context(), "bot_verified", "clientIp", rc.ClientIP.String(), "bot", result.BotName, "method", result.Method)

		return true
	}

	if !result.Pending {
		// fake bot — UA claims bot but verification failed
		rc.WAFScore += s.cfg.BotVerify.FakeBotScore
		s.metrics.BlockedTotal.WithLabelValues("fake_bot").Inc()
		s.addEvent(r, rc, "bot_fake", "claimed:"+botName)
		s.metrics.Recorder.RecordBotFake()
	}

	return false
}

func (s *Service) isWhitelisted(ip netip.Addr) bool {
	for _, p := range s.cfg.Whitelist {
		if p.Contains(ip) {
			return true
		}
	}

	return false
}

func (s *Service) isBlacklisted(ip netip.Addr) bool {
	// static config
	for _, p := range s.cfg.Blacklist {
		if p.Contains(ip) {
			return true
		}
	}

	// runtime
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now()

	// runtime IPs
	if e, ok := s.blockedIPs[ip]; ok && !e.isExpired(now) {
		return true
	}

	// runtime CIDRs
	for prefix, e := range s.blockedCIDRs {
		if prefix.Contains(ip) && !e.isExpired(now) {
			return true
		}
	}

	return false
}

func (s *Service) addEvent(r *http.Request, rc *waf.RequestContext, eventType, detail string) {
	args := []any{"reason", detail} //nolint:prealloc
	for _, a := range waf.SecurityAttrs(r) {
		args = append(args, a.Key, a.Value.Any())
	}

	s.Print(r.Context(), eventType, args...)

	s.metrics.Recorder.AddEvent(event.Event{
		Type:     eventType,
		ClientIP: rc.ClientIP.String(),
		Path:     r.URL.Path,
		Detail:   detail,
	})

	country := ""
	if rc.IP != nil {
		country = rc.IP.Country
	}

	s.metrics.Recorder.RecordBlocked(rc.ClientIP.String(), r.URL.Path, country, rc.Platform)
}

func (s *Service) isCountryBlocked(country string) bool {
	if country == "" {
		return false
	}

	// static config
	for _, c := range s.cfg.BlockCountries {
		if c == country {
			return true
		}
	}

	// runtime countries
	s.mu.RLock()
	defer s.mu.RUnlock()

	if e, ok := s.blockedCountries[country]; ok && !e.isExpired(time.Now()) {
		return true
	}

	return false
}

// checkReputation checks IP against reputation feeds and datacenter ASN.
// Returns true if request should be blocked (403).
func (s *Service) checkReputation(w http.ResponseWriter, r *http.Request, rc *waf.RequestContext, info *waf.IPInfo) bool {
	result := s.reputation.Check(rc.ClientIP)
	if result.Listed {
		info.ReputationFeeds = result.Feeds

		// check if Tor exit node
		for _, f := range result.Feeds {
			if f == feedTorExits {
				info.IsTor = true

				break
			}
		}

		switch result.Action {
		case FeedActionBlock:
			s.metrics.BlockedTotal.WithLabelValues("reputation").Inc()
			s.addEvent(r, rc, "ip_blocked", "reputation:"+strings.Join(result.Feeds, ","))
			http.Error(w, "Forbidden", http.StatusForbidden)

			return true
		case FeedActionCaptcha:
			rc.WAFScore += reputationCaptchaScore
		default: // "score"
			rc.WAFScore += result.Score
		}
	}

	// datacenter ASN check (uses ASN from GeoIP lookup)
	if info.ASN > 0 && s.reputation.CheckASN(info.ASN) {
		info.IsDatacenter = true
		rc.WAFScore += s.cfg.Reputation.Datacenter.ScoreAdjustment
	}

	return false
}
