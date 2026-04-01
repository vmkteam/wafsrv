package ip

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/vmkteam/embedlog"
	"golang.org/x/sync/singleflight"
)

// KnownBot describes a search engine bot for verification.
type KnownBot struct {
	Name       string
	UAPatterns []string
	PTRDomains []string
	RangesURL  string
}

var knownBots = []KnownBot{
	{
		Name:       "google",
		UAPatterns: []string{"Googlebot/", "Googlebot-Image/", "Googlebot-News/", "Googlebot-Video/", "Mediapartners-Google", "AdsBot-Google"},
		PTRDomains: []string{"googlebot.com", "google.com", "googleusercontent.com"},
		RangesURL:  "https://developers.google.com/static/search/apis/ipranges/googlebot.json",
	},
	{
		Name:       "bing",
		UAPatterns: []string{"bingbot/"},
		PTRDomains: []string{"search.msn.com"},
		RangesURL:  "https://www.bing.com/toolbox/bingbot.json",
	},
	{
		Name:       "yandex",
		UAPatterns: []string{"YandexBot/", "YandexImages/", "YandexMedia/"},
		PTRDomains: []string{"yandex.ru", "yandex.net", "yandex.com"},
	},
	{
		Name:       "apple",
		UAPatterns: []string{"Applebot/"},
		PTRDomains: []string{"applebot.apple.com"},
		RangesURL:  "https://search.developer.apple.com/applebot.json",
	},
	{
		Name:       "duckduckgo",
		UAPatterns: []string{"DuckDuckBot/"},
		PTRDomains: []string{"duckduckgo.com"},
		RangesURL:  "https://duckduckgo.com/duckduckbot.json",
	},
}

// BotVerifyConfig holds bot verification settings.
type BotVerifyConfig struct {
	CacheSize     int
	CacheTTL      time.Duration
	DNSTimeout    time.Duration
	RangesRefresh time.Duration
	FakeBotScore  float64
}

// BotVerifyResult is the outcome of a bot verification check.
type BotVerifyResult struct {
	Verified bool
	Pending  bool   // PTR in progress, no result yet
	BotName  string // "google", "bing", ...
	Hostname string // PTR hostname
	Method   string // "ip_ranges" | "ptr"
}

type verifyCacheEntry struct {
	result    BotVerifyResult
	expiresAt time.Time
}

// BotVerifier performs bot verification via IP ranges and PTR lookup.
type BotVerifier struct {
	bots         []KnownBot
	extraDomains []string
	allDomains   []botDomainEntry // precomputed: domain suffix → bot name
	ranges       *BotRanges
	cfg          BotVerifyConfig
	resolver     *net.Resolver
	logger       embedlog.Logger

	mu       sync.RWMutex
	cache    map[netip.Addr]*verifyCacheEntry
	inflight singleflight.Group
}

type botDomainEntry struct {
	suffix  string // ".googlebot.com"
	botName string
}

// NewBotVerifier creates a new bot verifier.
func NewBotVerifier(cfg BotVerifyConfig, extraDomains []string, ranges *BotRanges, logger embedlog.Logger) *BotVerifier {
	v := &BotVerifier{
		bots:         knownBots,
		extraDomains: extraDomains,
		ranges:       ranges,
		cfg:          cfg,
		resolver:     net.DefaultResolver,
		logger:       logger,
		cache:        make(map[netip.Addr]*verifyCacheEntry, cfg.CacheSize),
	}

	v.allDomains = v.buildDomainIndex()

	return v
}

func (v *BotVerifier) buildDomainIndex() []botDomainEntry {
	var entries []botDomainEntry

	for _, bot := range v.bots {
		for _, d := range bot.PTRDomains {
			entries = append(entries, botDomainEntry{
				suffix:  "." + d,
				botName: bot.Name,
			})
		}
	}

	for _, d := range v.extraDomains {
		entries = append(entries, botDomainEntry{
			suffix:  "." + d,
			botName: d, // use domain as name for extras
		})
	}

	return entries
}

// MatchUA returns the bot name if the User-Agent matches a known bot pattern, or "".
func (v *BotVerifier) MatchUA(ua string) string {
	for _, bot := range v.bots {
		for _, pattern := range bot.UAPatterns {
			if strings.Contains(ua, pattern) {
				return bot.Name
			}
		}
	}

	return ""
}

// Verify checks if an IP belongs to a verified bot.
// Returns immediately from cache or IP ranges. Falls back to async PTR lookup.
func (v *BotVerifier) Verify(ctx context.Context, ip netip.Addr) BotVerifyResult {
	// 1. cache
	if entry := v.getCached(ip); entry != nil {
		return entry.result
	}

	// 2. fast path: IP ranges
	if v.ranges != nil {
		if botName, ok := v.ranges.Contains(ip); ok {
			result := BotVerifyResult{
				Verified: true,
				BotName:  botName,
				Method:   "ip_ranges",
			}
			v.putCache(ip, result)

			return result
		}
	}

	// 3. slow path: async PTR
	ch := v.inflight.DoChan(ip.String(), func() (any, error) {
		result := v.verifyPTR(ip)
		v.putCache(ip, result)

		return result, nil
	})

	select {
	case res := <-ch:
		if r, ok := res.Val.(BotVerifyResult); ok {
			return r
		}

		return BotVerifyResult{}
	default:
		// PTR in progress, don't block
		return BotVerifyResult{Pending: true}
	}
}

func (v *BotVerifier) verifyPTR(ip netip.Addr) BotVerifyResult {
	ctx, cancel := context.WithTimeout(context.Background(), v.cfg.DNSTimeout)
	defer cancel()

	// reverse DNS
	names, err := v.resolver.LookupAddr(ctx, ip.String())
	if err != nil || len(names) == 0 {
		return BotVerifyResult{}
	}

	for _, name := range names {
		name = strings.TrimSuffix(name, ".")

		botName := v.matchDomain(name)
		if botName == "" {
			continue
		}

		// forward DNS confirm
		ctx2, cancel2 := context.WithTimeout(context.Background(), v.cfg.DNSTimeout)
		addrs, err := v.resolver.LookupHost(ctx2, name)
		cancel2()

		if err != nil {
			continue
		}

		for _, a := range addrs {
			if parsed, err := netip.ParseAddr(a); err == nil && parsed == ip {
				v.logger.Print(context.Background(), "bot_verified",
					"clientIp", ip.String(),
					"bot", botName,
					"method", "ptr",
					"hostname", name,
				)

				return BotVerifyResult{
					Verified: true,
					BotName:  botName,
					Hostname: name,
					Method:   "ptr",
				}
			}
		}
	}

	return BotVerifyResult{}
}

func (v *BotVerifier) matchDomain(hostname string) string {
	lower := strings.ToLower(hostname)
	for _, entry := range v.allDomains {
		if strings.HasSuffix(lower, entry.suffix) {
			return entry.botName
		}
	}

	return ""
}

func (v *BotVerifier) getCached(ip netip.Addr) *verifyCacheEntry {
	v.mu.RLock()
	entry, ok := v.cache[ip]
	v.mu.RUnlock()

	if !ok {
		return nil
	}

	if time.Now().After(entry.expiresAt) {
		v.mu.Lock()
		delete(v.cache, ip)
		v.mu.Unlock()

		return nil
	}

	return entry
}

func (v *BotVerifier) putCache(ip netip.Addr, result BotVerifyResult) {
	v.mu.Lock()
	defer v.mu.Unlock()

	// simple eviction: if at capacity, clear half
	if len(v.cache) >= v.cfg.CacheSize {
		i := 0
		for k := range v.cache {
			delete(v.cache, k)
			i++

			if i >= v.cfg.CacheSize/2 {
				break
			}
		}
	}

	v.cache[ip] = &verifyCacheEntry{
		result:    result,
		expiresAt: time.Now().Add(v.cfg.CacheTTL),
	}
}
