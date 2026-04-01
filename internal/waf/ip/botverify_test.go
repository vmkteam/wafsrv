package ip

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
	"github.com/vmkteam/embedlog"
)

type BotVerifySuite struct {
	suite.Suite
	logger *embedlog.Logger
}

func TestBotVerify(t *testing.T) {
	suite.Run(t, new(BotVerifySuite))
}

func (s *BotVerifySuite) SetupSuite() {
	sl := embedlog.NewLogger(false, false)
	s.logger = &sl
}

func (s *BotVerifySuite) TestMatchUA_Google() {
	v := s.newVerifier()
	s.Equal("google", v.MatchUA("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"))
	s.Equal("google", v.MatchUA("Googlebot-Image/1.0"))
	s.Equal("google", v.MatchUA("Mediapartners-Google"))
	s.Equal("google", v.MatchUA("AdsBot-Google (+http://www.google.com/adsbot.html)"))
}

func (s *BotVerifySuite) TestMatchUA_Bing() {
	v := s.newVerifier()
	s.Equal("bing", v.MatchUA("Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"))
}

func (s *BotVerifySuite) TestMatchUA_Yandex() {
	v := s.newVerifier()
	s.Equal("yandex", v.MatchUA("Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)"))
	s.Equal("yandex", v.MatchUA("Mozilla/5.0 (compatible; YandexImages/3.0; +http://yandex.com/bots)"))
}

func (s *BotVerifySuite) TestMatchUA_Apple() {
	v := s.newVerifier()
	s.Equal("apple", v.MatchUA("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/600.2.5 Applebot/0.1"))
}

func (s *BotVerifySuite) TestMatchUA_DuckDuckGo() {
	v := s.newVerifier()
	s.Equal("duckduckgo", v.MatchUA("DuckDuckBot/1.1; (+http://duckduckgo.com/duckduckbot.html)"))
}

func (s *BotVerifySuite) TestMatchUA_NoMatch() {
	v := s.newVerifier()
	s.Empty(v.MatchUA("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0"))
	s.Empty(v.MatchUA("curl/7.64.1"))
	s.Empty(v.MatchUA(""))
}

func (s *BotVerifySuite) TestMatchDomain() {
	v := s.newVerifier()
	s.Equal("google", v.matchDomain("crawl-66-249-66-1.googlebot.com"))
	s.Equal("google", v.matchDomain("geo-crawl-35-247-243-240.geo.googlebot.com"))
	s.Equal("google", v.matchDomain("rate-limited-proxy-66-249-83-67.google.com"))
	s.Equal("bing", v.matchDomain("msnbot-157-55-33-18.search.msn.com"))
	s.Equal("yandex", v.matchDomain("spider-5-255-253-1.yandex.com"))
	s.Equal("yandex", v.matchDomain("spider-141-8-142-74.yandex.ru"))
	s.Equal("apple", v.matchDomain("17-58-101-179.applebot.apple.com"))
	s.Empty(v.matchDomain("evil.example.com"))
	s.Empty(v.matchDomain("fakegooglebot.com"))
}

func (s *BotVerifySuite) TestMatchDomain_ExtraDomains() {
	v := NewBotVerifier(s.defaultCfg(), []string{"seznam.cz"}, nil, embedlog.NewLogger(false, false))
	s.Equal("seznam.cz", v.matchDomain("bot.seznam.cz"))
	s.Equal("google", v.matchDomain("crawl-1.googlebot.com"))
}

func (s *BotVerifySuite) TestVerify_CacheHit() {
	v := s.newVerifier()
	ip := netip.MustParseAddr("66.249.66.1")

	// prime cache
	v.putCache(ip, BotVerifyResult{Verified: true, BotName: "google", Method: "ptr"})

	result := v.Verify(context.Background(), ip)
	s.True(result.Verified)
	s.Equal("google", result.BotName)
}

func (s *BotVerifySuite) TestVerify_CacheExpiry() {
	cfg := s.defaultCfg()
	cfg.CacheTTL = 1 * time.Millisecond
	v := NewBotVerifier(cfg, nil, nil, embedlog.NewLogger(false, false))

	ip := netip.MustParseAddr("1.2.3.4")
	v.putCache(ip, BotVerifyResult{Verified: true, BotName: "google"})

	time.Sleep(5 * time.Millisecond)

	// expired — should return pending (PTR async)
	result := v.Verify(context.Background(), ip)
	s.False(result.Verified)
}

func (s *BotVerifySuite) TestVerify_IPRanges() {
	ranges := NewBotRanges(embedlog.NewLogger(false, false))
	ranges.mu.Lock()
	ranges.ranges["google"] = []netip.Prefix{netip.MustParsePrefix("66.249.64.0/19")}
	ranges.mu.Unlock()

	v := NewBotVerifier(s.defaultCfg(), nil, ranges, embedlog.NewLogger(false, false))
	ip := netip.MustParseAddr("66.249.66.1")

	result := v.Verify(context.Background(), ip)
	s.True(result.Verified)
	s.Equal("google", result.BotName)
	s.Equal("ip_ranges", result.Method)
}

func (s *BotVerifySuite) TestVerify_IPRanges_NoMatch() {
	ranges := NewBotRanges(embedlog.NewLogger(false, false))
	ranges.mu.Lock()
	ranges.ranges["google"] = []netip.Prefix{netip.MustParsePrefix("66.249.64.0/19")}
	ranges.mu.Unlock()

	v := NewBotVerifier(s.defaultCfg(), nil, ranges, embedlog.NewLogger(false, false))
	ip := netip.MustParseAddr("1.2.3.4")

	// no range match → async PTR → pending
	result := v.Verify(context.Background(), ip)
	s.False(result.Verified)
	s.True(result.Pending)
}

func (s *BotVerifySuite) TestVerify_PTR_WithMockResolver() {
	v := s.newVerifier()
	v.resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			// this won't actually be called in unit test mode,
			// but we test the PTR path via verifyPTR directly
			return nil, &net.DNSError{Err: "mock", Name: "test"}
		},
	}

	// verifyPTR with a non-existent IP → not verified
	result := v.verifyPTR(netip.MustParseAddr("1.2.3.4"))
	s.False(result.Verified)
	s.Empty(result.BotName)
}

func (s *BotVerifySuite) TestCacheEviction() {
	cfg := s.defaultCfg()
	cfg.CacheSize = 4
	v := NewBotVerifier(cfg, nil, nil, embedlog.NewLogger(false, false))

	// fill cache to capacity
	for i := range 4 {
		ip := netip.MustParseAddr("10.0.0." + itoa(i+1))
		v.putCache(ip, BotVerifyResult{})
	}

	s.Len(v.cache, 4)

	// add one more — triggers eviction of half
	v.putCache(netip.MustParseAddr("10.0.0.5"), BotVerifyResult{})
	s.LessOrEqual(len(v.cache), 3)
}

func (s *BotVerifySuite) newVerifier() *BotVerifier {
	return NewBotVerifier(s.defaultCfg(), nil, nil, embedlog.NewLogger(false, false))
}

func (s *BotVerifySuite) defaultCfg() BotVerifyConfig {
	return BotVerifyConfig{
		CacheSize:    1000,
		CacheTTL:     time.Hour,
		DNSTimeout:   2 * time.Second,
		FakeBotScore: 5.0,
	}
}

func itoa(i int) string {
	return []string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9"}[i]
}
