package filter

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/suite"
	"github.com/vmkteam/embedlog"
)

type FilterSuite struct {
	suite.Suite
}

func TestFilter(t *testing.T) {
	suite.Run(t, new(FilterSuite))
}

func (s *FilterSuite) TestSingleField_UAPrefix() {
	r := TrafficRule{Name: "python", Action: "block", UAPrefix: []string{"Python/"}}
	s.True(r.isActive(MatchRequest{UA: "Python/3.9 aiohttp/3.8"}))
	s.False(r.isActive(MatchRequest{UA: "Mozilla/5.0"}))
}

func (s *FilterSuite) TestSingleField_UAExact() {
	r := TrafficRule{Name: "bot", Action: "block", UAExact: []string{"BadBot/1.0"}}
	s.True(r.isActive(MatchRequest{UA: "BadBot/1.0"}))
	s.False(r.isActive(MatchRequest{UA: "BadBot/2.0"}))
}

func (s *FilterSuite) TestSingleField_Country() {
	r := TrafficRule{Name: "geo", Action: "block", Country: []string{"CN", "KP"}}
	s.True(r.isActive(MatchRequest{Country: "CN"}))
	s.True(r.isActive(MatchRequest{Country: "KP"}))
	s.False(r.isActive(MatchRequest{Country: "US"}))
}

func (s *FilterSuite) TestSingleField_IP_Exact() {
	r := TrafficRule{Name: "ip", Action: "block", IP: []string{"1.2.3.4"}}
	s.True(r.isActive(MatchRequest{IP: "1.2.3.4"}))
	s.False(r.isActive(MatchRequest{IP: "5.6.7.8"}))
}

func (s *FilterSuite) TestSingleField_IP_CIDR() {
	r := TrafficRule{Name: "cidr", Action: "block", IP: []string{"10.0.0.0/8"}}
	s.True(r.isActive(MatchRequest{IP: "10.1.2.3"}))
	s.False(r.isActive(MatchRequest{IP: "192.168.1.1"}))
}

func (s *FilterSuite) TestSingleField_Path() {
	r := TrafficRule{Name: "admin", Action: "block", Path: []string{"/admin", "/.env"}}
	s.True(r.isActive(MatchRequest{Path: "/admin/users"}))
	s.True(r.isActive(MatchRequest{Path: "/.env"}))
	s.False(r.isActive(MatchRequest{Path: "/api/v1"}))
}

func (s *FilterSuite) TestSingleField_Method() {
	r := TrafficRule{Name: "no-delete", Action: "block", Method: []string{"DELETE", "PATCH"}}
	s.True(r.isActive(MatchRequest{Method: "DELETE"}))
	s.False(r.isActive(MatchRequest{Method: "GET"}))
}

func (s *FilterSuite) TestMultiField_AND() {
	r := TrafficRule{
		Name:     "android-okhttp",
		Action:   "block",
		UAPrefix: []string{"okhttp"},
		Platform: []string{"Android"},
	}

	// both match
	s.True(r.isActive(MatchRequest{UA: "okhttp/4.9", Platform: "Android"}))
	// only UA matches
	s.False(r.isActive(MatchRequest{UA: "okhttp/4.9", Platform: "iOS"}))
	// only Platform matches
	s.False(r.isActive(MatchRequest{UA: "Mozilla/5.0", Platform: "Android"}))
	// neither matches
	s.False(r.isActive(MatchRequest{UA: "Mozilla/5.0", Platform: "iOS"}))
}

func (s *FilterSuite) TestUAExclude() {
	r := TrafficRule{
		Name:      "block-all-bots",
		Action:    "block",
		UAPrefix:  []string{"Bot/"},
		UAExclude: []string{"Bot/Good"},
	}

	s.True(r.isActive(MatchRequest{UA: "Bot/Evil"}))
	s.False(r.isActive(MatchRequest{UA: "Bot/Good"}))
}

func (s *FilterSuite) TestEmptyRule_NeverMatches() {
	r := TrafficRule{Name: "empty", Action: "block"}
	s.False(r.isActive(MatchRequest{UA: "anything", IP: "1.2.3.4"}))
}

func (s *FilterSuite) TestUAPrefix_SubstringNoMatch() {
	// UAPrefix must match only at the beginning of the UA string
	r := TrafficRule{Name: "headless", Action: "block", UAPrefix: []string{"HeadlessChrome"}}
	s.False(r.isActive(MatchRequest{UA: "Mozilla/5.0 (X11; Linux x86_64) HeadlessChrome/91.0"}))
	s.True(r.isActive(MatchRequest{UA: "HeadlessChrome/91.0"}))
}

func (s *FilterSuite) TestDynamic_AddRemoveList() {
	f := New(
		[]TrafficRule{{Name: "static-rule", Action: "block", UAPrefix: []string{"Python/"}}},
		embedlog.NewLogger(false, false), Metrics{MatchedTotal: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "test_total", Help: "test"}, []string{"rule", "action"})},
	)

	// list shows static only
	rules := f.ListRules()
	s.Len(rules, 1)
	s.Equal("config", rules[0].Source)

	// add dynamic
	s.Require().NoError(f.AddRule(TrafficRule{Name: "dyn-1", Action: "captcha", Country: []string{"CN"}}))

	rules = f.ListRules()
	s.Len(rules, 2)
	s.Equal("api", rules[1].Source)

	// duplicate name
	s.Require().Error(f.AddRule(TrafficRule{Name: "dyn-1", Action: "block"}))

	// empty name
	s.Require().Error(f.AddRule(TrafficRule{Action: "block"}))

	// remove
	s.Require().NoError(f.RemoveRule("dyn-1"))
	s.Len(f.ListRules(), 1)

	// remove non-existent
	s.Error(f.RemoveRule("no-such"))
}

func (s *FilterSuite) TestTestRequest() {
	f := New(
		[]TrafficRule{
			{Name: "python", Action: "block", UAPrefix: []string{"Python/"}},
			{Name: "geo", Action: "captcha", Country: []string{"CN"}},
		},
		embedlog.NewLogger(false, false), Metrics{MatchedTotal: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "test2_total", Help: "test"}, []string{"rule", "action"})},
	)

	_ = f.AddRule(TrafficRule{Name: "dyn-curl", Action: "log", UAPrefix: []string{"curl/"}})

	matches := f.TestRequest(MatchRequest{UA: "Python/3.9", Country: "CN"})
	s.Len(matches, 2)
	s.Equal("python", matches[0].Name)
	s.Equal("config", matches[0].Source)
	s.Equal("geo", matches[1].Name)

	matches = f.TestRequest(MatchRequest{UA: "curl/7.68"})
	s.Len(matches, 1)
	s.Equal("dyn-curl", matches[0].Name)
	s.Equal("api", matches[0].Source)

	matches = f.TestRequest(MatchRequest{UA: "Mozilla/5.0", Country: "US"})
	s.Empty(matches)
}

func BenchmarkFilterMatch(b *testing.B) {
	rules := []TrafficRule{
		{Name: "python", Action: "block", UAPrefix: []string{"Python/"}},
		{Name: "geo", Action: "captcha", Country: []string{"CN", "KP", "IR"}},
		{Name: "admin", Action: "block", Path: []string{"/admin", "/.env", "/.git"}},
		{Name: "curl", Action: "log", UAPrefix: []string{"curl/"}},
		{Name: "scanner", Action: "block", UAExact: []string{"Nmap", "sqlmap", "nikto"}},
		{Name: "seo-bots", Action: "captcha", UAContains: []string{"SemrushBot", "AhrefsBot"}},
		{Name: "hosting", Action: "captcha", ASN: []uint32{14061, 16509, 24940}},
		{Name: "admin-rpc", Action: "block", RPCMethod: []string{"admin."}},
		{Name: "bad-ref", Action: "log", Referer: []string{"https://evil-site.com"}},
	}

	req := MatchRequest{
		IP:         "8.8.8.8",
		UA:         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		Country:    "US",
		Platform:   "web",
		Version:    "2.5.0",
		Host:       "api.example.com",
		Path:       "/rpc/",
		Method:     "POST",
		ASN:        15169,
		RPCMethods: []string{"auth.login"},
		Referer:    "https://example.com/page",
	}

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		for i := range rules {
			rules[i].isActive(req)
		}
	}
}

func BenchmarkFilterMatchHit(b *testing.B) {
	rule := TrafficRule{
		Name:     "multi",
		Action:   "block",
		Platform: []string{"Android"},
		UAPrefix: []string{"okhttp"},
		Country:  []string{"CN"},
	}

	req := MatchRequest{UA: "okhttp/4.9", Platform: "Android", Country: "CN"}

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		rule.isActive(req)
	}
}

func (s *FilterSuite) TestUAContains() {
	r := TrafficRule{Name: "semrush", Action: "block", UAContains: []string{"SemrushBot", "AhrefsBot"}}
	s.True(r.isActive(MatchRequest{UA: "Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)"}))
	s.True(r.isActive(MatchRequest{UA: "Mozilla/5.0 (compatible; AhrefsBot/7.0)"}))
	s.False(r.isActive(MatchRequest{UA: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}))
}

func (s *FilterSuite) TestUAContains_NotPrefix() {
	r := TrafficRule{Name: "headless", Action: "block", UAContains: []string{"HeadlessChrome"}}
	// substring in the middle — should match (unlike UAPrefix)
	s.True(r.isActive(MatchRequest{UA: "Mozilla/5.0 (X11; Linux x86_64) HeadlessChrome/91.0"}))
	s.True(r.isActive(MatchRequest{UA: "HeadlessChrome/91.0"}))
	s.False(r.isActive(MatchRequest{UA: "Mozilla/5.0 Chrome/91.0"}))
}

func (s *FilterSuite) TestASN() {
	r := TrafficRule{Name: "hosting", Action: "captcha", ASN: []uint32{14061, 16509, 24940}}
	s.True(r.isActive(MatchRequest{ASN: 14061}))
	s.True(r.isActive(MatchRequest{ASN: 16509}))
	s.True(r.isActive(MatchRequest{ASN: 24940}))
}

func (s *FilterSuite) TestASN_NoMatch() {
	r := TrafficRule{Name: "hosting", Action: "captcha", ASN: []uint32{14061, 16509}}
	s.False(r.isActive(MatchRequest{ASN: 99999}))
	s.False(r.isActive(MatchRequest{ASN: 0}))
}

func (s *FilterSuite) TestRPCMethod_Exact() {
	r := TrafficRule{Name: "admin", Action: "block", RPCMethod: []string{"auth.login"}}
	s.True(r.isActive(MatchRequest{RPCMethods: []string{"auth.login"}}))
	s.False(r.isActive(MatchRequest{RPCMethods: []string{"auth.logout"}}))
}

func (s *FilterSuite) TestRPCMethod_Prefix() {
	r := TrafficRule{Name: "admin-ns", Action: "block", RPCMethod: []string{"admin."}}
	s.True(r.isActive(MatchRequest{RPCMethods: []string{"admin.users"}}))
	s.True(r.isActive(MatchRequest{RPCMethods: []string{"admin.deleteAll"}}))
	s.False(r.isActive(MatchRequest{RPCMethods: []string{"auth.login"}}))
}

func (s *FilterSuite) TestRPCMethod_Batch() {
	r := TrafficRule{Name: "admin-batch", Action: "block", RPCMethod: []string{"admin."}}
	// batch with mixed methods — should match if any method matches
	s.True(r.isActive(MatchRequest{RPCMethods: []string{"auth.login", "admin.users"}}))
	s.False(r.isActive(MatchRequest{RPCMethods: []string{"auth.login", "status.get"}}))
}

func (s *FilterSuite) TestRPCMethod_EmptyMethods() {
	r := TrafficRule{Name: "admin", Action: "block", RPCMethod: []string{"admin."}}
	s.False(r.isActive(MatchRequest{RPCMethods: nil}))
	s.False(r.isActive(MatchRequest{RPCMethods: []string{}}))
}

func (s *FilterSuite) TestReferer_Prefix() {
	r := TrafficRule{Name: "bad-ref", Action: "log", Referer: []string{"https://evil-site.com"}}
	s.True(r.isActive(MatchRequest{Referer: "https://evil-site.com/page"}))
	s.True(r.isActive(MatchRequest{Referer: "https://evil-site.com"}))
	s.False(r.isActive(MatchRequest{Referer: "https://good-site.com"}))
	s.False(r.isActive(MatchRequest{Referer: ""}))
}

func (s *FilterSuite) TestMultiField_ASN_Country() {
	r := TrafficRule{
		Name:    "datacenter-cn",
		Action:  "block",
		ASN:     []uint32{14061, 16509},
		Country: []string{"CN"},
	}

	s.True(r.isActive(MatchRequest{ASN: 14061, Country: "CN"}))
	s.False(r.isActive(MatchRequest{ASN: 14061, Country: "US"}))
	s.False(r.isActive(MatchRequest{ASN: 99999, Country: "CN"}))
}

func (s *FilterSuite) TestTripleField_AND() {
	r := TrafficRule{
		Name:     "specific",
		Action:   "block",
		Platform: []string{"Desktop"},
		Version:  []string{"149bd482"},
		Method:   []string{"POST"},
	}

	s.True(r.isActive(MatchRequest{Platform: "Desktop", Version: "149bd482", Method: "POST"}))
	s.False(r.isActive(MatchRequest{Platform: "Desktop", Version: "149bd482", Method: "GET"}))
	s.False(r.isActive(MatchRequest{Platform: "Mobile", Version: "149bd482", Method: "POST"}))
}
