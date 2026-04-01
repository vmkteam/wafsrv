package ip

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/suite"
	"github.com/vmkteam/embedlog"
)

type ReputationSuite struct {
	suite.Suite
}

func TestReputationSuite(t *testing.T) {
	suite.Run(t, new(ReputationSuite))
}

func (s *ReputationSuite) TestParseFeed() {
	body := `# comment line
; another comment
1.2.3.4
5.6.7.8

10.0.0.0/24
# trailing comment
192.168.1.1
invalid-line
2001:db8::1
`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	}))
	defer srv.Close()

	client := &http.Client{}
	addrs, prefixes, err := parseFeed(context.Background(), client, srv.URL)
	s.Require().NoError(err)

	s.Len(addrs, 4, "should parse 4 IP addresses (1.2.3.4, 5.6.7.8, 192.168.1.1, 2001:db8::1)")
	s.Len(prefixes, 1, "should parse 1 CIDR prefix (10.0.0.0/24)")

	_, ok1 := addrs[netip.MustParseAddr("1.2.3.4")]
	_, ok2 := addrs[netip.MustParseAddr("5.6.7.8")]
	_, ok3 := addrs[netip.MustParseAddr("192.168.1.1")]
	s.True(ok1)
	s.True(ok2)
	s.True(ok3)
	s.Equal(netip.MustParsePrefix("10.0.0.0/24"), prefixes[0])
}

func (s *ReputationSuite) TestParseFeedIPv6() {
	body := "2001:db8::1\n2001:db8::/32\n"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	}))
	defer srv.Close()

	client := &http.Client{}
	addrs, prefixes, err := parseFeed(context.Background(), client, srv.URL)
	s.Require().NoError(err)

	s.Len(addrs, 1)
	s.Len(prefixes, 1)
	_, ok := addrs[netip.MustParseAddr("2001:db8::1")]
	s.True(ok)
}

func (s *ReputationSuite) TestParseFeedHTTPError() {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	client := &http.Client{}
	_, _, err := parseFeed(context.Background(), client, srv.URL)
	s.Require().Error(err)
	s.Contains(err.Error(), "status 500")
}

func (s *ReputationSuite) TestCheck() {
	r := NewReputation(ReputationConfig{
		Enabled:         true,
		UpdateInterval:  1,
		ScoreAdjustment: 3.0,
	}, embedlog.NewLogger(false, false))

	// manually populate feed
	r.mu.Lock()
	r.feeds["test_feed"] = &feedData{
		name:   "test_feed",
		action: FeedActionScore,
		score:  3.0,
		addrs: map[netip.Addr]struct{}{
			netip.MustParseAddr("1.2.3.4"): {},
			netip.MustParseAddr("5.6.7.8"): {},
		},
		prefixes: []netip.Prefix{
			netip.MustParsePrefix("10.0.0.0/24"),
		},
	}
	r.mu.Unlock()

	// listed IP (exact match)
	result := r.Check(netip.MustParseAddr("1.2.3.4"))
	s.True(result.Listed)
	s.Equal([]string{"test_feed"}, result.Feeds)
	s.Equal(FeedActionScore, result.Action)
	s.InEpsilon(3.0, result.Score, 0.01)

	// listed IP (CIDR match)
	result = r.Check(netip.MustParseAddr("10.0.0.42"))
	s.True(result.Listed)

	// not listed IP
	result = r.Check(netip.MustParseAddr("8.8.8.8"))
	s.False(result.Listed)
	s.Empty(result.Feeds)
}

func (s *ReputationSuite) TestCheckMultipleFeeds() {
	r := NewReputation(ReputationConfig{
		Enabled:         true,
		UpdateInterval:  1,
		ScoreAdjustment: 3.0,
	}, embedlog.NewLogger(false, false))

	r.mu.Lock()
	r.feeds["feed_a"] = &feedData{
		name:   "feed_a",
		action: FeedActionScore,
		score:  3.0,
		addrs:  map[netip.Addr]struct{}{netip.MustParseAddr("1.2.3.4"): {}},
	}
	r.feeds["feed_b"] = &feedData{
		name:   "feed_b",
		action: FeedActionBlock,
		score:  3.0,
		addrs:  map[netip.Addr]struct{}{netip.MustParseAddr("1.2.3.4"): {}},
	}
	r.mu.Unlock()

	result := r.Check(netip.MustParseAddr("1.2.3.4"))
	s.True(result.Listed)
	s.Len(result.Feeds, 2)
	s.Equal(FeedActionBlock, result.Action, "should pick most severe action")
	s.InEpsilon(6.0, result.Score, 0.01, "should sum scores")
}

func (s *ReputationSuite) TestCheckASN() {
	r := NewReputation(ReputationConfig{
		Enabled: true,
		Datacenter: DatacenterReputationConfig{
			Enabled:   true,
			ExtraASNs: []uint32{99999},
		},
	}, embedlog.NewLogger(false, false))

	// known datacenter ASN
	s.True(r.CheckASN(14618), "AWS ASN should be datacenter")
	s.True(r.CheckASN(24940), "Hetzner ASN should be datacenter")

	// extra ASN from config
	s.True(r.CheckASN(99999), "extra ASN should be datacenter")

	// unknown ASN
	s.False(r.CheckASN(12345), "unknown ASN should not be datacenter")

	// zero ASN
	s.False(r.CheckASN(0))
}

func (s *ReputationSuite) TestCheckASNDisabled() {
	r := NewReputation(ReputationConfig{
		Enabled: true,
		Datacenter: DatacenterReputationConfig{
			Enabled: false,
		},
	}, embedlog.NewLogger(false, false))

	s.False(r.CheckASN(14618), "should return false when datacenter detection disabled")
}

func (s *ReputationSuite) TestActionSeverity() {
	s.Equal(FeedActionBlock, moreSevereAction(FeedActionScore, FeedActionBlock))
	s.Equal(FeedActionBlock, moreSevereAction(FeedActionBlock, FeedActionScore))
	s.Equal(FeedActionCaptcha, moreSevereAction(FeedActionScore, FeedActionCaptcha))
	s.Equal(FeedActionBlock, moreSevereAction(FeedActionCaptcha, FeedActionBlock))
	s.Equal(FeedActionScore, moreSevereAction("", FeedActionScore))
}

func (s *ReputationSuite) TestStats() {
	r := NewReputation(ReputationConfig{
		Enabled:        true,
		UpdateInterval: 1,
	}, embedlog.NewLogger(false, false))

	r.mu.Lock()
	r.feeds["feed1"] = &feedData{
		name:  "feed1",
		addrs: map[netip.Addr]struct{}{netip.MustParseAddr("1.1.1.1"): {}},
		prefixes: []netip.Prefix{
			netip.MustParsePrefix("10.0.0.0/8"),
		},
	}
	r.mu.Unlock()

	stats := r.Stats()
	s.Len(stats, 1)
	s.Equal("feed1", stats[0].Name)
	s.Equal(2, stats[0].Count) // 1 addr + 1 prefix
}

func (s *ReputationSuite) TestLoadFeed() {
	body := "1.2.3.4\n5.6.7.8\n10.0.0.0/24\n"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	}))
	defer srv.Close()

	r := NewReputation(ReputationConfig{
		Enabled:         true,
		UpdateInterval:  1,
		ScoreAdjustment: 3.0,
	}, embedlog.NewLogger(false, false))

	r.loadFeed(context.Background(), "test", srv.URL, FeedActionScore, 3.0)

	result := r.Check(netip.MustParseAddr("1.2.3.4"))
	s.True(result.Listed)

	result = r.Check(netip.MustParseAddr("10.0.0.100"))
	s.True(result.Listed)

	result = r.Check(netip.MustParseAddr("8.8.8.8"))
	s.False(result.Listed)
}

func BenchmarkReputation_Check(b *testing.B) {
	r := NewReputation(ReputationConfig{
		Enabled:         true,
		UpdateInterval:  1,
		ScoreAdjustment: 3.0,
	}, embedlog.NewLogger(false, false))

	// populate with 50K IPs
	addrs := make(map[netip.Addr]struct{}, 50000)
	for i := range 50000 {
		a := byte(i >> 16)
		bb := byte(i >> 8)
		c := byte(i)
		addr := netip.AddrFrom4([4]byte{10, a, bb, c})
		addrs[addr] = struct{}{}
	}

	r.mu.Lock()
	r.feeds["bench"] = &feedData{
		name:   "bench",
		action: FeedActionScore,
		score:  3.0,
		addrs:  addrs,
	}
	r.mu.Unlock()

	// lookup existing IP
	target := netip.MustParseAddr("10.0.100.50")

	b.ResetTimer()

	for b.Loop() {
		r.Check(target)
	}
}

func BenchmarkReputation_CheckASN(b *testing.B) {
	r := NewReputation(ReputationConfig{
		Enabled: true,
		Datacenter: DatacenterReputationConfig{
			Enabled: true,
		},
	}, embedlog.NewLogger(false, false))

	b.ResetTimer()

	for b.Loop() {
		r.CheckASN(14618)
	}
}
