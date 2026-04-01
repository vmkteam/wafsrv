package ip

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/suite"
	"github.com/vmkteam/embedlog"
)

type BotRangesSuite struct {
	suite.Suite
}

func TestBotRanges(t *testing.T) {
	suite.Run(t, new(BotRangesSuite))
}

func (s *BotRangesSuite) TestFetchRanges_Google() {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"prefixes":[{"ipv4Prefix":"66.249.64.0/19"},{"ipv6Prefix":"2001:4860:4801::/48"},{"ipv4Prefix":"209.85.238.0/24"}]}`))
	}))
	defer srv.Close()

	sl := embedlog.NewLogger(false, false)
	r := NewBotRanges(sl)

	prefixes, err := r.fetchRanges(srv.URL)
	s.Require().NoError(err)
	s.Len(prefixes, 3)
	s.Equal(netip.MustParsePrefix("66.249.64.0/19"), prefixes[0])
	s.Equal(netip.MustParsePrefix("2001:4860:4801::/48"), prefixes[1])
	s.Equal(netip.MustParsePrefix("209.85.238.0/24"), prefixes[2])
}

func (s *BotRangesSuite) TestFetchRanges_Empty() {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"prefixes":[]}`))
	}))
	defer srv.Close()

	sl := embedlog.NewLogger(false, false)
	r := NewBotRanges(sl)

	prefixes, err := r.fetchRanges(srv.URL)
	s.Require().NoError(err)
	s.Empty(prefixes)
}

func (s *BotRangesSuite) TestFetchRanges_ServerError() {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	sl := embedlog.NewLogger(false, false)
	r := NewBotRanges(sl)

	_, err := r.fetchRanges(srv.URL)
	s.Require().Error(err)
	s.Contains(err.Error(), "status 500")
}

func (s *BotRangesSuite) TestFetchRanges_InvalidJSON() {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`not json`))
	}))
	defer srv.Close()

	sl := embedlog.NewLogger(false, false)
	r := NewBotRanges(sl)

	_, err := r.fetchRanges(srv.URL)
	s.Require().Error(err)
}

func (s *BotRangesSuite) TestContains() {
	sl := embedlog.NewLogger(false, false)
	r := NewBotRanges(sl)

	r.mu.Lock()
	r.ranges["google"] = []netip.Prefix{
		netip.MustParsePrefix("66.249.64.0/19"),
		netip.MustParsePrefix("209.85.238.0/24"),
	}
	r.ranges["bing"] = []netip.Prefix{
		netip.MustParsePrefix("157.55.39.0/24"),
	}
	r.mu.Unlock()

	name, ok := r.Contains(netip.MustParseAddr("66.249.66.1"))
	s.True(ok)
	s.Equal("google", name)

	name, ok = r.Contains(netip.MustParseAddr("157.55.39.100"))
	s.True(ok)
	s.Equal("bing", name)

	_, ok = r.Contains(netip.MustParseAddr("1.2.3.4"))
	s.False(ok)
}

func (s *BotRangesSuite) TestContains_Empty() {
	sl := embedlog.NewLogger(false, false)
	r := NewBotRanges(sl)

	_, ok := r.Contains(netip.MustParseAddr("66.249.66.1"))
	s.False(ok)
}

func (s *BotRangesSuite) TestRefreshAll_KeepsOldOnError() {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCount++
		if callCount == 1 {
			_, _ = w.Write([]byte(`{"prefixes":[{"ipv4Prefix":"66.249.64.0/19"}]}`))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	sl := embedlog.NewLogger(false, false)
	r := NewBotRanges(sl)

	bots := []KnownBot{{Name: "test", RangesURL: srv.URL}}

	// first refresh — success
	r.refreshAll(bots)
	s.Len(r.ranges["test"], 1)

	// second refresh — error → keep old
	r.refreshAll(bots)
	s.Len(r.ranges["test"], 1, "should keep old ranges on error")
}
