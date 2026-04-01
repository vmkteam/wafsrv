package proxy

import (
	"net/http"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/suite"
)

type RealIPSuite struct {
	suite.Suite
	trusted []netip.Prefix
}

func TestRealIP(t *testing.T) {
	suite.Run(t, new(RealIPSuite))
}

func (s *RealIPSuite) SetupSuite() {
	var err error
	s.trusted, err = ParseTrustedProxies([]string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"})
	s.Require().NoError(err)
}

func (s *RealIPSuite) TestXRealIP() {
	r := s.newRequest()
	r.Header.Set("X-Real-IP", "1.2.3.4")
	r.RemoteAddr = "10.0.0.1:12345"

	ip := ExtractIP(r, []string{"X-Real-IP", "X-Forwarded-For"}, s.trusted)
	s.Equal(netip.MustParseAddr("1.2.3.4"), ip, "should use X-Real-IP header")
}

func (s *RealIPSuite) TestXForwardedForSingle() {
	r := s.newRequest()
	r.Header.Set("X-Forwarded-For", "5.6.7.8")
	r.RemoteAddr = "10.0.0.1:12345"

	ip := ExtractIP(r, []string{"X-Real-IP", "X-Forwarded-For"}, s.trusted)
	s.Equal(netip.MustParseAddr("5.6.7.8"), ip, "should use single XFF value")
}

func (s *RealIPSuite) TestXForwardedForChain() {
	r := s.newRequest()
	r.Header.Set("X-Forwarded-For", "1.1.1.1, 10.0.0.5, 192.168.1.1")
	r.RemoteAddr = "10.0.0.1:12345"

	ip := ExtractIP(r, []string{"X-Real-IP", "X-Forwarded-For"}, s.trusted)
	s.Equal(netip.MustParseAddr("1.1.1.1"), ip, "should return rightmost non-trusted IP from XFF chain")
}

func (s *RealIPSuite) TestXForwardedForAllTrusted() {
	r := s.newRequest()
	r.Header.Set("X-Forwarded-For", "10.0.0.5, 192.168.1.1")
	r.RemoteAddr = "10.0.0.1:12345"

	ip := ExtractIP(r, []string{"X-Forwarded-For"}, s.trusted)
	s.Equal(netip.MustParseAddr("10.0.0.1"), ip, "should fall back to RemoteAddr when all XFF IPs are trusted")
}

func (s *RealIPSuite) TestFallbackToRemoteAddr() {
	r := s.newRequest()
	r.RemoteAddr = "9.8.7.6:54321"

	ip := ExtractIP(r, []string{"X-Real-IP", "X-Forwarded-For"}, s.trusted)
	s.Equal(netip.MustParseAddr("9.8.7.6"), ip, "should fall back to RemoteAddr when no headers set")
}

func (s *RealIPSuite) TestHeaderPriority() {
	r := s.newRequest()
	r.Header.Set("X-Real-IP", "1.1.1.1")
	r.Header.Set("X-Forwarded-For", "2.2.2.2")
	r.RemoteAddr = "10.0.0.1:12345"

	ip := ExtractIP(r, []string{"X-Real-IP", "X-Forwarded-For"}, s.trusted)
	s.Equal(netip.MustParseAddr("1.1.1.1"), ip, "should respect header priority order")
}

func (s *RealIPSuite) TestIPv6() {
	r := s.newRequest()
	r.Header.Set("X-Real-IP", "2001:db8::1")
	r.RemoteAddr = "[::1]:12345"

	ip := ExtractIP(r, []string{"X-Real-IP"}, s.trusted)
	s.Equal(netip.MustParseAddr("2001:db8::1"), ip, "should handle IPv6 addresses")
}

func (s *RealIPSuite) TestParseTrustedProxiesInvalid() {
	_, err := ParseTrustedProxies([]string{"not-a-cidr"})
	s.Error(err, "should return error for invalid CIDR")
}

func (s *RealIPSuite) newRequest() *http.Request {
	r, err := http.NewRequest(http.MethodGet, "/", nil)
	s.Require().NoError(err)
	return r
}
