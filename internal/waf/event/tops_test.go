package event

import (
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

type TopsSuite struct {
	suite.Suite
}

func TestTops(t *testing.T) {
	suite.Run(t, new(TopsSuite))
}

func (s *TopsSuite) TestRecord_And_TopIPs() {
	t := NewTops(5*time.Minute, 100)

	t.Record("1.1.1.1", "/", "US", "")
	t.Record("1.1.1.1", "/", "US", "")
	t.Record("1.1.1.1", "/", "US", "")
	t.Record("2.2.2.2", "/api", "DE", "")
	t.Record("2.2.2.2", "/api", "DE", "")
	t.Record("3.3.3.3", "/rpc", "", "")

	top := t.TopIPs(2)
	s.Len(top, 2)
	s.Equal("1.1.1.1", top[0].Key)
	s.Equal(int64(3), top[0].Total)
	s.Equal(int64(0), top[0].Blocked)
	s.Equal("2.2.2.2", top[1].Key)
	s.Equal(int64(2), top[1].Total)
}

func (s *TopsSuite) TestRecordBlocked() {
	t := NewTops(5*time.Minute, 100)

	t.Record("1.1.1.1", "/", "US", "")
	t.Record("1.1.1.1", "/", "US", "")
	t.RecordBlocked("1.1.1.1", "/", "US", "")

	top := t.TopIPs(10)
	s.Len(top, 1)
	s.Equal(int64(3), top[0].Total)
	s.Equal(int64(1), top[0].Blocked)
}

func (s *TopsSuite) TestTopPaths() {
	t := NewTops(5*time.Minute, 100)

	t.Record("1.1.1.1", "/rpc/", "US", "")
	t.Record("1.1.1.1", "/rpc/", "US", "")
	t.Record("1.1.1.1", "/assets/app.js", "US", "")

	top := t.TopPaths(10)
	s.Len(top, 2)
	s.Equal("/rpc/", top[0].Key)
	s.Equal(int64(2), top[0].Total)
}

func (s *TopsSuite) TestTopCountries_EmptySkipped() {
	t := NewTops(5*time.Minute, 100)

	t.Record("1.1.1.1", "/", "US", "")
	t.Record("2.2.2.2", "/", "", "") // no country
	t.Record("3.3.3.3", "/", "DE", "")
	t.Record("4.4.4.4", "/", "DE", "")

	top := t.TopCountries(10)
	s.Len(top, 2)
	s.Equal("DE", top[0].Key)
	s.Equal(int64(2), top[0].Total)
}

func (s *TopsSuite) TestWindowReset() {
	t := NewTops(1*time.Millisecond, 100)

	t.Record("1.1.1.1", "/", "US", "")
	s.Len(t.TopIPs(10), 1)

	time.Sleep(5 * time.Millisecond)

	// after window expired, should be empty
	s.Empty(t.TopIPs(10))
}

func (s *TopsSuite) TestMaxKeys() {
	t := NewTops(5*time.Minute, 3)

	t.Record("1.1.1.1", "/", "US", "")
	t.Record("2.2.2.2", "/", "DE", "")
	t.Record("3.3.3.3", "/", "FR", "")
	t.Record("4.4.4.4", "/", "JP", "") // should be dropped

	top := t.TopIPs(10)
	s.Len(top, 3) // capped at maxKeys
}

func (s *TopsSuite) TestTopN_LimitOutput() {
	t := NewTops(5*time.Minute, 100)

	for i := range 10 {
		ip := "10.0.0." + itoa(i)
		for range i + 1 {
			t.Record(ip, "/", "US", "")
		}
	}

	top := t.TopIPs(3)
	s.Len(top, 3)
	s.Equal(int64(10), top[0].Total)
}

func (s *TopsSuite) TestTopBlockedIPs() {
	t := NewTops(5*time.Minute, 100)

	t.Record("1.1.1.1", "/", "US", "")
	t.Record("1.1.1.1", "/", "US", "")
	t.RecordBlocked("2.2.2.2", "/", "DE", "")
	t.RecordBlocked("2.2.2.2", "/", "DE", "")
	t.RecordBlocked("3.3.3.3", "/", "FR", "")

	top := t.TopBlockedIPs(10)
	s.Len(top, 2) // 1.1.1.1 excluded (0 blocked)
	s.Equal("2.2.2.2", top[0].Key)
	s.Equal(int64(2), top[0].Blocked)
	s.Equal("3.3.3.3", top[1].Key)
	s.Equal(int64(1), top[1].Blocked)
}

func (s *TopsSuite) TestTopUserAgents() {
	t := NewTops(5*time.Minute, 100)

	t.RecordUA("Mozilla/5.0")
	t.RecordUA("Mozilla/5.0")
	t.RecordUA("curl/7.64")

	top := t.TopUserAgents(10)
	s.Len(top, 2)
	s.Equal("Mozilla/5.0", top[0].Key)
	s.Equal(int64(2), top[0].Total)
}

func (s *TopsSuite) TestTopReferers() {
	t := NewTops(5*time.Minute, 100)

	t.RecordReferer("https://example.com")
	t.RecordReferer("https://example.com")
	t.RecordReferer("https://other.com")

	top := t.TopReferers(10)
	s.Len(top, 2)
	s.Equal("https://example.com", top[0].Key)
}

func (s *TopsSuite) TestTopRPCMethods() {
	t := NewTops(5*time.Minute, 100)

	t.RecordRPCMethod("auth.login")
	t.RecordRPCMethod("auth.login")
	t.RecordRPCMethod("auth.login")
	t.RecordRPCMethod("user.get")

	top := t.TopRPCMethods(10)
	s.Len(top, 2)
	s.Equal("auth.login", top[0].Key)
	s.Equal(int64(3), top[0].Total)
}

func (s *TopsSuite) TestTopASNs() {
	t := NewTops(5*time.Minute, 100)

	t.RecordASN("Amazon.com Inc.")
	t.RecordASN("Amazon.com Inc.")
	t.RecordASN("Google LLC")

	top := t.TopASNs(10)
	s.Len(top, 2)
	s.Equal("Amazon.com Inc.", top[0].Key)
}

func (s *TopsSuite) TestTopSignResults() {
	t := NewTops(5*time.Minute, 100)

	t.RecordSignResult("valid")
	t.RecordSignResult("valid")
	t.RecordSignResult("unsigned")
	t.RecordSignResult("invalid")

	top := t.TopSignResults(10)
	s.Len(top, 3)
	s.Equal("valid", top[0].Key)
	s.Equal(int64(2), top[0].Total)
}

func (s *TopsSuite) TestTopDecisions() {
	t := NewTops(5*time.Minute, 100)

	t.RecordDecision("pass")
	t.RecordDecision("pass")
	t.RecordDecision("pass")
	t.RecordDecision("captcha")
	t.RecordDecision("block")

	top := t.TopDecisions(10)
	s.Len(top, 3)
	s.Equal("pass", top[0].Key)
	s.Equal(int64(3), top[0].Total)
}

func (s *TopsSuite) TestEmptyKey_Skipped() {
	t := NewTops(5*time.Minute, 100)

	t.RecordUA("")
	t.RecordReferer("")
	t.RecordRPCMethod("")
	t.RecordASN("")

	s.Empty(t.TopUserAgents(10))
	s.Empty(t.TopReferers(10))
	s.Empty(t.TopRPCMethods(10))
	s.Empty(t.TopASNs(10))
}

func itoa(i int) string {
	return []string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9"}[i]
}
