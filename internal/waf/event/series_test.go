package event

import (
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

type SeriesSuite struct {
	suite.Suite
}

func TestSeries(t *testing.T) {
	suite.Run(t, new(SeriesSuite))
}

func (s *SeriesSuite) TestRecordAndHistory() {
	sr := NewSeries(time.Second, 10)

	sr.RecordRequest(false)
	sr.RecordRequest(true)
	sr.RecordBlocked()

	// force tick
	time.Sleep(1100 * time.Millisecond)
	sr.RecordRequest(false)

	h := sr.History(10)
	s.Require().NotEmpty(h)

	// first completed point should have 2 requests, 1 error, 1 blocked
	s.Equal(int64(2), h[0].Requests)
	s.Equal(int64(1), h[0].Errors5xx)
	s.Equal(int64(1), h[0].Blocked)
}

func (s *SeriesSuite) TestRPS() {
	sr := NewSeries(2*time.Second, 10)

	// wait for a clean slot boundary
	time.Sleep(time.Duration(2000-time.Now().UnixMilli()%2000) * time.Millisecond)

	for range 100 {
		sr.RecordRequest(false)
	}

	// wait for the next slot to flush
	time.Sleep(2200 * time.Millisecond)
	sr.RecordRequest(false) // trigger tick

	rps := sr.RPS()
	s.InDelta(50.0, rps, 1.0) // 100 requests / 2s interval = 50 RPS
}

func (s *SeriesSuite) TestHistoryLimit() {
	sr := NewSeries(time.Second, 10)

	sr.RecordRequest(false)
	time.Sleep(1100 * time.Millisecond)
	sr.RecordRequest(false)
	time.Sleep(1100 * time.Millisecond)
	sr.RecordRequest(false)
	time.Sleep(1100 * time.Millisecond)
	sr.RecordRequest(false) // trigger tick

	h := sr.History(2)
	s.Len(h, 2)
}

func BenchmarkSeriesRecord(b *testing.B) {
	sr := NewSeries(5*time.Second, 360)

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		sr.RecordRequest(false)
	}
}

func BenchmarkSeriesRecordParallel(b *testing.B) {
	sr := NewSeries(5*time.Second, 360)

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			sr.RecordRequest(false)
		}
	})
}

func BenchmarkRecorderHotPath(b *testing.B) {
	rec := NewRecorder(
		NewBuffer(1000),
		NewSeries(5*time.Second, 360),
		NewTops(5*time.Minute, 10000),
	)

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		rec.RecordIncoming()
	}
}

func BenchmarkRecorderTops(b *testing.B) {
	rec := NewRecorder(
		NewBuffer(1000),
		NewSeries(5*time.Second, 360),
		NewTops(5*time.Minute, 10000),
	)

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		rec.RecordTops("1.2.3.4", "/rpc/", "US", "", false)
	}
}

func (s *SeriesSuite) TestEmptyHistory() {
	sr := NewSeries(time.Second, 10)
	h := sr.History(10)
	s.Empty(h)
}

func (s *SeriesSuite) TestRecordTypes() {
	sr := NewSeries(time.Second, 10)

	sr.RecordRateLimited()
	sr.RecordCaptcha()
	sr.RecordWAFMatch()

	time.Sleep(1100 * time.Millisecond)
	sr.RecordRequest(false)

	h := sr.History(10)
	s.Require().NotEmpty(h)
	s.Equal(int64(1), h[0].RateLimited)
	s.Equal(int64(1), h[0].Captcha)
	s.Equal(int64(1), h[0].WAFMatches)
}
