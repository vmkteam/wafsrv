package event

import (
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

type LatencySuite struct {
	suite.Suite
}

func TestLatency(t *testing.T) {
	suite.Run(t, new(LatencySuite))
}

func (s *LatencySuite) TestRecordAndSnapshot() {
	t := NewLatencyTracker()

	t.Record("backend:3000", 10*time.Millisecond)
	t.Record("backend:3000", 20*time.Millisecond)
	t.Record("backend:3001", 5*time.Millisecond)

	snap := t.Snapshot()
	s.Len(snap, 2)

	// sorted by count desc
	s.Equal("backend:3000", snap[0].Key)
	s.Equal(int64(2), snap[0].Count)
	s.InDelta(15.0, snap[0].AvgMs, 0.1)
	s.InDelta(20.0, snap[0].MaxMs, 0.1)

	s.Equal("backend:3001", snap[1].Key)
	s.Equal(int64(1), snap[1].Count)
}

func (s *LatencySuite) TestP95() {
	t := NewLatencyTracker()

	// 100 samples: 1ms, 2ms, ..., 100ms
	for i := 1; i <= 100; i++ {
		t.Record("api", time.Duration(i)*time.Millisecond)
	}

	snap := t.Snapshot()
	s.Require().Len(snap, 1)

	// P95 of 1..100 should be ~95ms
	s.InDelta(95.0, snap[0].P95Ms, 1.0)
	s.InDelta(100.0, snap[0].MaxMs, 0.1)
	s.InDelta(50.5, snap[0].AvgMs, 0.1)
}

func (s *LatencySuite) TestRingOverflow() {
	t := NewLatencyTracker()

	// fill ring (100) + 50 more
	for i := 1; i <= 150; i++ {
		t.Record("api", time.Duration(i)*time.Millisecond)
	}

	snap := t.Snapshot()
	s.Require().Len(snap, 1)
	s.Equal(int64(150), snap[0].Count)

	// P95 should be based on last 100 samples (51..150)
	s.InDelta(145.0, snap[0].P95Ms, 2.0)
}

func (s *LatencySuite) TestReset() {
	t := NewLatencyTracker()
	t.Record("api", 10*time.Millisecond)

	t.Reset()

	snap := t.Snapshot()
	s.Empty(snap)
}

func (s *LatencySuite) TestEmptySnapshot() {
	t := NewLatencyTracker()
	s.Empty(t.Snapshot())
}
