package event

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type ErrorTrackerSuite struct {
	suite.Suite
}

func TestErrorTracker(t *testing.T) {
	suite.Run(t, new(ErrorTrackerSuite))
}

func (s *ErrorTrackerSuite) TestRecord_And_Snapshot() {
	t := NewErrorTracker()

	t.Record("backend-1", false)
	t.Record("backend-1", false)
	t.Record("backend-1", true)
	t.Record("backend-2", false)

	snap := t.Snapshot()
	s.Len(snap, 2)

	// sorted by error rate desc
	s.Equal("backend-1", snap[0].Key)
	s.Equal(int64(3), snap[0].Total)
	s.Equal(int64(1), snap[0].Errors5xx)
	s.InDelta(33.33, snap[0].ErrorRate, 0.1)

	s.Equal("backend-2", snap[1].Key)
	s.Equal(int64(1), snap[1].Total)
	s.Equal(int64(0), snap[1].Errors5xx)
	s.InDelta(0, snap[1].ErrorRate, 0.01)
}

func (s *ErrorTrackerSuite) TestEmpty() {
	t := NewErrorTracker()
	s.Empty(t.Snapshot())
}

func (s *ErrorTrackerSuite) TestAllErrors() {
	t := NewErrorTracker()

	t.Record("backend-1", true)
	t.Record("backend-1", true)

	snap := t.Snapshot()
	s.Len(snap, 1)
	s.InDelta(100, snap[0].ErrorRate, 0.01)
}
