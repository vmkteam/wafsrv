package app

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type MetricsSuite struct {
	suite.Suite
}

func TestMetrics(t *testing.T) {
	suite.Run(t, new(MetricsSuite))
}

// TestWireUp guards against silent regressions where a new metric is added
// to a sub-package's Metrics struct but the app-side adapter forgets to
// populate it. A nil CounterVec passed to a hot-path middleware is a no-op
// that hides the missing metric in production.
func (s *MetricsSuite) TestWireUp() {
	m := newMetrics()

	fm := m.filterMetrics(nil)
	s.NotNil(fm.MatchedTotal, "filter.Metrics.MatchedTotal must be wired")
	s.NotNil(fm.AttackOnlyTotal, "filter.Metrics.AttackOnlyTotal must be wired")

	dm := m.decideMetrics(nil, nil)
	s.NotNil(dm.DecisionTotal, "decide.Metrics.DecisionTotal must be wired")
	s.NotNil(dm.AttackBoostUsed, "decide.Metrics.AttackBoostUsed must be wired")
}
