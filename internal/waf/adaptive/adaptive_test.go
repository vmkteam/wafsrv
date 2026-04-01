package adaptive

import (
	"log/slog"
	"testing"
	"time"

	"wafsrv/internal/waf/event"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/suite"
)

type AdaptiveSuite struct {
	suite.Suite
}

func TestAdaptive(t *testing.T) {
	suite.Run(t, new(AdaptiveSuite))
}

func (s *AdaptiveSuite) TestRPSSpikeTrigger() {
	e, attack := s.newEngine(Config{
		AutoAttack: AutoAttackConfig{RPSMultiplier: 2, MinRPS: 5},
	})

	// baseline=10 RPS, current=25 → 25 > 10*2 → trigger
	snap := event.SeriesSnapshot{RPS: 25, Incoming: 100}
	triggers := e.checkTriggers(snap, 10)
	s.Contains(triggers, "rps_spike")
	_ = attack
}

func (s *AdaptiveSuite) TestRPSBelowMinRPS() {
	e, _ := s.newEngine(Config{
		AutoAttack: AutoAttackConfig{RPSMultiplier: 2, MinRPS: 20},
	})

	// baseline=5 < MinRPS=20 → skip RPS trigger
	snap := event.SeriesSnapshot{RPS: 50, Incoming: 100}
	triggers := e.checkTriggers(snap, 5)
	s.Empty(triggers)
}

func (s *AdaptiveSuite) TestErrorRateTrigger() {
	e, _ := s.newEngine(Config{
		AutoAttack: AutoAttackConfig{ErrorRateThreshold: 10},
	})

	snap := event.SeriesSnapshot{ErrorRate: 15}
	triggers := e.checkTriggers(snap, 0)
	s.Contains(triggers, "error_rate")
}

func (s *AdaptiveSuite) TestLatencyTrigger() {
	e, _ := s.newEngine(Config{
		AutoAttack: AutoAttackConfig{LatencyThresholdMs: 200},
	})

	snap := event.SeriesSnapshot{AvgLatencyMs: 300}
	triggers := e.checkTriggers(snap, 0)
	s.Contains(triggers, "latency_spike")
}

func (s *AdaptiveSuite) TestBlockedRateTrigger() {
	e, _ := s.newEngine(Config{
		AutoAttack: AutoAttackConfig{BlockedRateThreshold: 30},
	})

	snap := event.SeriesSnapshot{BlockedRate: 45}
	triggers := e.checkTriggers(snap, 0)
	s.Contains(triggers, "blocked_rate")
}

func (s *AdaptiveSuite) TestDisabledThreshold() {
	e, _ := s.newEngine(Config{
		AutoAttack: AutoAttackConfig{
			RPSMultiplier:        0, // disabled
			ErrorRateThreshold:   0,
			LatencyThresholdMs:   0,
			BlockedRateThreshold: 0,
		},
	})

	snap := event.SeriesSnapshot{RPS: 1000, ErrorRate: 90, AvgLatencyMs: 5000, BlockedRate: 80}
	triggers := e.checkTriggers(snap, 100)
	s.Empty(triggers, "all thresholds disabled → no triggers")
}

func (s *AdaptiveSuite) TestNoTriggerNormalTraffic() {
	e, _ := s.newEngine(Config{
		AutoAttack: AutoAttackConfig{
			RPSMultiplier:        3,
			MinRPS:               10,
			ErrorRateThreshold:   20,
			LatencyThresholdMs:   500,
			BlockedRateThreshold: 50,
		},
	})

	snap := event.SeriesSnapshot{RPS: 20, ErrorRate: 1, AvgLatencyMs: 10, BlockedRate: 2}
	triggers := e.checkTriggers(snap, 15)
	s.Empty(triggers)
}

func (s *AdaptiveSuite) TestNotifyMode() {
	e, attack := s.newEngine(Config{
		Mode:       "notify",
		AutoAttack: AutoAttackConfig{ErrorRateThreshold: 10, Duration: time.Minute},
	})

	snap := event.SeriesSnapshot{ErrorRate: 50}
	triggers := e.checkTriggers(snap, 0)
	s.NotEmpty(triggers)

	e.onTrigger(s.T().Context(), triggers, snap, 0)
	s.False(attack.enabled, "notify mode should not enable attack")
}

func (s *AdaptiveSuite) TestAutoMode() {
	e, attack := s.newEngine(Config{
		Mode:       "auto",
		AutoAttack: AutoAttackConfig{ErrorRateThreshold: 10, Duration: time.Minute},
	})

	snap := event.SeriesSnapshot{ErrorRate: 50}
	triggers := e.checkTriggers(snap, 0)

	e.onTrigger(s.T().Context(), triggers, snap, 0)
	s.True(attack.enabled, "auto mode should enable attack")
	s.Equal("auto", attack.source)
	s.Contains(attack.triggers, "error_rate")
}

func (s *AdaptiveSuite) TestManualOverride() {
	e, attack := s.newEngine(Config{
		Mode:       "auto",
		AutoAttack: AutoAttackConfig{ErrorRateThreshold: 10, Duration: time.Minute},
	})

	// manual attack already active
	attack.enabled = true
	attack.source = "manual"

	snap := event.SeriesSnapshot{ErrorRate: 50}
	triggers := e.checkTriggers(snap, 0)
	e.onTrigger(s.T().Context(), triggers, snap, 0)

	// should still be manual (EnableAuto skips if manual)
	s.Equal("manual", attack.source)
}

func (s *AdaptiveSuite) TestHysteresis() {
	e, attack := s.newEngine(Config{
		Mode: "auto",
		AutoAttack: AutoAttackConfig{
			RPSMultiplier:         3,
			RPSRecoveryMultiplier: 1.5,
			MinRPS:                5,
		},
	})

	attack.enabled = true
	attack.source = "auto"

	// baseline=10, recovery=15, current=20 → still above recovery → no disable
	snap := event.SeriesSnapshot{RPS: 20, Incoming: 100}
	e.checkRecovery(s.T().Context(), snap, 10)
	s.True(attack.enabled, "RPS above recovery threshold → stay enabled")
}

func (s *AdaptiveSuite) TestAutoDisable() {
	e, attack := s.newEngine(Config{
		Mode: "auto",
		AutoAttack: AutoAttackConfig{
			RPSMultiplier:         3,
			RPSRecoveryMultiplier: 1.5,
			MinRPS:                5,
			ErrorRateThreshold:    20,
		},
	})

	attack.enabled = true
	attack.source = "auto"

	// all metrics below recovery
	snap := event.SeriesSnapshot{RPS: 10, ErrorRate: 1, Incoming: 100}
	e.checkRecovery(s.T().Context(), snap, 10)
	s.False(attack.enabled, "all metrics normalized → disable")
}

func (s *AdaptiveSuite) TestRuntimeDisable() {
	e, _ := s.newEngine(Config{})

	s.False(e.paused)
	e.SetEnabled(false)
	s.True(e.paused)

	status := e.Status()
	s.True(status.Paused)

	e.SetEnabled(true)
	s.False(e.paused)
}

func (s *AdaptiveSuite) newEngine(cfg Config) (*Engine, *mockAttack) {
	if cfg.Mode == "" {
		cfg.Mode = "auto"
	}

	attack := &mockAttack{}

	return New(cfg, event.NewSeries(time.Second, 60), attack, nil, slog.Default(), testMetrics()), attack
}

type mockAttack struct {
	enabled  bool
	source   string
	triggers []string
	duration time.Duration
}

func (m *mockAttack) EnableAuto(duration time.Duration, triggers []string) {
	if m.enabled && m.source == "manual" {
		return // don't override manual
	}

	m.enabled = true
	m.source = "auto"
	m.triggers = triggers
	m.duration = duration
}

func (m *mockAttack) DisableAuto() {
	m.enabled = false
	m.source = ""
	m.triggers = nil
}

func (m *mockAttack) IsEnabled() bool { return m.enabled }
func (m *mockAttack) Source() string  { return m.source }

func testMetrics() Metrics {
	return Metrics{
		TriggerTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "test_adaptive_trigger_total",
			Help: "test",
		}, []string{"trigger"}),
		AttackTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "test_adaptive_attack_total",
			Help: "test",
		}, []string{"action"}),
	}
}
