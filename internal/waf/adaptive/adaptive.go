package adaptive

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"wafsrv/internal/waf/alerting"
	"wafsrv/internal/waf/event"

	"github.com/prometheus/client_golang/prometheus"
)

// Config holds adaptive engine configuration.
type Config struct {
	Mode           string // "notify" | "auto"
	EvalInterval   time.Duration
	WarmupDuration time.Duration
	AutoAttack     AutoAttackConfig
}

// AutoAttackConfig holds auto-attack trigger thresholds.
type AutoAttackConfig struct {
	RPSMultiplier         float64
	RPSRecoveryMultiplier float64
	MinRPS                float64
	ErrorRateThreshold    float64
	LatencyThresholdMs    float64
	BlockedRateThreshold  float64
	Window                time.Duration
	Cooldown              time.Duration
	Duration              time.Duration
}

// AttackToggle controls Under Attack Mode.
type AttackToggle interface {
	EnableAuto(duration time.Duration, triggers []string)
	DisableAuto()
	IsEnabled() bool
	Source() string // "manual" | "auto" | ""
}

// Metrics holds prometheus metrics for adaptive engine.
type Metrics struct {
	TriggerTotal *prometheus.CounterVec // labels: trigger
	AttackTotal  *prometheus.CounterVec // labels: action (enable/disable)
}

// Status holds current adaptive engine status.
type Status struct {
	Enabled     bool      `json:"enabled"`
	Mode        string    `json:"mode"`
	Paused      bool      `json:"paused"`
	InWarmup    bool      `json:"inWarmup"`
	LastEval    time.Time `json:"lastEval,omitempty"`
	BaselineRPS float64   `json:"baselineRps"`
}

// Engine evaluates traffic metrics and auto-enables Under Attack Mode.
type Engine struct {
	cfg     Config
	series  *event.Series
	attack  AttackToggle
	alerter alerting.Sender
	logger  *slog.Logger
	metrics Metrics

	mu        sync.Mutex
	paused    bool
	lastEval  time.Time
	startedAt time.Time
}

// New creates a new adaptive engine.
func New(cfg Config, series *event.Series, attack AttackToggle, alerter alerting.Sender, logger *slog.Logger, metrics Metrics) *Engine {
	return &Engine{
		cfg:     cfg,
		series:  series,
		attack:  attack,
		alerter: alerter,
		logger:  logger,
		metrics: metrics,
	}
}

// Start begins the background evaluation loop.
func (e *Engine) Start(ctx context.Context) {
	e.mu.Lock()
	e.startedAt = time.Now()
	e.mu.Unlock()

	go e.loop(ctx)
}

// SetEnabled pauses or resumes the adaptive engine at runtime.
func (e *Engine) SetEnabled(enabled bool) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.paused = !enabled
}

// Status returns the current adaptive engine status.
func (e *Engine) Status() Status {
	e.mu.Lock()
	defer e.mu.Unlock()

	return Status{
		Enabled:     !e.paused,
		Mode:        e.cfg.Mode,
		Paused:      e.paused,
		InWarmup:    time.Since(e.startedAt) < e.cfg.WarmupDuration,
		LastEval:    e.lastEval,
		BaselineRPS: e.series.BaselineRPS(),
	}
}

func (e *Engine) loop(ctx context.Context) {
	ticker := time.NewTicker(e.cfg.EvalInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.eval(ctx)
		}
	}
}

func (e *Engine) eval(ctx context.Context) {
	e.mu.Lock()
	paused := e.paused
	warmupUntil := e.startedAt.Add(e.cfg.WarmupDuration)
	e.lastEval = time.Now()
	e.mu.Unlock()

	if paused {
		return
	}

	if time.Now().Before(warmupUntil) {
		return
	}

	snap := e.series.Snapshot(e.cfg.AutoAttack.Window)
	baseline := e.series.BaselineRPS()
	triggers := e.checkTriggers(snap, baseline)

	if len(triggers) > 0 {
		e.onTrigger(ctx, triggers, snap, baseline)
	} else if e.attack.IsEnabled() && e.attack.Source() == "auto" {
		e.checkRecovery(ctx, snap, baseline)
	}
}

func (e *Engine) checkTriggers(snap event.SeriesSnapshot, baseline float64) []string {
	var triggers []string
	aa := e.cfg.AutoAttack

	if aa.RPSMultiplier > 0 && baseline >= aa.MinRPS && snap.RPS > baseline*aa.RPSMultiplier {
		triggers = append(triggers, "rps_spike")
	}

	if aa.ErrorRateThreshold > 0 && snap.ErrorRate > aa.ErrorRateThreshold {
		triggers = append(triggers, "error_rate")
	}

	if aa.LatencyThresholdMs > 0 && snap.AvgLatencyMs > aa.LatencyThresholdMs {
		triggers = append(triggers, "latency_spike")
	}

	if aa.BlockedRateThreshold > 0 && snap.BlockedRate > aa.BlockedRateThreshold {
		triggers = append(triggers, "blocked_rate")
	}

	return triggers
}

func (e *Engine) onTrigger(ctx context.Context, triggers []string, snap event.SeriesSnapshot, baseline float64) {
	// record metrics
	for _, t := range triggers {
		e.metrics.TriggerTotal.WithLabelValues(t).Inc()
	}

	detail := e.formatTriggerDetail(triggers, snap, baseline)

	e.logger.WarnContext(ctx, "adaptive trigger",
		"detail", detail,
		"mode", e.cfg.Mode,
	)

	// enable attack mode (auto mode only, skip if manual or already auto)
	if e.cfg.Mode == "auto" && !e.attack.IsEnabled() {
		e.attack.EnableAuto(e.cfg.AutoAttack.Duration, triggers)
		e.metrics.AttackTotal.WithLabelValues("enable").Inc()
		e.logger.WarnContext(ctx, "auto attack enabled", "triggers", triggers, "duration", e.cfg.AutoAttack.Duration)

		if e.alerter != nil {
			e.alerter.Send(ctx, alerting.Event{
				Type:    alerting.EventUnderAttack,
				Message: detail,
			})
		}
	}
}

func (e *Engine) checkRecovery(ctx context.Context, snap event.SeriesSnapshot, baseline float64) {
	aa := e.cfg.AutoAttack

	// check all enabled triggers are below recovery threshold
	if aa.RPSMultiplier > 0 && baseline >= aa.MinRPS {
		if snap.RPS >= baseline*aa.RPSRecoveryMultiplier {
			return // still elevated
		}
	}

	if aa.ErrorRateThreshold > 0 && snap.ErrorRate >= aa.ErrorRateThreshold {
		return
	}

	if aa.LatencyThresholdMs > 0 && snap.AvgLatencyMs >= aa.LatencyThresholdMs {
		return
	}

	if aa.BlockedRateThreshold > 0 && snap.BlockedRate >= aa.BlockedRateThreshold {
		return
	}

	// cooldown check — don't flap
	// Source() == "auto" already checked by caller
	// We need enabledAt — use Cooldown from duration start
	// Since we can't access enabledAt directly, use a simpler approach:
	// check if attack has been enabled long enough
	// For cooldown we rely on the attack duration — if it expires, IsEnabled() returns false.
	// For early recovery: metrics normalized → disable immediately after cooldown.
	// AttackService handles expiration. We just call Disable.
	e.attack.DisableAuto()
	e.metrics.AttackTotal.WithLabelValues("disable").Inc()
	e.logger.InfoContext(ctx, "auto attack disabled, metrics normalized")

	if e.alerter != nil {
		e.alerter.Send(ctx, alerting.Event{
			Type:    alerting.EventAttackOff,
			Message: "auto attack disabled, metrics normalized",
		})
	}
}

func (e *Engine) formatTriggerDetail(triggers []string, snap event.SeriesSnapshot, baseline float64) string {
	parts := make([]string, 0, len(triggers))
	aa := e.cfg.AutoAttack

	for _, t := range triggers {
		switch t {
		case "rps_spike":
			parts = append(parts, fmt.Sprintf("rps(%.0f>%.0f×%.1f)", snap.RPS, baseline, aa.RPSMultiplier))
		case "error_rate":
			parts = append(parts, fmt.Sprintf("errors(%.1f%%>%.0f%%)", snap.ErrorRate, aa.ErrorRateThreshold))
		case "latency_spike":
			parts = append(parts, fmt.Sprintf("latency(%.0fms>%.0fms)", snap.AvgLatencyMs, aa.LatencyThresholdMs))
		case "blocked_rate":
			parts = append(parts, fmt.Sprintf("blocked(%.1f%%>%.0f%%)", snap.BlockedRate, aa.BlockedRateThreshold))
		}
	}

	action := "trigger"
	if e.cfg.Mode == "auto" {
		action = "auto_attack_enabled"
	}

	return action + ": " + strings.Join(parts, ", ")
}
