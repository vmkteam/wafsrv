package dashboard

import (
	"context"
	"sync"
	"time"

	"github.com/vmkteam/zenrpc/v2"
)

// attackState holds the shared mutable state (survives zenrpc value-receiver copies).
type attackState struct {
	mu        sync.Mutex
	enabled   bool
	source    string // "manual" | "auto"
	triggers  []string
	since     time.Time
	expiresAt time.Time
}

// AttackService manages Under Attack Mode.
type AttackService struct {
	zenrpc.Service
	state *attackState
}

// NewAttackService creates a new AttackService.
func NewAttackService() *AttackService {
	return &AttackService{state: &attackState{}}
}

// AttackStatus is the response for attack.status.
type AttackStatus struct {
	Enabled   bool     `json:"enabled"`
	Source    string   `json:"source,omitempty"`   // "manual" | "auto"
	Triggers  []string `json:"triggers,omitempty"` // trigger names when source=auto
	Since     string   `json:"since,omitempty"`
	ExpiresAt string   `json:"expiresAt,omitempty"`
}

// Enable activates Under Attack Mode.
//
//zenrpc:duration="" Duration (e.g. "5m", "1h"). Empty = until manual disable
//zenrpc:return AttackStatus
func (s AttackService) Enable(_ context.Context, duration string) (AttackStatus, error) {
	s.state.mu.Lock()
	defer s.state.mu.Unlock()

	s.state.enabled = true
	s.state.source = "manual"
	s.state.triggers = nil
	s.state.since = time.Now()
	s.state.expiresAt = time.Time{}

	if duration != "" {
		d, err := time.ParseDuration(duration)
		if err != nil {
			return AttackStatus{}, ErrBadRequest
		}

		s.state.expiresAt = s.state.since.Add(d)
	}

	return s.state.statusLocked(), nil
}

// Disable deactivates Under Attack Mode.
//
//zenrpc:return AttackStatus
func (s AttackService) Disable(_ context.Context) AttackStatus {
	s.state.mu.Lock()
	defer s.state.mu.Unlock()

	s.state.enabled = false
	s.state.source = ""
	s.state.triggers = nil
	s.state.since = time.Time{}
	s.state.expiresAt = time.Time{}

	return s.state.statusLocked()
}

// Status returns the current Under Attack Mode state.
//
//zenrpc:return AttackStatus
func (s AttackService) Status(_ context.Context) AttackStatus {
	s.state.mu.Lock()
	defer s.state.mu.Unlock()

	s.state.expireIfNeeded()

	return s.state.statusLocked()
}

// IsEnabled returns whether Under Attack Mode is active (for middleware).
func (s AttackService) IsEnabled() bool {
	s.state.mu.Lock()
	defer s.state.mu.Unlock()

	s.state.expireIfNeeded()

	return s.state.enabled
}

// EnableAuto activates Under Attack Mode from adaptive engine.
func (s AttackService) EnableAuto(duration time.Duration, triggers []string) {
	s.state.mu.Lock()
	defer s.state.mu.Unlock()

	// don't override manual attack
	if s.state.enabled && s.state.source == "manual" {
		return
	}

	s.state.enabled = true
	s.state.source = "auto"
	s.state.triggers = triggers
	s.state.since = time.Now()
	s.state.expiresAt = s.state.since.Add(duration)
}

// DisableAuto deactivates Under Attack Mode (for adaptive engine, no context needed).
func (s AttackService) DisableAuto() {
	s.state.mu.Lock()
	defer s.state.mu.Unlock()

	s.state.enabled = false
	s.state.source = ""
	s.state.triggers = nil
	s.state.since = time.Time{}
	s.state.expiresAt = time.Time{}
}

// Source returns the source of the current attack mode ("manual", "auto", or "").
func (s AttackService) Source() string {
	s.state.mu.Lock()
	defer s.state.mu.Unlock()

	if !s.state.enabled {
		return ""
	}

	return s.state.source
}

func (st *attackState) expireIfNeeded() {
	if st.enabled && !st.expiresAt.IsZero() && time.Now().After(st.expiresAt) {
		st.enabled = false
		st.source = ""
		st.triggers = nil
		st.since = time.Time{}
		st.expiresAt = time.Time{}
	}
}

func (st *attackState) statusLocked() AttackStatus {
	as := AttackStatus{Enabled: st.enabled}

	if st.enabled {
		as.Source = st.source
		as.Triggers = st.triggers
	}

	if !st.since.IsZero() {
		as.Since = st.since.Format(time.RFC3339)
	}

	if !st.expiresAt.IsZero() {
		as.ExpiresAt = st.expiresAt.Format(time.RFC3339)
	}

	return as
}
