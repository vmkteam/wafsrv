package dashboard

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vmkteam/zenrpc/v2"
)

// snapshot is an immutable view of the attack-mode state. Readers load the
// pointer atomically; writers serialize via mu, build a new snapshot and Store.
type snapshot struct {
	enabled   bool
	source    string
	triggers  []string
	since     time.Time
	expiresAt time.Time
}

// attackState holds the shared mutable state (survives zenrpc value-receiver copies).
type attackState struct {
	mu   sync.Mutex
	snap atomic.Pointer[snapshot]
}

// AttackService manages Under Attack Mode.
type AttackService struct {
	zenrpc.Service
	state *attackState
}

// NewAttackService creates a new AttackService.
func NewAttackService() *AttackService {
	st := &attackState{}
	st.snap.Store(&snapshot{})

	return &AttackService{state: st}
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

	now := time.Now()
	next := snapshot{enabled: true, source: "manual", since: now}

	if duration != "" {
		d, err := time.ParseDuration(duration)
		if err != nil {
			return AttackStatus{}, ErrBadRequest
		}

		next.expiresAt = now.Add(d)
	}

	s.state.snap.Store(&next)

	return s.state.statusFromSnapshot(&next), nil
}

// Disable deactivates Under Attack Mode.
//
//zenrpc:return AttackStatus
func (s AttackService) Disable(_ context.Context) AttackStatus {
	s.state.mu.Lock()
	defer s.state.mu.Unlock()

	next := snapshot{}
	s.state.snap.Store(&next)

	return s.state.statusFromSnapshot(&next)
}

// Status returns the current Under Attack Mode state.
//
//zenrpc:return AttackStatus
func (s AttackService) Status(_ context.Context) AttackStatus {
	cur := s.state.expireIfNeeded()
	return s.state.statusFromSnapshot(cur)
}

// IsEnabled returns whether Under Attack Mode is active. Lock-free fast path
// (single atomic load) so it can be called from per-request middleware.
func (s AttackService) IsEnabled() bool {
	cur := s.state.snap.Load()
	if !cur.enabled {
		return false
	}

	if !cur.expiresAt.IsZero() && time.Now().After(cur.expiresAt) {
		// CAS-style expiry: only first caller wins, others observe disabled.
		next := s.state.expireIfNeeded()
		return next.enabled
	}

	return true
}

// EnableAuto activates Under Attack Mode from adaptive engine.
func (s AttackService) EnableAuto(duration time.Duration, triggers []string) {
	s.state.mu.Lock()
	defer s.state.mu.Unlock()

	cur := s.state.snap.Load()

	// don't override manual attack
	if cur.enabled && cur.source == "manual" {
		return
	}

	now := time.Now()
	s.state.snap.Store(&snapshot{
		enabled:   true,
		source:    "auto",
		triggers:  triggers,
		since:     now,
		expiresAt: now.Add(duration),
	})
}

// DisableAuto deactivates Under Attack Mode (for adaptive engine, no context needed).
func (s AttackService) DisableAuto() {
	s.state.mu.Lock()
	defer s.state.mu.Unlock()

	s.state.snap.Store(&snapshot{})
}

// Source returns the source of the current attack mode ("manual", "auto", or "").
func (s AttackService) Source() string {
	cur := s.state.snap.Load()
	if !cur.enabled {
		return ""
	}

	return cur.source
}

// expireIfNeeded clears expired state under the write lock and returns the
// (possibly updated) snapshot. Always reflects the post-call state.
func (st *attackState) expireIfNeeded() *snapshot {
	cur := st.snap.Load()
	if !cur.enabled || cur.expiresAt.IsZero() || !time.Now().After(cur.expiresAt) {
		return cur
	}

	st.mu.Lock()
	defer st.mu.Unlock()

	// re-check under lock — another goroutine may have cleared first
	cur = st.snap.Load()
	if !cur.enabled || cur.expiresAt.IsZero() || !time.Now().After(cur.expiresAt) {
		return cur
	}

	next := &snapshot{}
	st.snap.Store(next)

	return next
}

func (st *attackState) statusFromSnapshot(snap *snapshot) AttackStatus {
	as := AttackStatus{Enabled: snap.enabled}

	if snap.enabled {
		as.Source = snap.source
		as.Triggers = snap.triggers
	}

	if !snap.since.IsZero() {
		as.Since = snap.since.Format(time.RFC3339)
	}

	if !snap.expiresAt.IsZero() {
		as.ExpiresAt = snap.expiresAt.Format(time.RFC3339)
	}

	return as
}
