package event

import (
	"sort"
	"sync"
)

// ErrorEntry holds per-target error statistics.
type ErrorEntry struct {
	Key       string  `json:"key"`
	Total     int64   `json:"total"`
	Errors5xx int64   `json:"errors5xx"`
	ErrorRate float64 `json:"errorRate"` // Errors5xx / Total * 100
}

// ErrorTracker collects per-target request and error counts.
type ErrorTracker struct {
	mu      sync.Mutex
	buckets map[string]*errorBucket
}

type errorBucket struct {
	total     int64
	errors5xx int64
}

// NewErrorTracker creates a new tracker.
func NewErrorTracker() *ErrorTracker {
	return &ErrorTracker{
		buckets: make(map[string]*errorBucket),
	}
}

// Record records a request result for the given target.
func (t *ErrorTracker) Record(target string, is5xx bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	b, ok := t.buckets[target]
	if !ok {
		b = &errorBucket{}
		t.buckets[target] = b
	}

	b.total++

	if is5xx {
		b.errors5xx++
	}
}

// Snapshot returns error stats for all targets, sorted by error rate desc.
func (t *ErrorTracker) Snapshot() []ErrorEntry {
	t.mu.Lock()
	defer t.mu.Unlock()

	entries := make([]ErrorEntry, 0, len(t.buckets))

	for key, b := range t.buckets {
		var rate float64
		if b.total > 0 {
			rate = float64(b.errors5xx) / float64(b.total) * 100
		}

		entries = append(entries, ErrorEntry{
			Key:       key,
			Total:     b.total,
			Errors5xx: b.errors5xx,
			ErrorRate: rate,
		})
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].ErrorRate > entries[j].ErrorRate
	})

	return entries
}
