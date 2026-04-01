package event

import (
	"sort"
	"sync"
	"time"
)

const latencyRingSize = 100 // last N samples for percentile calculation

// LatencyEntry holds latency statistics for a single key (target or method).
type LatencyEntry struct {
	Key   string  `json:"key"`
	Count int64   `json:"count"`
	AvgMs float64 `json:"avgMs"`
	MaxMs float64 `json:"maxMs"`
	P95Ms float64 `json:"p95Ms"`
}

// LatencyTracker collects per-key latency statistics.
type LatencyTracker struct {
	mu      sync.Mutex
	buckets map[string]*latencyBucket
}

type latencyBucket struct {
	count int64
	sumUs int64 // microseconds
	maxUs int64
	ring  [latencyRingSize]int64 // last N latencies in microseconds
	ringN int                    // total samples written (may exceed ring size)
}

// NewLatencyTracker creates a new tracker.
func NewLatencyTracker() *LatencyTracker {
	return &LatencyTracker{
		buckets: make(map[string]*latencyBucket),
	}
}

// Record records a latency sample for the given key.
func (t *LatencyTracker) Record(key string, d time.Duration) {
	us := d.Microseconds()

	t.mu.Lock()
	defer t.mu.Unlock()

	b, ok := t.buckets[key]
	if !ok {
		b = &latencyBucket{}
		t.buckets[key] = b
	}

	b.count++
	b.sumUs += us

	if us > b.maxUs {
		b.maxUs = us
	}

	b.ring[b.ringN%latencyRingSize] = us
	b.ringN++
}

// Snapshot returns current latency stats for all keys, sorted by count desc.
func (t *LatencyTracker) Snapshot() []LatencyEntry {
	t.mu.Lock()
	defer t.mu.Unlock()

	entries := make([]LatencyEntry, 0, len(t.buckets))

	for key, b := range t.buckets {
		avgMs := float64(b.sumUs) / float64(b.count) / 1000
		maxMs := float64(b.maxUs) / 1000

		entries = append(entries, LatencyEntry{
			Key:   key,
			Count: b.count,
			AvgMs: avgMs,
			MaxMs: maxMs,
			P95Ms: b.p95Ms(),
		})
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Count > entries[j].Count
	})

	return entries
}

// Reset clears all buckets.
func (t *LatencyTracker) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.buckets = make(map[string]*latencyBucket)
}

func (b *latencyBucket) p95Ms() float64 {
	n := b.ringN
	if n > latencyRingSize {
		n = latencyRingSize
	}

	if n == 0 {
		return 0
	}

	// copy and sort
	samples := make([]int64, n)
	copy(samples, b.ring[:n])

	sort.Slice(samples, func(i, j int) bool {
		return samples[i] < samples[j]
	})

	idx := int(float64(n) * 0.95)
	if idx >= n {
		idx = n - 1
	}

	return float64(samples[idx]) / 1000
}
