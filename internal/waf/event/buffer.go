package event

import (
	"sync"
	"time"
)

// Event represents a security event.
type Event struct {
	Time     time.Time `json:"time"`
	Type     string    `json:"type"` // waf_match, ip_blocked, rate_limit, decision
	ClientIP string    `json:"clientIp"`
	Path     string    `json:"path"`
	Detail   string    `json:"detail"`
}

// Buffer is a thread-safe fixed-size circular buffer for events.
type Buffer struct {
	mu    sync.RWMutex
	items []Event
	pos   int
	full  bool
	size  int
}

// NewBuffer creates a new ring buffer with the given capacity.
func NewBuffer(size int) *Buffer {
	if size <= 0 {
		size = 1000
	}

	return &Buffer{
		items: make([]Event, size),
		size:  size,
	}
}

// Add appends an event to the buffer.
func (b *Buffer) Add(e Event) {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}

	b.mu.Lock()
	b.items[b.pos] = e
	b.pos = (b.pos + 1) % b.size

	if !b.full && b.pos == 0 {
		b.full = true
	}

	b.mu.Unlock()
}

// Recent returns the last n events, newest first.
func (b *Buffer) Recent(n int) []Event {
	b.mu.RLock()
	defer b.mu.RUnlock()

	total := b.pos
	if b.full {
		total = b.size
	}

	if n <= 0 || n > total {
		n = total
	}

	result := make([]Event, n)

	for i := range n {
		idx := (b.pos - 1 - i + b.size) % b.size
		result[i] = b.items[idx]
	}

	return result
}
