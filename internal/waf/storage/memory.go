package storage

import (
	"encoding/binary"
	"sync"
	"time"

	"wafsrv/internal/lru"

	"golang.org/x/time/rate"
)

// MemoryCounter implements Counter using token bucket rate limiters (LRU-evicted).
type MemoryCounter struct {
	mu      sync.Mutex
	entries *lru.Cache[string, *counterEntry]
}

type counterEntry struct {
	limiter *rate.Limiter
}

// NewMemoryCounter creates a new in-memory counter with LRU eviction.
func NewMemoryCounter(maxSize int) *MemoryCounter {
	return &MemoryCounter{
		entries: lru.New[string, *counterEntry](maxSize),
	}
}

// Allow checks rate limit using token bucket. Thread-safe.
func (c *MemoryCounter) Allow(key string, limit int, window time.Duration) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	e, ok := c.entries.Get(key)
	if !ok {
		r := rate.Limit(float64(limit) / window.Seconds())
		e = &counterEntry{
			limiter: rate.NewLimiter(r, limit),
		}
		c.entries.Put(key, e)
	}

	return e.limiter.Allow(), nil
}

// MemoryKV implements KVStore using an LRU cache with TTL expiry.
type MemoryKV struct {
	mu      sync.RWMutex
	entries *lru.Cache[string, *kvEntry]
}

type kvEntry struct {
	value     []byte
	expiresAt time.Time
}

// NewMemoryKV creates a new in-memory key-value store with LRU eviction.
func NewMemoryKV(maxSize int) *MemoryKV {
	return &MemoryKV{
		entries: lru.New[string, *kvEntry](maxSize),
	}
}

func (kv *MemoryKV) Get(key string) ([]byte, bool, error) {
	kv.mu.Lock()
	defer kv.mu.Unlock()

	e, ok := kv.entries.Get(key)
	if !ok {
		return nil, false, nil
	}

	if !e.expiresAt.IsZero() && time.Now().After(e.expiresAt) {
		kv.entries.Delete(key)
		return nil, false, nil
	}

	return e.value, true, nil
}

func (kv *MemoryKV) Set(key string, value []byte, ttl time.Duration) error {
	kv.mu.Lock()
	defer kv.mu.Unlock()

	var expiresAt time.Time
	if ttl > 0 {
		expiresAt = time.Now().Add(ttl)
	}

	kv.entries.Put(key, &kvEntry{
		value:     value,
		expiresAt: expiresAt,
	})

	return nil
}

func (kv *MemoryKV) Delete(key string) error {
	kv.mu.Lock()
	defer kv.mu.Unlock()

	kv.entries.Delete(key)

	return nil
}

func (kv *MemoryKV) Exists(key string) (bool, error) {
	// LRU.Get mutates (MoveToFront), so we need a write lock.
	_, exists, err := kv.Get(key)
	return exists, err
}

func (kv *MemoryKV) Increment(key string, ttl time.Duration) (int64, error) {
	kv.mu.Lock()
	defer kv.mu.Unlock()

	var val int64

	e, ok := kv.entries.Get(key)
	if ok && (e.expiresAt.IsZero() || time.Now().Before(e.expiresAt)) {
		if len(e.value) == 8 {
			val = int64(binary.BigEndian.Uint64(e.value))
		}
	}

	val++

	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(val))

	var expiresAt time.Time
	if ttl > 0 {
		expiresAt = time.Now().Add(ttl)
	}

	kv.entries.Put(key, &kvEntry{
		value:     buf[:],
		expiresAt: expiresAt,
	})

	return val, nil
}
