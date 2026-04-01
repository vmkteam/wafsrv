package storage

import "time"

// Counter provides atomic increment with sliding window for rate limiting.
type Counter interface {
	// Allow checks if the key has not exceeded limit within the window.
	// Returns true if allowed, false if limit exceeded.
	// Atomically increments the counter.
	Allow(key string, limit int, window time.Duration) (bool, error)
}

// KVStore provides key-value operations with TTL.
type KVStore interface {
	Get(key string) ([]byte, bool, error)
	Set(key string, value []byte, ttl time.Duration) error
	Delete(key string) error
	Exists(key string) (bool, error)
	// Increment atomically increments an integer value, returns new value.
	Increment(key string, ttl time.Duration) (int64, error)
}
