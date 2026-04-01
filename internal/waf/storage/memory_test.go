package storage

import (
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

type MemoryCounterSuite struct {
	suite.Suite
	counter *MemoryCounter
}

func (s *MemoryCounterSuite) SetupTest() {
	s.counter = NewMemoryCounter(1000)
}

func (s *MemoryCounterSuite) TestAllow_Basic() {
	// allow 3 requests per second
	for i := range 3 {
		ok, err := s.counter.Allow("key1", 3, time.Second)
		s.Require().NoError(err)
		s.True(ok, "request %d should be allowed", i+1)
	}

	// 4th should be denied
	ok, err := s.counter.Allow("key1", 3, time.Second)
	s.Require().NoError(err)
	s.False(ok, "4th request should be denied")
}

func (s *MemoryCounterSuite) TestAllow_DifferentKeys() {
	ok, _ := s.counter.Allow("key1", 1, time.Second)
	s.True(ok)

	ok, _ = s.counter.Allow("key1", 1, time.Second)
	s.False(ok, "key1 should be exhausted")

	ok, _ = s.counter.Allow("key2", 1, time.Second)
	s.True(ok, "key2 should be independent")
}

func (s *MemoryCounterSuite) TestAllow_WindowReset() {
	ok, _ := s.counter.Allow("key1", 1, 50*time.Millisecond)
	s.True(ok)

	ok, _ = s.counter.Allow("key1", 1, 50*time.Millisecond)
	s.False(ok)

	// wait for window to reset
	time.Sleep(60 * time.Millisecond)

	ok, _ = s.counter.Allow("key1", 1, 50*time.Millisecond)
	s.True(ok, "should be allowed after window reset")
}

func TestMemoryCounter(t *testing.T) {
	suite.Run(t, new(MemoryCounterSuite))
}

type MemoryKVSuite struct {
	suite.Suite
	kv *MemoryKV
}

func (s *MemoryKVSuite) SetupTest() {
	s.kv = NewMemoryKV(1000)
}

func (s *MemoryKVSuite) TestGetSetDelete() {
	// get non-existent
	val, exists, err := s.kv.Get("key1")
	s.Require().NoError(err)
	s.False(exists)
	s.Nil(val)

	// set
	err = s.kv.Set("key1", []byte("hello"), time.Minute)
	s.Require().NoError(err)

	// get existing
	val, exists, err = s.kv.Get("key1")
	s.Require().NoError(err)
	s.True(exists)
	s.Equal([]byte("hello"), val)

	// delete
	err = s.kv.Delete("key1")
	s.Require().NoError(err)

	// get after delete
	_, exists, err = s.kv.Get("key1")
	s.Require().NoError(err)
	s.False(exists)
}

func (s *MemoryKVSuite) TestExists() {
	exists, err := s.kv.Exists("key1")
	s.Require().NoError(err)
	s.False(exists)

	_ = s.kv.Set("key1", []byte("v"), time.Minute)

	exists, err = s.kv.Exists("key1")
	s.Require().NoError(err)
	s.True(exists)
}

func (s *MemoryKVSuite) TestTTLExpiry() {
	err := s.kv.Set("key1", []byte("v"), 50*time.Millisecond)
	s.Require().NoError(err)

	exists, _ := s.kv.Exists("key1")
	s.True(exists)

	time.Sleep(60 * time.Millisecond)

	exists, _ = s.kv.Exists("key1")
	s.False(exists, "should expire after TTL")
}

func (s *MemoryKVSuite) TestZeroTTL() {
	err := s.kv.Set("key1", []byte("v"), 0)
	s.Require().NoError(err)

	// zero TTL = no expiry
	val, exists, err := s.kv.Get("key1")
	s.Require().NoError(err)
	s.True(exists)
	s.Equal([]byte("v"), val)
}

func (s *MemoryKVSuite) TestIncrement() {
	val, err := s.kv.Increment("counter1", time.Minute)
	s.Require().NoError(err)
	s.Equal(int64(1), val)

	val, err = s.kv.Increment("counter1", time.Minute)
	s.Require().NoError(err)
	s.Equal(int64(2), val)

	val, err = s.kv.Increment("counter1", time.Minute)
	s.Require().NoError(err)
	s.Equal(int64(3), val)
}

func (s *MemoryKVSuite) TestIncrement_TTLExpiry() {
	_, _ = s.kv.Increment("counter1", 50*time.Millisecond)
	_, _ = s.kv.Increment("counter1", 50*time.Millisecond)

	time.Sleep(60 * time.Millisecond)

	val, err := s.kv.Increment("counter1", 50*time.Millisecond)
	s.Require().NoError(err)
	s.Equal(int64(1), val, "should reset after TTL")
}

func TestMemoryKV(t *testing.T) {
	suite.Run(t, new(MemoryKVSuite))
}

// --- Benchmarks ---

func BenchmarkMemoryCounterAllow(b *testing.B) {
	c := NewMemoryCounter(100000)

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		c.Allow("key1", 1000000, time.Minute)
	}
}

func BenchmarkMemoryCounterAllowParallel(b *testing.B) {
	c := NewMemoryCounter(100000)

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			c.Allow("key1", 1000000, time.Minute)
		}
	})
}

func BenchmarkMemoryKVSet(b *testing.B) {
	kv := NewMemoryKV(100000)
	val := []byte("hello world")

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		kv.Set("key1", val, time.Minute)
	}
}

func BenchmarkMemoryKVGet(b *testing.B) {
	kv := NewMemoryKV(100000)
	kv.Set("key1", []byte("hello world"), time.Minute)

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		kv.Get("key1")
	}
}

func BenchmarkMemoryKVIncrement(b *testing.B) {
	kv := NewMemoryKV(100000)

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		kv.Increment("key1", time.Minute)
	}
}
