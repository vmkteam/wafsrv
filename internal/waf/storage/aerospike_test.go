package storage

import (
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

func aerospikeHost() string {
	if h := os.Getenv("AEROSPIKE_HOST"); h != "" {
		return h
	}

	return ""
}

func newTestAerospike(t *testing.T) *Aerospike {
	t.Helper()

	host := aerospikeHost()
	if host == "" {
		t.Skip("AEROSPIKE_HOST not set, skipping integration test")
	}

	a, err := NewAerospike(AerospikeConfig{
		Hosts:          []string{host},
		Namespace:      "test",
		ConnectTimeout: 5 * time.Second,
		OperTimeout:    2 * time.Second,
	})
	if err != nil {
		t.Fatalf("connect to aerospike: %v", err)
	}

	t.Cleanup(func() { a.Close() })

	return a
}

// --- Counter ---

type AerospikeCounterSuite struct {
	suite.Suite
	a       *Aerospike
	counter *AerospikeCounter
}

func (s *AerospikeCounterSuite) SetupSuite() {
	s.a = newTestAerospike(s.T())
	s.counter = s.a.Counter("rl_test")
}

func (s *AerospikeCounterSuite) TestAllow_Basic() {
	// unique key per test
	key := "test_basic_" + time.Now().Format("150405.000")

	for i := range 3 {
		ok, err := s.counter.Allow(key, 3, 10*time.Second)
		s.Require().NoError(err)
		s.True(ok, "request %d should be allowed", i+1)
	}

	ok, err := s.counter.Allow(key, 3, 10*time.Second)
	s.Require().NoError(err)
	s.False(ok, "4th request should be denied")
}

func (s *AerospikeCounterSuite) TestAllow_DifferentKeys() {
	base := "test_diffkeys_" + time.Now().Format("150405.000")

	ok, _ := s.counter.Allow(base+"_a", 1, 10*time.Second)
	s.True(ok)

	ok, _ = s.counter.Allow(base+"_a", 1, 10*time.Second)
	s.False(ok, "key a should be exhausted")

	ok, _ = s.counter.Allow(base+"_b", 1, 10*time.Second)
	s.True(ok, "key b should be independent")
}

func (s *AerospikeCounterSuite) TestAllow_WindowReset() {
	key := "test_reset_" + time.Now().Format("150405.000")

	ok, _ := s.counter.Allow(key, 1, time.Second)
	s.True(ok)

	ok, _ = s.counter.Allow(key, 1, time.Second)
	s.False(ok)

	// wait for TTL to expire
	time.Sleep(2 * time.Second)

	ok, err := s.counter.Allow(key, 1, time.Second)
	s.Require().NoError(err)
	s.True(ok, "should be allowed after window reset")
}

func (s *AerospikeCounterSuite) TestAllow_Concurrent() {
	key := "test_concurrent_" + time.Now().Format("150405.000")
	limit := 50
	total := 100

	var wg sync.WaitGroup

	allowed := make(chan bool, total)

	for range total {
		wg.Add(1)

		go func() {
			defer wg.Done()

			ok, _ := s.counter.Allow(key, limit, 10*time.Second)
			allowed <- ok
		}()
	}

	wg.Wait()
	close(allowed)

	var allowedCount int
	for ok := range allowed {
		if ok {
			allowedCount++
		}
	}

	// Allow small margin: fail-open on connection errors may inflate count slightly.
	s.InDelta(limit, allowedCount, 10, "approximately %d requests should be allowed (got %d)", limit, allowedCount)
}

func TestAerospikeCounter(t *testing.T) {
	suite.Run(t, new(AerospikeCounterSuite))
}

// --- KVStore ---

type AerospikeKVSuite struct {
	suite.Suite
	a  *Aerospike
	kv *AerospikeKV
}

func (s *AerospikeKVSuite) SetupSuite() {
	s.a = newTestAerospike(s.T())
	s.kv = s.a.KV("kv_test")
}

func (s *AerospikeKVSuite) TestGetSetDelete() {
	key := "test_crud_" + time.Now().Format("150405.000")

	// get non-existent
	val, exists, err := s.kv.Get(key)
	s.Require().NoError(err)
	s.False(exists)
	s.Nil(val)

	// set
	err = s.kv.Set(key, []byte("hello"), 10*time.Second)
	s.Require().NoError(err)

	// get existing
	val, exists, err = s.kv.Get(key)
	s.Require().NoError(err)
	s.True(exists)
	s.Equal([]byte("hello"), val)

	// delete
	err = s.kv.Delete(key)
	s.Require().NoError(err)

	// get after delete
	_, exists, err = s.kv.Get(key)
	s.Require().NoError(err)
	s.False(exists)
}

func (s *AerospikeKVSuite) TestExists() {
	key := "test_exists_" + time.Now().Format("150405.000")

	exists, err := s.kv.Exists(key)
	s.Require().NoError(err)
	s.False(exists)

	_ = s.kv.Set(key, []byte("v"), 10*time.Second)

	exists, err = s.kv.Exists(key)
	s.Require().NoError(err)
	s.True(exists)
}

func (s *AerospikeKVSuite) TestTTLExpiry() {
	key := "test_ttl_" + time.Now().Format("150405.000")

	err := s.kv.Set(key, []byte("v"), time.Second)
	s.Require().NoError(err)

	exists, _ := s.kv.Exists(key)
	s.True(exists)

	time.Sleep(2 * time.Second)

	exists, _ = s.kv.Exists(key)
	s.False(exists, "should expire after TTL")
}

func (s *AerospikeKVSuite) TestIncrement() {
	key := "test_inc_" + time.Now().Format("150405.000")

	val, err := s.kv.Increment(key, 10*time.Second)
	s.Require().NoError(err)
	s.Equal(int64(1), val)

	val, err = s.kv.Increment(key, 10*time.Second)
	s.Require().NoError(err)
	s.Equal(int64(2), val)

	val, err = s.kv.Increment(key, 10*time.Second)
	s.Require().NoError(err)
	s.Equal(int64(3), val)
}

func (s *AerospikeKVSuite) TestDeleteNonExistent() {
	err := s.kv.Delete("nonexistent_key_12345")
	s.NoError(err, "deleting non-existent key should not error")
}

func TestAerospikeKV(t *testing.T) {
	suite.Run(t, new(AerospikeKVSuite))
}

// --- Benchmarks ---

func newBenchAerospike(b *testing.B) *Aerospike {
	b.Helper()

	host := aerospikeHost()
	if host == "" {
		b.Skip("AEROSPIKE_HOST not set, skipping benchmark")
	}

	a, err := NewAerospike(AerospikeConfig{
		Hosts:          []string{host},
		Namespace:      "test",
		ConnectTimeout: 5 * time.Second,
		OperTimeout:    2 * time.Second,
	})
	if err != nil {
		b.Fatalf("connect to aerospike: %v", err)
	}

	b.Cleanup(func() { a.Close() })

	return a
}

func BenchmarkAerospikeCounterAllow(b *testing.B) {
	a := newBenchAerospike(b)
	c := a.Counter("bench_rl")

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		c.Allow("bench_key", 1000000, time.Minute)
	}
}

func BenchmarkAerospikeCounterAllowParallel(b *testing.B) {
	a := newBenchAerospike(b)
	c := a.Counter("bench_rl")

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			c.Allow("bench_key_par", 1000000, time.Minute)
		}
	})
}

func BenchmarkAerospikeKVSet(b *testing.B) {
	a := newBenchAerospike(b)
	kv := a.KV("bench_kv")
	val := []byte("hello world")

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		kv.Set("bench_key", val, time.Minute)
	}
}

func BenchmarkAerospikeKVGet(b *testing.B) {
	a := newBenchAerospike(b)
	kv := a.KV("bench_kv")
	kv.Set("bench_key", []byte("hello world"), time.Minute)

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		kv.Get("bench_key")
	}
}

func BenchmarkAerospikeKVIncrement(b *testing.B) {
	a := newBenchAerospike(b)
	kv := a.KV("bench_kv")

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		kv.Increment("bench_inc", time.Minute)
	}
}
