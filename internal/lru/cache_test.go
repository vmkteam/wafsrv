package lru

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type CacheSuite struct {
	suite.Suite
}

func TestCache(t *testing.T) {
	suite.Run(t, new(CacheSuite))
}

func (s *CacheSuite) TestPutAndGet() {
	c := New[string, int](3)

	c.Put("a", 1)
	c.Put("b", 2)
	c.Put("c", 3)

	v, ok := c.Get("a")
	s.True(ok)
	s.Equal(1, v)

	v, ok = c.Get("b")
	s.True(ok)
	s.Equal(2, v)
}

func (s *CacheSuite) TestEviction() {
	c := New[string, int](2)

	c.Put("a", 1)
	c.Put("b", 2)
	c.Put("c", 3) // evicts "a"

	_, ok := c.Get("a")
	s.False(ok, "a should be evicted")

	v, ok := c.Get("b")
	s.True(ok)
	s.Equal(2, v)

	v, ok = c.Get("c")
	s.True(ok)
	s.Equal(3, v)
}

func (s *CacheSuite) TestAccessRefreshesOrder() {
	c := New[string, int](2)

	c.Put("a", 1)
	c.Put("b", 2)
	c.Get("a")    // refresh "a"
	c.Put("c", 3) // evicts "b" (oldest)

	_, ok := c.Get("b")
	s.False(ok, "b should be evicted")

	v, ok := c.Get("a")
	s.True(ok)
	s.Equal(1, v)
}

func (s *CacheSuite) TestUpdate() {
	c := New[string, int](2)

	c.Put("a", 1)
	c.Put("a", 10)

	v, ok := c.Get("a")
	s.True(ok)
	s.Equal(10, v)
	s.Equal(1, c.Len())
}

func (s *CacheSuite) TestDelete() {
	c := New[string, int](3)

	c.Put("a", 1)
	c.Put("b", 2)
	c.Delete("a")

	_, ok := c.Get("a")
	s.False(ok)
	s.Equal(1, c.Len())
}

func (s *CacheSuite) TestLen() {
	c := New[string, int](5)
	s.Equal(0, c.Len())

	c.Put("a", 1)
	s.Equal(1, c.Len())

	c.Put("b", 2)
	s.Equal(2, c.Len())

	c.Delete("a")
	s.Equal(1, c.Len())
}

func (s *CacheSuite) TestGetMiss() {
	c := New[string, int](2)

	v, ok := c.Get("missing")
	s.False(ok)
	s.Equal(0, v)
}

func BenchmarkCachePut(b *testing.B) {
	c := New[int, int](10000)

	b.ResetTimer()
	b.ReportAllocs()

	for i := range b.N {
		c.Put(i, i)
	}
}

func BenchmarkCacheGet(b *testing.B) {
	c := New[int, int](10000)
	for i := range 10000 {
		c.Put(i, i)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := range b.N {
		c.Get(i % 10000)
	}
}
