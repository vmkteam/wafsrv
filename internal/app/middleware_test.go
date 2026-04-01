package app

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type MiddlewareSuite struct {
	suite.Suite
}

func TestMiddleware(t *testing.T) {
	suite.Run(t, new(MiddlewareSuite))
}

func (s *MiddlewareSuite) TestParseSize() {
	tests := []struct {
		input    string
		expected int64
	}{
		{"1KB", 1024},
		{"1MB", 1 << 20},
		{"5MB", 5 << 20},
		{"10MB", 10 << 20},
		{"100MB", 100 << 20},
		{"1GB", 1 << 30},
		{"512KB", 512 * 1024},
		{"1B", 1},
		{"1024B", 1024},
		{"1KIB", 1024},
		{"1MIB", 1 << 20},
		{"1K", 1024},
		{"1M", 1 << 20},
		{"1G", 1 << 30},
		{"1 MB", 1 << 20},
		{"0.5MB", (1 << 20) / 2},
	}

	for _, tt := range tests {
		s.Equal(tt.expected, parseSize(tt.input, -1), "parseSize(%q)", tt.input)
	}
}

func (s *MiddlewareSuite) TestParseSizeDefault() {
	s.Equal(int64(42), parseSize("", 42), "empty string should return default")
	s.Equal(int64(42), parseSize("abc", 42), "invalid string should return default")
	s.Equal(int64(42), parseSize("MB", 42), "no number should return default")
	s.Equal(int64(42), parseSize("1XB", 42), "unknown suffix should return default")
}

func (s *MiddlewareSuite) TestStatusBucket() {
	s.Equal("1xx", statusBucket(100))
	s.Equal("2xx", statusBucket(200))
	s.Equal("2xx", statusBucket(204))
	s.Equal("3xx", statusBucket(301))
	s.Equal("4xx", statusBucket(404))
	s.Equal("5xx", statusBucket(500))
	s.Equal("5xx", statusBucket(503))
}
