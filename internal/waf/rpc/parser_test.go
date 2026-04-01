package rpc

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type ParserSuite struct {
	suite.Suite
}

func TestParser(t *testing.T) {
	suite.Run(t, new(ParserSuite))
}

func (s *ParserSuite) TestSingleRequest() {
	body := []byte(`{"jsonrpc":"2.0","method":"auth.login","params":{"email":"test@test.com"},"id":1}`)

	call := Parse(body, "/rpc/")

	s.Require().NotNil(call, "should parse valid single request")
	s.Equal("/rpc/", call.Endpoint)
	s.Equal([]string{"auth.login"}, call.Methods)
	s.False(call.IsBatch, "should not be batch")
}

func (s *ParserSuite) TestBatchRequest() {
	body := []byte(`[
		{"jsonrpc":"2.0","method":"auth.login","params":{},"id":1},
		{"jsonrpc":"2.0","method":"user.get","params":{},"id":2}
	]`)

	call := Parse(body, "/rpc/")

	s.Require().NotNil(call, "should parse valid batch request")
	s.Equal([]string{"auth.login", "user.get"}, call.Methods)
	s.True(call.IsBatch, "should be batch")
}

func (s *ParserSuite) TestEmptyBody() {
	call := Parse(nil, "/rpc/")
	s.Nil(call, "should return nil for nil body")

	call = Parse([]byte{}, "/rpc/")
	s.Nil(call, "should return nil for empty body")
}

func (s *ParserSuite) TestInvalidJSON() {
	call := Parse([]byte(`not json`), "/rpc/")
	s.Nil(call, "should return nil for invalid JSON")
}

func (s *ParserSuite) TestNoMethod() {
	call := Parse([]byte(`{"jsonrpc":"2.0","params":{},"id":1}`), "/rpc/")
	s.Nil(call, "should return nil when method is empty")
}

func (s *ParserSuite) TestEmptyBatch() {
	call := Parse([]byte(`[]`), "/rpc/")
	s.Nil(call, "should return nil for empty batch")
}

func (s *ParserSuite) TestBatchWithEmptyMethods() {
	body := []byte(`[{"jsonrpc":"2.0","params":{},"id":1}]`)

	call := Parse(body, "/rpc/")
	s.Nil(call, "should return nil when batch has no methods")
}

func (s *ParserSuite) TestWhitespace() {
	body := []byte(`   {"jsonrpc":"2.0","method":"test.method","id":1}`)

	call := Parse(body, "/rpc/")

	s.Require().NotNil(call, "should handle leading whitespace")
	s.Equal([]string{"test.method"}, call.Methods)
}

func (s *ParserSuite) TestDifferentEndpoints() {
	body := []byte(`{"jsonrpc":"2.0","method":"catalog.search","id":1}`)

	call := Parse(body, "/rpc/catalog/")

	s.Require().NotNil(call)
	s.Equal("/rpc/catalog/", call.Endpoint, "should preserve endpoint")
}

func BenchmarkParseSingle(b *testing.B) {
	body := []byte(`{"jsonrpc":"2.0","method":"auth.login","params":{"email":"test@test.com","password":"123"},"id":1}`)

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		Parse(body, "/rpc/")
	}
}

func BenchmarkParseBatch(b *testing.B) {
	body := []byte(`[
		{"jsonrpc":"2.0","method":"auth.login","params":{},"id":1},
		{"jsonrpc":"2.0","method":"user.get","params":{"id":42},"id":2},
		{"jsonrpc":"2.0","method":"catalog.search","params":{"q":"test"},"id":3}
	]`)

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		Parse(body, "/rpc/")
	}
}
