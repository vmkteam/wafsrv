package rpc

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type SchemaSuite struct {
	suite.Suite
}

func TestSchema(t *testing.T) {
	suite.Run(t, new(SchemaSuite))
}

func (s *SchemaSuite) TestParseSMD() {
	data := []byte(`{
		"transport": "POST",
		"envelope": "JSON-RPC-2.0",
		"SMDVersion": "2.0",
		"services": {
			"auth.login": {"parameters": []},
			"auth.register": {"parameters": []},
			"catalog.search": {"parameters": []}
		}
	}`)

	methods, err := ParseSchema(data)
	s.Require().NoError(err)
	s.Equal([]string{"auth.login", "auth.register", "catalog.search"}, methods)
}

func (s *SchemaSuite) TestParseOpenRPC() {
	data := []byte(`{
		"openrpc": "1.2.6",
		"info": {"title": "Test", "version": "1.0.0"},
		"methods": [
			{"name": "auth.login", "params": []},
			{"name": "catalog.search", "params": []}
		]
	}`)

	methods, err := ParseSchema(data)
	s.Require().NoError(err)
	s.Equal([]string{"auth.login", "catalog.search"}, methods)
}

func (s *SchemaSuite) TestAutoDetectSMD() {
	// has both services and methods — SMD wins (services is object)
	data := []byte(`{"services": {"a.b": {}}}`)
	methods, err := ParseSchema(data)
	s.Require().NoError(err)
	s.Equal([]string{"a.b"}, methods)
}

func (s *SchemaSuite) TestAutoDetectOpenRPC() {
	data := []byte(`{"methods": [{"name": "x.y"}]}`)
	methods, err := ParseSchema(data)
	s.Require().NoError(err)
	s.Equal([]string{"x.y"}, methods)
}

func (s *SchemaSuite) TestEmptySchema() {
	_, err := ParseSchema([]byte{})
	s.Error(err)
}

func (s *SchemaSuite) TestInvalidJSON() {
	_, err := ParseSchema([]byte(`not json`))
	s.Error(err)
}

func (s *SchemaSuite) TestNoMethodsFound() {
	_, err := ParseSchema([]byte(`{"foo": "bar"}`))
	s.Error(err)
}

func (s *SchemaSuite) TestResolveSchemaURL() {
	tests := []struct {
		schema string
		target string
		want   string
	}{
		{"/rpc/", "http://backend:3000", "http://backend:3000/rpc/"},
		{"/openrpc.json", "http://backend:3000/", "http://backend:3000/openrpc.json"},
		{"http://other:4000/rpc/", "http://backend:3000", "http://other:4000/rpc/"},
		{"", "http://backend:3000", ""},
		{"rpc/", "http://backend:3000", "http://backend:3000/rpc/"},
	}

	for _, tt := range tests {
		s.Equal(tt.want, ResolveSchemaURL(tt.schema, tt.target), "ResolveSchemaURL(%q, %q)", tt.schema, tt.target)
	}
}
