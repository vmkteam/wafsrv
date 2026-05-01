package rpc

import (
	"bytes"
	"encoding/json"

	"wafsrv/internal/waf"
)

// MaxParseSize is the maximum body size read for JSON-RPC method extraction.
const MaxParseSize = 64 * 1024

// mcpToolCallMethod is the MCP method for invoking tools.
const mcpToolCallMethod = "tools/call"

// Parse extracts JSON-RPC method names from request body.
// It handles both single and batch requests.
// When mcpMode is true, tools/call methods are enriched with params.name → "tools/call:tool_name".
// Returns nil if body is not valid JSON-RPC.
func Parse(body []byte, endpoint string, mcpMode bool) *waf.RPCCall {
	if len(body) == 0 {
		return nil
	}

	// limit parsing to MaxParseSize
	data := body
	if len(data) > MaxParseSize {
		data = data[:MaxParseSize]
	}

	data = bytes.TrimLeft(data, " \t\r\n")
	if len(data) == 0 {
		return nil
	}

	if data[0] == '[' {
		return parseBatch(data, endpoint, mcpMode)
	}

	return parseSingle(data, endpoint, mcpMode)
}

func parseSingle(data []byte, endpoint string, mcpMode bool) *waf.RPCCall {
	var req Request
	if err := json.Unmarshal(data, &req); err != nil || req.Method == "" {
		return nil
	}

	method := req.Method
	if mcpMode {
		method = mcpEnrichMethod(method, req.Params)
	}

	return &waf.RPCCall{
		Endpoint: endpoint,
		Methods:  []string{method},
		IsBatch:  false,
	}
}

func parseBatch(data []byte, endpoint string, mcpMode bool) *waf.RPCCall {
	var reqs []Request
	if err := json.Unmarshal(data, &reqs); err != nil || len(reqs) == 0 {
		return nil
	}

	methods := make([]string, 0, len(reqs))
	for _, r := range reqs {
		if r.Method == "" {
			continue
		}

		method := r.Method
		if mcpMode {
			method = mcpEnrichMethod(method, r.Params)
		}

		methods = append(methods, method)
	}

	if len(methods) == 0 {
		return nil
	}

	return &waf.RPCCall{
		Endpoint:  endpoint,
		Methods:   methods,
		IsBatch:   true,
		BatchSize: len(reqs),
	}
}

// mcpEnrichMethod extracts tool name from params for tools/call method.
// "tools/call" + params.name="search_issues" → "tools/call:search_issues"
func mcpEnrichMethod(method string, params json.RawMessage) string {
	if method != mcpToolCallMethod || len(params) == 0 {
		return method
	}

	var p struct {
		Name string `json:"name"`
	}

	if json.Unmarshal(params, &p) == nil && p.Name != "" {
		return method + ":" + p.Name
	}

	return method
}
