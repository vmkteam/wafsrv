package rpc

import (
	"bytes"
	"encoding/json"

	"wafsrv/internal/waf"
)

// MaxParseSize is the maximum body size read for JSON-RPC method extraction.
const MaxParseSize = 64 * 1024

// Parse extracts JSON-RPC method names from request body.
// It handles both single and batch requests.
// Returns nil if body is not valid JSON-RPC.
func Parse(body []byte, endpoint string) *waf.RPCCall {
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
		return parseBatch(data, endpoint)
	}

	return parseSingle(data, endpoint)
}

func parseSingle(data []byte, endpoint string) *waf.RPCCall {
	var req Request
	if err := json.Unmarshal(data, &req); err != nil || req.Method == "" {
		return nil
	}

	return &waf.RPCCall{
		Endpoint: endpoint,
		Methods:  []string{req.Method},
		IsBatch:  false,
	}
}

func parseBatch(data []byte, endpoint string) *waf.RPCCall {
	var reqs []Request
	if err := json.Unmarshal(data, &reqs); err != nil || len(reqs) == 0 {
		return nil
	}

	methods := make([]string, 0, len(reqs))
	for _, r := range reqs {
		if r.Method != "" {
			methods = append(methods, r.Method)
		}
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
