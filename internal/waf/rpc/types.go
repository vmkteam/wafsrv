package rpc

// Request represents a JSON-RPC 2.0 request (only fields needed for parsing).
type Request struct {
	Method string `json:"method"`
}
