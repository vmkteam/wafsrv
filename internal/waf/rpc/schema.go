package rpc

import (
	"encoding/json"
	"errors"
	"sort"
)

// ParseSchema auto-detects SMD or OpenRPC format and extracts method names.
func ParseSchema(data []byte) ([]string, error) {
	if len(data) == 0 {
		return nil, errors.New("rpc: empty schema")
	}

	// probe for format
	var probe struct {
		Services map[string]json.RawMessage `json:"services"` // SMD
		Methods  []json.RawMessage          `json:"methods"`  // OpenRPC
	}

	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, errors.New("rpc: invalid schema JSON")
	}

	if len(probe.Services) > 0 {
		return parseSMDMethods(probe.Services), nil
	}

	if len(probe.Methods) > 0 {
		return parseOpenRPCMethods(probe.Methods)
	}

	return nil, errors.New("rpc: unrecognized schema format (expected SMD services or OpenRPC methods)")
}

// parseSMDMethods extracts method names from SMD services map.
func parseSMDMethods(services map[string]json.RawMessage) []string {
	methods := make([]string, 0, len(services))
	for name := range services {
		methods = append(methods, name)
	}

	sort.Strings(methods)

	return methods
}

// parseOpenRPCMethods extracts method names from OpenRPC methods array.
func parseOpenRPCMethods(raw []json.RawMessage) ([]string, error) {
	methods := make([]string, 0, len(raw))

	for _, r := range raw {
		var m struct {
			Name string `json:"name"`
		}

		if err := json.Unmarshal(r, &m); err != nil {
			continue
		}

		if m.Name != "" {
			methods = append(methods, m.Name)
		}
	}

	if len(methods) == 0 {
		return nil, errors.New("rpc: no methods found in OpenRPC schema")
	}

	sort.Strings(methods)

	return methods, nil
}
