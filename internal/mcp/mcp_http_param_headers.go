// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"encoding/json"
	"math/big"
	"strconv"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
)

const (
	mcpParamHeaderPrefix = "mcp-param-"
	maxMCPMirrorInteger  = int64(9007199254740991)
)

// validateMCPParamHeaders verifies every recognized 2026-07-28 mirrored tool
// parameter against the exact property path in the accepted tools/list schema.
// Unknown headers remain intermediary data and are forwarded after scanning, as
// the protocol requires. A known schema is strict in both directions: a body
// value requires its header, and a recognized header requires its body value.
func validateMCPParamHeaders(headers map[string][]string, frame MCPFrame, baseline *tools.ToolBaseline) bool {
	if frame.RoutingNameErr != nil {
		return false
	}
	if frame.Method != methodToolsCall || baseline == nil || frame.RoutingName == "" {
		return true
	}
	bindings, known := baseline.HeaderBindings(frame.RoutingName)
	if !known {
		return true
	}
	paramHeaders := make(map[string][]string)
	for name, values := range headers {
		lower := strings.ToLower(name)
		if strings.HasPrefix(lower, mcpParamHeaderPrefix) {
			paramHeaders[strings.TrimPrefix(lower, mcpParamHeaderPrefix)] = values
		}
	}
	for lowerName, binding := range bindings {
		raw, present, ok := argumentAtPath(frame.Args, binding.Path)
		if !ok {
			return false
		}
		values := paramHeaders[lowerName]
		if !present || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			if len(values) != 0 {
				return false
			}
			continue
		}
		if len(values) != 1 {
			return false
		}
		decoded, ok := decodeMCPHeaderValue(values[0])
		if !ok || !mcpParamValueMatches(decoded, raw, binding.Type) {
			return false
		}
	}
	return true
}

func argumentAtPath(arguments json.RawMessage, path []string) (json.RawMessage, bool, bool) {
	if len(arguments) == 0 {
		return nil, false, true
	}
	current := arguments
	for _, part := range path {
		var object map[string]json.RawMessage
		if err := json.Unmarshal(current, &object); err != nil {
			return nil, false, false
		}
		next, exists := object[part]
		if !exists {
			return nil, false, true
		}
		current = next
	}
	return current, true, true
}

func decodeMCPHeaderValue(value string) (string, bool) {
	decoded, ok := decodeMCPWireValue(value)
	if !ok {
		return "", false
	}
	if strings.HasPrefix(value, "=?base64?") {
		return decoded, true
	}
	if decoded == "" || strings.TrimSpace(decoded) != decoded {
		return "", false
	}
	for i := range len(decoded) {
		if (decoded[i] < 0x20 || decoded[i] > 0x7e) && decoded[i] != '\t' {
			return "", false
		}
	}
	return decoded, true
}

func mcpParamValueMatches(header string, raw json.RawMessage, valueType string) bool {
	switch valueType {
	case "string":
		var body string
		return json.Unmarshal(raw, &body) == nil && header == body
	case "boolean":
		var body bool
		return json.Unmarshal(raw, &body) == nil && header == strconv.FormatBool(body)
	case "integer":
		bodyNumber := new(big.Rat)
		if _, ok := bodyNumber.SetString(string(bytes.TrimSpace(raw))); !ok || !bodyNumber.IsInt() {
			return false
		}
		body := bodyNumber.Num()
		limit := big.NewInt(maxMCPMirrorInteger)
		if body.Cmp(limit) > 0 || body.Cmp(new(big.Int).Neg(limit)) < 0 {
			return false
		}
		headerInteger, err := strconv.ParseInt(header, 10, 64)
		if err != nil || strconv.FormatInt(headerInteger, 10) != header || headerInteger > maxMCPMirrorInteger || headerInteger < -maxMCPMirrorInteger {
			return false
		}
		return body.Cmp(big.NewInt(headerInteger)) == 0
	default:
		return false
	}
}
