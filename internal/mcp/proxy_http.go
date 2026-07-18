// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/jsonrpc"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

var defaultMCPListenerSensitiveHeaders = []string{
	"Authorization",
	"Cookie",
	listenerLastEventID,
	"X-Api-Key",
	"X-Token",
	"Proxy-Authorization",
	"X-Goog-Api-Key",
}

type mcpListenerHeaderDLPResult struct {
	header  string
	matches []scanner.TextDLPMatch
}

func scanMCPListenerHeadersForDLP(
	ctx context.Context,
	headers http.Header,
	sc *scanner.Scanner,
	cfg *config.RequestBodyScanning,
) *mcpListenerHeaderDLPResult {
	if sc == nil {
		return nil
	}

	headersToScan := mcpListenerHeadersToScan(headers, cfg)
	allValues := make([]string, 0)
	for name, values := range headersToScan {
		if mcpListenerShouldScanHeaderNames(cfg) {
			result := sc.ScanTextForDLP(ctx, name)
			if !result.Clean {
				return &mcpListenerHeaderDLPResult{header: name, matches: result.Matches}
			}
			allValues = append(allValues, name)
		}

		for _, value := range values {
			if value == "" {
				continue
			}
			allValues = append(allValues, value)
			result := sc.ScanTextForDLP(ctx, value)
			if !result.Clean {
				return &mcpListenerHeaderDLPResult{header: name, matches: result.Matches}
			}
			if mcpListenerShouldScanHeaderNames(cfg) {
				result = sc.ScanTextForDLP(ctx, name+value)
				if !result.Clean {
					return &mcpListenerHeaderDLPResult{header: name, matches: result.Matches}
				}
			}
		}
	}

	if len(allValues) > 1 {
		sort.Strings(allValues)
		result := sc.ScanTextForDLP(ctx, strings.Join(allValues, "\n"))
		if !result.Clean {
			return &mcpListenerHeaderDLPResult{header: "(joined)", matches: result.Matches}
		}
	}
	return nil
}

func mcpListenerHeadersToScan(headers http.Header, cfg *config.RequestBodyScanning) map[string][]string {
	if cfg == nil || !cfg.Enabled || !cfg.ScanHeaders {
		return mcpListenerExplicitHeaders(headers, []string{listenerAuthorization, listenerLastEventID})
	}
	if cfg.HeaderMode == config.HeaderModeAll {
		ignored := make(map[string]struct{}, len(cfg.IgnoreHeaders))
		for _, name := range cfg.IgnoreHeaders {
			ignored[http.CanonicalHeaderKey(name)] = struct{}{}
		}
		out := make(map[string][]string)
		for name, values := range headers {
			canonical := http.CanonicalHeaderKey(name)
			if _, skip := ignored[canonical]; skip {
				continue
			}
			out[canonical] = values
		}
		// Last-Event-ID is a credential-bearing SSE resume cursor and is scanned
		// unconditionally in every other header-selection path; reinsert it here so
		// IgnoreHeaders cannot exempt it in all-header mode (fail closed).
		if values := headers.Values(listenerLastEventID); len(values) > 0 {
			out[http.CanonicalHeaderKey(listenerLastEventID)] = values
		}
		return out
	}

	sensitiveHeaders := cfg.SensitiveHeaders
	if len(sensitiveHeaders) == 0 {
		sensitiveHeaders = defaultMCPListenerSensitiveHeaders
	} else {
		sensitiveHeaders = append([]string{}, sensitiveHeaders...)
		sensitiveHeaders = append(sensitiveHeaders, listenerLastEventID)
	}
	return mcpListenerExplicitHeaders(headers, sensitiveHeaders)
}

func mcpListenerExplicitHeaders(headers http.Header, names []string) map[string][]string {
	out := make(map[string][]string)
	for _, name := range names {
		canonical := http.CanonicalHeaderKey(name)
		values, ok := headers[canonical]
		if !ok || len(values) == 0 {
			continue
		}
		out[canonical] = values
	}
	return out
}

func mcpListenerShouldScanHeaderNames(cfg *config.RequestBodyScanning) bool {
	return cfg != nil && cfg.Enabled && cfg.ScanHeaders && cfg.HeaderMode == config.HeaderModeAll
}

// hashSessionKey produces a short, non-reversible identifier from a raw IP
// for use in audit logs, so client IPs don't leak through the session field.
func hashSessionKey(ip string) string {
	h := sha256.Sum256([]byte(ip))
	return "ip:" + hex.EncodeToString(h[:8]) // 16 hex chars, enough to correlate
}

// extractRPCID extracts the "id" field from a JSON-RPC message.
// Returns nil for notifications (no id field) or parse failures.
func extractRPCID(msg []byte) json.RawMessage {
	var rpc struct {
		ID json.RawMessage `json:"id"`
	}
	if json.Unmarshal(msg, &rpc) != nil {
		return nil
	}
	if string(rpc.ID) == jsonrpc.Null || len(rpc.ID) == 0 {
		return nil
	}
	return rpc.ID
}

// validateRPCStructure checks JSON-RPC 2.0 structural requirements that
// json.Valid() cannot catch: version field, method presence, and method type.
// Returns an error message if invalid, empty string if ok.
func validateRPCStructure(msg []byte) string {
	var env struct {
		JSONRPC string          `json:"jsonrpc"`
		Method  json.RawMessage `json:"method"`
	}
	if json.Unmarshal(msg, &env) != nil {
		return "invalid JSON structure"
	}
	// jsonrpc field must be exactly "2.0".
	if env.JSONRPC != jsonrpc.Version {
		return "jsonrpc field must be \"2.0\""
	}
	// method field is required for client requests.
	if len(env.Method) == 0 {
		return "missing required field: method"
	}
	// Method must be a JSON string (starts with quote).
	if env.Method[0] != '"' {
		return "method must be a string"
	}
	return ""
}

// upstreamErrorResponse creates a JSON-RPC error for HTTP transport failures.
// If id is nil, the response uses a JSON null id (valid for unidentifiable requests).
func upstreamErrorResponse(id json.RawMessage, upstreamErr error) []byte {
	resp := rpcError{
		JSONRPC: jsonrpc.Version,
		ID:      id,
		Error: rpcErrorDetail{
			Code:    -32003,
			Message: fmt.Sprintf("pipelock: upstream error: %v", upstreamErr),
		},
	}
	data, _ := json.Marshal(resp) //nolint:errcheck // marshaling known-good struct
	return data
}
