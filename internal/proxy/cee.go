// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"io"
	"net/http"
	"strings"
)

// ceeSessionKey builds a consistent session identity for cross-request
// exfiltration detection. When an agent name is available, the key is
// "agent|clientIP". Otherwise, just the client IP.
func ceeSessionKey(agent, clientIP string) string {
	if agent != "" && agent != agentAnonymous {
		return agent + "|" + clientIP
	}
	return clientIP
}

// maxCEEBodyRead limits the body bytes read for CEE payload extraction.
// Larger bodies are unlikely to be fragment-based exfiltration attempts.
const maxCEEBodyRead = 65536 // 64KB

// extractOutboundPayload extracts the outbound data visible to the proxy
// for entropy measurement and fragment buffering. Includes query parameter
// values and request body content.
func extractOutboundPayload(r *http.Request) []byte {
	var parts []string

	// Query parameter values (keys are not agent-controlled data).
	for _, values := range r.URL.Query() {
		parts = append(parts, values...)
	}

	// Request body (limited read to bound memory).
	if r.Body != nil && r.ContentLength != 0 {
		limited := io.LimitReader(r.Body, maxCEEBodyRead)
		bodyBytes, err := io.ReadAll(limited)
		if err == nil && len(bodyBytes) > 0 {
			parts = append(parts, string(bodyBytes))
		}
	}

	return []byte(strings.Join(parts, ""))
}
