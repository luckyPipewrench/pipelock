// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package envelope

import (
	"net/http"
	"strings"
)

// InjectHTTP serializes the envelope and sets it as the Pipelock-Mediation
// HTTP header value.
func InjectHTTP(h http.Header, env Envelope) error {
	val, err := env.Serialize()
	if err != nil {
		return err
	}
	h.Set(HeaderName, val)
	return nil
}

// StripInbound removes any inbound Pipelock-Mediation header and any
// pipelock-labeled Signature/Signature-Input members. This prevents
// header injection where an agent or upstream proxy forges mediation headers.
func StripInbound(h http.Header) {
	h.Del(HeaderName)
	stripPipelockSignatureMembers(h, "Signature-Input")
	stripPipelockSignatureMembers(h, "Signature")
}

// stripPipelockSignatureMembers removes dictionary members from a header
// where the member key starts with "pipelock".
func stripPipelockSignatureMembers(h http.Header, headerName string) {
	values := h.Values(headerName)
	if len(values) == 0 {
		return
	}

	h.Del(headerName)

	for _, val := range values {
		members := strings.Split(val, ",")
		var kept []string
		for _, m := range members {
			trimmed := strings.TrimSpace(m)
			if strings.HasPrefix(trimmed, "pipelock") {
				continue
			}
			kept = append(kept, m)
		}
		if len(kept) > 0 {
			h.Add(headerName, strings.Join(kept, ","))
		}
	}
}

// InjectMCP adds the envelope to an MCP _meta map.
func InjectMCP(meta map[string]any, env Envelope) {
	meta[MCPMetaKey] = env.ToMCPMeta()
}

// StripInboundMCP removes any existing mediation key from an MCP _meta map.
func StripInboundMCP(meta map[string]any) {
	delete(meta, MCPMetaKey)
}
