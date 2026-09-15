// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanapi

import (
	"crypto/rand"
	"encoding/hex"
)

// scanIDBytes is the number of random bytes used for scan ID generation.
// 8 bytes = 16 hex chars = 64 bits of entropy, collision-safe at any
// realistic scan rate.
const scanIDBytes = 8

// Request is the JSON body for POST /api/v1/scan.
type Request struct {
	Kind    string          `json:"kind"`
	Input   Input           `json:"input"`
	Context *RequestContext `json:"context,omitempty"`
	Options *RequestOptions `json:"options,omitempty"`

	// callerToken is the authenticated bearer token for this request. It is
	// unexported (JSON decoding never populates or emits it) and is set by
	// ServeHTTP after authentication succeeds, so executeScan and its kind
	// handlers can derive the cross-request fragment session's caller
	// component (see crossrequest.go callerKeyForToken) without changing
	// their signatures or the many existing call sites/tests that construct
	// a Request literal directly.
	callerToken string
}

// Input holds kind-specific scan payload fields.
type Input struct {
	URL       string  `json:"url,omitempty"`
	Text      string  `json:"text,omitempty"`
	Content   string  `json:"content,omitempty"`
	ToolName  string  `json:"tool_name,omitempty"`
	Arguments RawJSON `json:"arguments,omitempty"`
}

// RawJSON holds arbitrary JSON for tool_call arguments.
// Stored as raw bytes to avoid premature parsing.
type RawJSON []byte

// MarshalJSON returns the raw bytes as-is.
func (r RawJSON) MarshalJSON() ([]byte, error) {
	if r == nil {
		return []byte("null"), nil
	}
	return r, nil
}

// UnmarshalJSON stores raw bytes without parsing.
func (r *RawJSON) UnmarshalJSON(data []byte) error {
	*r = append((*r)[:0], data...)
	return nil
}

// RequestContext holds caller-supplied correlation metadata.
type RequestContext struct {
	RequestID string `json:"request_id,omitempty"`
	SessionID string `json:"session_id,omitempty"`
	AgentName string `json:"agent_name,omitempty"`
}

// RequestOptions holds scan behavior overrides.
type RequestOptions struct {
	IncludeEvidence bool `json:"include_evidence,omitempty"`
}

// Response is the JSON envelope for all scan results and errors.
type Response struct {
	Status    string `json:"status"`
	Decision  string `json:"decision,omitempty"`
	Kind      string `json:"kind"`
	ScanID    string `json:"scan_id"`
	RequestID string `json:"request_id,omitempty"`
	// SessionID echoes context.session_id, following the same post-scan-only
	// copy timing as RequestID: present on completed responses (allow, warn,
	// deny, timeout, cancel), absent on pre-scan errors (401, 405, 429, 503,
	// invalid_json, invalid_kind, kind_disabled, invalid_input), and absent
	// when the request omitted session_id.
	SessionID     string     `json:"session_id,omitempty"`
	DurationMS    int64      `json:"duration_ms,omitempty"`
	EngineVersion string     `json:"engine_version"`
	Findings      []Finding  `json:"findings,omitempty"`
	Errors        []APIError `json:"errors,omitempty"`
}

// Finding represents a single scanner match.
type Finding struct {
	Scanner  string    `json:"scanner"`
	RuleID   string    `json:"rule_id"`
	Severity string    `json:"severity"`
	Message  string    `json:"message"`
	Evidence *Evidence `json:"evidence,omitempty"`
	// Contributors lists the scan_id of every earlier request in this
	// session whose content contributed retained bytes to this cross-request
	// fragment match. Present only on a "cross_request_fragment" finding.
	// Bounded and exact: it names only the fragments the buffer actually
	// retained, matching the MCP proxy's contributing-request provenance
	// shape (internal/mcp/cee.go captureCEEContributors).
	Contributors []string `json:"contributors,omitempty"`
}

// Evidence holds match location details. Only present when include_evidence is true.
type Evidence struct {
	Offsets  []Offset `json:"offsets,omitempty"`
	Encoding string   `json:"encoding,omitempty"`
}

// Offset is a UTF-8 byte range [Start, End) in the original input.
type Offset struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

// APIError is a machine-readable error in the response.
type APIError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

// generateScanID returns a unique scan ID: "scan-" + 16 hex chars from crypto/rand.
func generateScanID() string {
	b := make([]byte, scanIDBytes)
	_, _ = rand.Read(b) // crypto/rand.Read never returns an error on supported platforms
	return "scan-" + hex.EncodeToString(b)
}
