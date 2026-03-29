// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package capture defines the types and interfaces used by the policy
// capture-and-replay system. Capture observers are called by the proxy and MCP
// scanner layers; the resulting CaptureSummary structs are stored as
// recorder.Entry.Detail values in the evidence log.
package capture

import "context"

// CaptureSchemaV1 is the current CaptureSummary schema version.
// Replay engines must reject summaries with unknown versions.
const CaptureSchemaV1 = 1

// Surface constants identify which proxy layer produced a capture entry.
const (
	SurfaceURL        = "url"
	SurfaceResponse   = "response"
	SurfaceDLP        = "dlp"
	SurfaceCEE        = "cee"
	SurfaceToolPolicy = "tool_policy"
	SurfaceToolScan   = "tool_scan"
)

// Outcome constants describe what the scanner decided to do with a request.
const (
	OutcomeClean      = "clean"
	OutcomeBlocked    = "blocked"
	OutcomeWarned     = "warned"
	OutcomeStripped   = "stripped"
	OutcomeRedirected = "redirected"
	OutcomeSkipped    = "skipped"
	OutcomeFailClosed = "fail_closed"
)

// Finding kind constants identify which detection rule produced a finding.
const (
	KindDLP               = "dlp"
	KindAddressProtection = "address_protection"
	KindInjection         = "injection"
	KindCEE               = "cee"
	KindChainDetection    = "chain_detection"
	KindSessionBinding    = "session_binding"
	KindToolPoison        = "tool_poison"
	KindToolDrift         = "tool_drift"
	KindToolPolicy        = "tool_policy"
	KindRedirect          = "redirect"
)

// TransformKind constants describe which text transformation was applied to the
// payload before scanning. This lets the replay engine reproduce the exact same
// transform to compare scanner results.
const (
	TransformRaw                    = "raw"
	TransformReadability            = "readability"
	TransformHiddenHTML             = "hidden_html"
	TransformHeaderValue            = "header_value"
	TransformJoinedFields           = "joined_fields"
	TransformCEEWindow              = "cee_window"
	TransformWebSocketFrame         = "websocket_frame"
	TransformToolsListDescription   = "tools_list_description"
	TransformToolsListSiblingFields = "tools_list_sibling_fields"
	TransformMCPBatchElement        = "mcp_batch_element"
	TransformRedirectOutput         = "redirect_output"
)

// Entry type constants for recorder entries produced by this package.
const (
	// EntryTypeCapture is the type for normal capture entries.
	EntryTypeCapture = "capture"
	// EntryTypeCaptureDrop is the type written when captures are dropped (e.g.
	// buffer full), so the chain records the loss event.
	EntryTypeCaptureDrop = "capture_drop"
)

// CaptureSummary is the Detail payload stored in a recorder.Entry of type
// EntryTypeCapture. It contains everything the replay engine needs to reproduce
// the original scan decision: the request context, the canonicalised scanner
// input, the raw and effective findings, and the final outcome.
type CaptureSummary struct {
	// CaptureSchemaVersion must equal CaptureSchemaV1. Replay engines reject
	// entries with unknown versions.
	CaptureSchemaVersion int `json:"capture_schema_version"`

	// Surface identifies which proxy layer produced this entry (url, response,
	// dlp, cee, tool_policy, tool_scan).
	Surface string `json:"surface"`
	// Subsurface qualifies the surface (e.g. transport name: fetch, forward,
	// connect, websocket, mcp_stdio, mcp_http).
	Subsurface string `json:"subsurface"`
	// BatchIndex is set when this entry is one element of an MCP batch request.
	// Nil for non-batch requests (omitted from JSON rather than null).
	BatchIndex *int `json:"batch_index,omitempty"`

	// ConfigHash is the hex SHA-256 of the effective config at scan time.
	ConfigHash string `json:"config_hash"`
	// BuildVersion is the pipelock version string (e.g. "v2.0.0").
	BuildVersion string `json:"build_version"`
	// BuildSHA is the git commit SHA the binary was built from.
	BuildSHA string `json:"build_sha"`

	// Agent is the agent profile name, if agents are enabled.
	Agent string `json:"agent,omitempty"`
	// Profile is the resolved config profile name.
	Profile string `json:"profile,omitempty"`

	// PayloadRef is the recorder RawRef for the full raw payload (optional;
	// only set when raw escrow is enabled).
	PayloadRef string `json:"payload_ref,omitempty"`
	// PayloadSHA256 is the hex SHA-256 of the complete wire payload.
	PayloadSHA256 string `json:"payload_sha256,omitempty"`
	// PayloadBytes is the total byte length of the wire payload.
	PayloadBytes int `json:"payload_bytes,omitempty"`
	// PayloadComplete is true when the payload was fully buffered (no
	// truncation). False means only a prefix was captured.
	PayloadComplete bool `json:"payload_complete"`

	// TransformKind identifies which text extraction was applied before scanning.
	TransformKind string `json:"transform_kind"`

	// WirePayloadBytes is the byte count of the raw wire payload passed to the
	// transform.
	WirePayloadBytes int `json:"wire_payload_bytes,omitempty"`
	// WirePayloadSample is the first 256 bytes of the wire payload (for human
	// inspection; not used by the replay engine).
	WirePayloadSample string `json:"wire_payload_sample,omitempty"`

	// ScannerBytes is the byte count of the string fed to the scanner after
	// transformation.
	ScannerBytes int `json:"scanner_bytes,omitempty"`
	// ScannerSample is the first 256 bytes of the scanner input.
	ScannerSample string `json:"scanner_sample,omitempty"`

	// Request describes the originating HTTP/MCP request.
	Request CaptureRequest `json:"request"`

	// RawFindings is every finding produced by the scanner before action
	// resolution (suppression, allowlist overrides, etc.).
	RawFindings []Finding `json:"raw_findings"`
	// EffectiveFindings is the subset of findings that contributed to the final
	// action after resolution.
	EffectiveFindings []Finding `json:"effective_findings"`
	// EffectiveAction is the action taken (block, warn, strip, redirect, allow).
	EffectiveAction string `json:"effective_action"`
	// Outcome is the coarse outcome category (blocked, warned, clean, etc.).
	Outcome string `json:"outcome"`
	// SkipReason explains why scanning was skipped (e.g. "allowlisted domain").
	SkipReason string `json:"skip_reason,omitempty"`
}

// CaptureRequest describes the originating request. Not all fields are set for
// every surface; unused fields are omitted from JSON.
type CaptureRequest struct {
	// Method is the HTTP verb (GET, POST, etc.) for HTTP surfaces.
	Method string `json:"method"`
	// URL is the request URL (absolute for forward proxy, path for fetch).
	URL string `json:"url"`
	// Headers contains selected request headers (no auth/cookie values).
	Headers map[string][]string `json:"headers,omitempty"`
	// BodySample is the first 256 bytes of the request body.
	BodySample string `json:"body_sample,omitempty"`
	// ToolName is the MCP tool name, for tool_policy and tool_scan surfaces.
	ToolName string `json:"tool_name,omitempty"`
	// ToolArgsJSON is the raw JSON of the tool arguments.
	ToolArgsJSON string `json:"tool_args_json,omitempty"`
	// MCPMethod is the JSON-RPC method (e.g. "tools/call", "tools/list").
	MCPMethod string `json:"mcp_method,omitempty"`
}

// Finding is a single scanner detection result. Not all fields apply to every
// kind; unused fields are omitted from JSON.
type Finding struct {
	// Kind identifies which detection rule fired (KindDLP, KindInjection, etc.).
	Kind string `json:"kind"`
	// Action is the per-finding action recommendation before resolution.
	Action string `json:"action,omitempty"`
	// Severity is the finding severity (info, warn, critical, etc.).
	Severity string `json:"severity,omitempty"`
	// PatternName is the DLP or injection pattern that matched.
	PatternName string `json:"pattern_name,omitempty"`
	// Encoded describes the encoding layer that was decoded to find the match.
	Encoded string `json:"encoded,omitempty"`
	// MatchText is a truncated excerpt of the matched text.
	MatchText string `json:"match_text,omitempty"`
	// Chain is the chain sequence label for chain detection findings.
	Chain string `json:"chain,omitempty"`
	// AddrVerdict is the address protection verdict string.
	AddrVerdict string `json:"addr_verdict,omitempty"`
	// ToolName is the MCP tool name associated with this finding.
	ToolName string `json:"tool_name,omitempty"`
	// DriftType describes the type of tool drift detected.
	DriftType string `json:"drift_type,omitempty"`
	// PoisonSignal describes the tool poisoning signal detected.
	PoisonSignal string `json:"poison_signal,omitempty"`
	// PolicyRule is the tool policy rule ID or label that matched.
	PolicyRule string `json:"policy_rule,omitempty"`
	// RedirectTo is the redirect destination for KindRedirect findings.
	RedirectTo string `json:"redirect_to,omitempty"`
	// ToolSequence is the tool call sequence matched by chain detection.
	ToolSequence []string `json:"tool_sequence,omitempty"`
}

// CaptureDropDetail is the Detail payload for EntryTypeCaptureDrop entries.
// It records how many captures were dropped and why (e.g. buffer full).
type CaptureDropDetail struct {
	Count  int    `json:"count"`
	Reason string `json:"reason"`
}

// DropSink is implemented by components that can receive drop notifications.
// The capture writer calls RecordCaptureDrop when it discards an entry to keep
// the evidence chain aware of the loss.
type DropSink interface {
	RecordCaptureDrop()
}

// CaptureObserver is called by proxy and MCP scanner hooks with the verdict for
// each scanned surface. Implementations write captures to the evidence log,
// update metrics, or both. The NopObserver provides a no-op implementation
// suitable for use when capture is disabled.
//
// All Observe methods are called synchronously on the scan hot path; they must
// return quickly.
type CaptureObserver interface {
	ObserveURLVerdict(ctx context.Context, rec *URLVerdictRecord)
	ObserveResponseVerdict(ctx context.Context, rec *ResponseVerdictRecord)
	ObserveDLPVerdict(ctx context.Context, rec *DLPVerdictRecord)
	ObserveCEEVerdict(ctx context.Context, rec *CEERecord)
	ObserveToolPolicyVerdict(ctx context.Context, rec *ToolPolicyRecord)
	ObserveToolScanVerdict(ctx context.Context, rec *ToolScanRecord)
	Close() error
}

// URLVerdictRecord holds the context for a URL-pipeline scan result.
type URLVerdictRecord struct {
	Subsurface        string
	Transport         string
	SessionID         string
	RequestID         string
	ConfigHash        string
	Agent             string
	Profile           string
	Request           CaptureRequest
	RawFindings       []Finding
	EffectiveFindings []Finding
	EffectiveAction   string
	Outcome           string
	SkipReason        string
}

// ResponseVerdictRecord holds the context for a response injection scan result.
type ResponseVerdictRecord struct {
	Subsurface        string
	Transport         string
	SessionID         string
	RequestID         string
	ConfigHash        string
	Agent             string
	Profile           string
	Request           CaptureRequest
	TransformKind     string
	WirePayload       []byte
	RawFindings       []Finding
	EffectiveFindings []Finding
	EffectiveAction   string
	Outcome           string
	SkipReason        string
}

// DLPVerdictRecord holds the context for a DLP body-scan result.
type DLPVerdictRecord struct {
	Subsurface        string
	Transport         string
	SessionID         string
	RequestID         string
	ConfigHash        string
	Agent             string
	Profile           string
	Request           CaptureRequest
	TransformKind     string
	ScannerInput      string
	RawFindings       []Finding
	EffectiveFindings []Finding
	EffectiveAction   string
	Outcome           string
	SkipReason        string
}

// CEERecord holds the context for a cross-entry entropy (CEE) scan result.
type CEERecord struct {
	Subsurface        string
	Transport         string
	SessionID         string
	RequestID         string
	ConfigHash        string
	Agent             string
	Profile           string
	Request           CaptureRequest
	TransformKind     string
	ScannerInput      string
	RawFindings       []Finding
	EffectiveFindings []Finding
	EffectiveAction   string
	Outcome           string
	SkipReason        string
}

// ToolPolicyRecord holds the context for a tool-policy evaluation result.
type ToolPolicyRecord struct {
	Subsurface        string
	Transport         string
	SessionID         string
	RequestID         string
	ConfigHash        string
	Agent             string
	Profile           string
	BatchIndex        *int
	Request           CaptureRequest
	RawFindings       []Finding
	EffectiveFindings []Finding
	EffectiveAction   string
	Outcome           string
	SkipReason        string
}

// ToolScanRecord holds the context for a tool-description scan result (tool
// poisoning detection, drift detection).
type ToolScanRecord struct {
	Subsurface        string
	Transport         string
	SessionID         string
	RequestID         string
	ConfigHash        string
	Agent             string
	Profile           string
	BatchIndex        *int
	Request           CaptureRequest
	TransformKind     string
	ScannerInput      string
	RawFindings       []Finding
	EffectiveFindings []Finding
	EffectiveAction   string
	Outcome           string
	SkipReason        string
}

// NopObserver implements CaptureObserver with no-ops. Use it when capture is
// disabled to avoid nil checks throughout the proxy and MCP scanner layers.
type NopObserver struct{}

// ObserveURLVerdict implements CaptureObserver.
func (NopObserver) ObserveURLVerdict(_ context.Context, _ *URLVerdictRecord) {}

// ObserveResponseVerdict implements CaptureObserver.
func (NopObserver) ObserveResponseVerdict(_ context.Context, _ *ResponseVerdictRecord) {}

// ObserveDLPVerdict implements CaptureObserver.
func (NopObserver) ObserveDLPVerdict(_ context.Context, _ *DLPVerdictRecord) {}

// ObserveCEEVerdict implements CaptureObserver.
func (NopObserver) ObserveCEEVerdict(_ context.Context, _ *CEERecord) {}

// ObserveToolPolicyVerdict implements CaptureObserver.
func (NopObserver) ObserveToolPolicyVerdict(_ context.Context, _ *ToolPolicyRecord) {}

// ObserveToolScanVerdict implements CaptureObserver.
func (NopObserver) ObserveToolScanVerdict(_ context.Context, _ *ToolScanRecord) {}

// Close implements CaptureObserver and is a no-op.
func (NopObserver) Close() error { return nil }
