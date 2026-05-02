// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package blockreason emits the X-Pipelock-Block-Reason header set on every
// pipelock block path. The header carries a small, finite vocabulary of
// machine-readable reason codes so agents can react intelligently to a block
// instead of treating every 403 as opaque.
//
// The schema is locked at v1. See docs/specs/block-reason-header.md for the
// canonical reason vocabulary, severity values, retry hints, layer-label
// mapping, and privacy rules.
//
// Construction: callers MUST use New(reason, severity, retry) — the required
// triple is enforced at construction time. Optional fields use the fluent
// WithLayer / WithReceipt helpers. Direct struct literals (Info{...}) bypass
// the invariant and should not be used outside tests of the helper itself.
//
// Privacy: header values must never carry matched secret content, DLP pattern
// names, agent identifiers, session IDs, or any user-attributable data. The
// header is operational metadata only.
package blockreason

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// HTTP response headers emitted on every block.
const (
	HeaderReason   = "X-Pipelock-Block-Reason"
	HeaderVersion  = "X-Pipelock-Block-Reason-Version"
	HeaderSeverity = "X-Pipelock-Block-Reason-Severity"
	HeaderRetry    = "X-Pipelock-Block-Reason-Retry"
	HeaderLayer    = "X-Pipelock-Block-Reason-Layer"
	HeaderReceipt  = "X-Pipelock-Block-Reason-Receipt"

	// SchemaVersion increments only on breaking changes. Additive changes
	// (new reason codes, new optional headers) keep v1.
	SchemaVersion = "1"
)

// Reason is a machine-readable block-reason code. The full vocabulary is
// defined as constants below and mirrored in docs/specs/block-reason-header.md.
type Reason string

const (
	// Egress / network layer.
	SchemeBlocked    Reason = "scheme_blocked"
	DomainBlocklist  Reason = "domain_blocklist"
	SSRFPrivateIP    Reason = "ssrf_private_ip"
	SSRFMetadata     Reason = "ssrf_metadata"
	SSRFDNSRebind    Reason = "ssrf_dns_rebind"
	PathEntropy      Reason = "path_entropy"
	SubdomainEntropy Reason = "subdomain_entropy"
	URLLength        Reason = "url_length"
	RateLimit        Reason = "rate_limit"
	DataBudget       Reason = "data_budget"

	// Content / payload layer.
	DLPMatch         Reason = "dlp_match"
	PromptInjection  Reason = "prompt_injection"
	RedactionFailure Reason = "redaction_failure"
	MediaPolicy      Reason = "media_policy"

	// MCP / tool layer.
	ToolPolicyDeny   Reason = "tool_policy_deny"
	ToolChainBlocked Reason = "tool_chain_blocked"
	ToolPoisoning    Reason = "tool_poisoning"
	SessionBinding   Reason = "session_binding"

	// Posture / runtime layer.
	AirlockActive        Reason = "airlock_active"
	KillSwitchActive     Reason = "kill_switch_active"
	EnvelopeVerifyFailed Reason = "envelope_verify_failed"
	AuthorityMismatch    Reason = "authority_mismatch"
	EscalationLevel      Reason = "escalation_level"

	// Generic.
	ParseError         Reason = "parse_error"
	Timeout            Reason = "timeout"
	PatternUnavailable Reason = "pattern_unavailable"
	NotEnabled         Reason = "not_enabled"
	BadRequest         Reason = "bad_request"
)

// Severity matches pipelock's existing severity vocabulary in
// internal/config/schema.go (SeverityInfo / SeverityWarn / SeverityCritical).
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarn     Severity = "warn"
	SeverityCritical Severity = "critical"
)

// Retry hints tell the agent whether and how to retry.
type Retry string

const (
	// RetryNone means the block is permanent for this request as-is.
	// Retrying without changing the input produces the same block.
	RetryNone Retry = "none"

	// RetryTransient means the condition is time-bound. Retry with backoff
	// may succeed (rate limits, airlock cooldown, kill switch deactivation).
	RetryTransient Retry = "transient"

	// RetryPolicy means the agent should only retry after an operator
	// changes pipelock policy (domain blocklist, tool policy, data budget).
	RetryPolicy Retry = "policy"
)

// Info is the operational metadata for a block. Privacy: never populate
// Layer or Receipt with anything that could identify matched content,
// session, or agent.
//
// Construct via New() so the required triple (reason, severity, retry) is
// enforced. Use WithLayer / WithReceipt for optional fields.
type Info struct {
	Reason   Reason
	Severity Severity
	Retry    Retry

	// Layer is the scanner pipeline layer label, e.g. "dlp", "ssrf",
	// "ratelimit". Optional. Aligns with internal/scanner/ Scanner*
	// constants so operators can correlate header-driven agent behavior
	// with their existing audit / metrics streams.
	Layer string

	// Receipt is the receipt UUID for this block, if a receipt was emitted.
	// Lets the agent fetch richer context via the receipt-transports
	// endpoint. Optional.
	Receipt string
}

// New constructs a complete Info. Reason, severity, and retry are required;
// New panics if any is empty. The panic surfaces a programming error in the
// call site — every documented reason has a fixed severity and retry hint
// per docs/specs/block-reason-header.md.
//
// This is consistent with the codebase's panic policy: panics flag
// post-validation programming errors, not runtime input.
func New(reason Reason, severity Severity, retry Retry) Info {
	if reason == "" || severity == "" || retry == "" {
		panic(fmt.Sprintf("blockreason.New: required field empty (reason=%q severity=%q retry=%q)",
			reason, severity, retry))
	}
	return Info{Reason: reason, Severity: severity, Retry: retry}
}

// WithLayer returns a copy of i with the Layer label set. Layer should be
// one of the internal/scanner/ Scanner* constants for operator correlation.
func (i Info) WithLayer(layer string) Info {
	i.Layer = layer
	return i
}

// WithReceipt returns a copy of i with the Receipt UUID set.
func (i Info) WithReceipt(receipt string) Info {
	i.Receipt = receipt
	return i
}

// SetHeaders writes all four required headers (reason, version, severity,
// retry) and any populated optional headers onto h. Call BEFORE the
// response's WriteHeader; net/http only honors headers set before status.
//
// SetHeaders unconditionally emits the four required headers. Empty values
// in the required slots indicate the Info was not constructed via New(),
// which is a contract violation — the headers will still emit (with empty
// values) but downstream consumers may treat that as a malformed block.
func (i Info) SetHeaders(h http.Header) {
	h.Set(HeaderReason, string(i.Reason))
	h.Set(HeaderVersion, SchemaVersion)
	h.Set(HeaderSeverity, string(i.Severity))
	h.Set(HeaderRetry, string(i.Retry))
	if i.Layer != "" {
		h.Set(HeaderLayer, i.Layer)
	}
	if i.Receipt != "" {
		h.Set(HeaderReceipt, i.Receipt)
	}
}

// closeFramePayload is the JSON shape carried in WebSocket close-frame Reason
// fields. Field names mirror the header set without the X-Pipelock prefix.
type closeFramePayload struct {
	BlockReason string `json:"block_reason"`
	Version     string `json:"version,omitempty"`
	Severity    string `json:"severity,omitempty"`
	Retry       string `json:"retry,omitempty"`
	Layer       string `json:"layer,omitempty"`
	Receipt     string `json:"receipt,omitempty"`
}

// closeFrameMaxBytes is RFC 6455's close-frame reason payload limit (125 bytes
// total, minus 2 bytes for the close-status code = 123 bytes for UTF-8 reason).
const closeFrameMaxBytes = 123

// closeFrameOverflowFallback is a fixed sentinel that is guaranteed to fit
// within closeFrameMaxBytes. Used when even the bare {"block_reason":"..."}
// would overflow because the Reason value is unusually long. The fallback
// preserves a useful signal (parse_error severity warn / retry none, by
// schema convention) while honoring the byte ceiling.
const closeFrameOverflowFallback = `{"block_reason":"parse_error","version":"1"}`

// CloseFramePayload returns a JSON document for the WebSocket close-frame
// Reason field. The result is GUARANTEED to be at most closeFrameMaxBytes
// bytes (RFC 6455's 123-byte ceiling). To honor the ceiling, optional
// fields drop in this order: receipt, layer, retry, severity, version.
// If even the bare {"block_reason":"<code>"} would overflow (extremely
// long Reason values), CloseFramePayload returns the fixed fallback
// closeFrameOverflowFallback rather than a malformed close frame.
//
// CloseFramePayload assumes Info was constructed via New(); a zero Info
// returns an empty-object sentinel.
func (i Info) CloseFramePayload() string {
	if i.Reason == "" {
		return "{}"
	}
	p := closeFramePayload{
		BlockReason: string(i.Reason),
		Version:     SchemaVersion,
		Severity:    string(i.Severity),
		Retry:       string(i.Retry),
		Layer:       i.Layer,
		Receipt:     i.Receipt,
	}
	out := mustMarshal(p)
	if len(out) <= closeFrameMaxBytes {
		return out
	}

	// Drop optional fields in order until the payload fits.
	dropFields := []func(*closeFramePayload){
		func(p *closeFramePayload) { p.Receipt = "" },
		func(p *closeFramePayload) { p.Layer = "" },
		func(p *closeFramePayload) { p.Retry = "" },
		func(p *closeFramePayload) { p.Severity = "" },
		func(p *closeFramePayload) { p.Version = "" },
	}
	for _, drop := range dropFields {
		drop(&p)
		out = mustMarshal(p)
		if len(out) <= closeFrameMaxBytes {
			return out
		}
	}
	// Even the bare {"block_reason":"<code>"} doesn't fit: the Reason value
	// is so long that we can't honor the byte ceiling without dropping the
	// only required field. Return the fixed fallback so the close frame is
	// always RFC 6455-compliant.
	return closeFrameOverflowFallback
}

// mustMarshal is json.Marshal with a known-good fixed-shape struct. The
// struct has only string fields (no interface{}, no time.Time) so
// json.Marshal cannot fail. The error fallback is defensive code; if it
// ever fires, treat it as a programming bug, not a runtime condition.
func mustMarshal(p closeFramePayload) string {
	b, err := json.Marshal(p)
	if err != nil {
		// Defensive: closeFramePayload only contains strings.
		return closeFrameOverflowFallback
	}
	return string(b)
}
