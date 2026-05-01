// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package blockreason emits the X-Pipelock-Block-Reason header set on every
// pipelock block path. The header carries a small, finite vocabulary of
// machine-readable reason codes so agents can react intelligently to a block
// instead of treating every 403 as opaque.
//
// The schema is locked at v1. See docs/specs/block-reason-header.md for the
// canonical reason vocabulary, severity values, retry hints, and privacy rules.
//
// Privacy: header values must never carry matched secret content, DLP pattern
// names, agent identifiers, session IDs, or any user-attributable data. The
// header is operational metadata only.
package blockreason

import (
	"encoding/json"
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
type Info struct {
	Reason   Reason
	Severity Severity
	Retry    Retry

	// Layer is the scanner pipeline layer label, e.g. "dlp", "ssrf",
	// "rate_limit". Optional. Aligns with internal/scanner/ layer names.
	Layer string

	// Receipt is the receipt UUID for this block, if a receipt was emitted.
	// Lets the agent fetch richer context via the receipt-transports
	// endpoint. Optional.
	Receipt string
}

// SetHeaders writes the required headers and any populated optional headers
// onto h. Call BEFORE the response's WriteHeader; the headers are only
// honored by net/http when set before status is written.
func (i Info) SetHeaders(h http.Header) {
	if i.Reason == "" {
		// A block with no reason is a programming error in the call site.
		// We still emit the version header so consumers can detect the
		// schema; the reason header is omitted to preserve the invariant
		// that an emitted reason code is always one we documented.
		h.Set(HeaderVersion, SchemaVersion)
		return
	}
	h.Set(HeaderReason, string(i.Reason))
	h.Set(HeaderVersion, SchemaVersion)
	if i.Severity != "" {
		h.Set(HeaderSeverity, string(i.Severity))
	}
	if i.Retry != "" {
		h.Set(HeaderRetry, string(i.Retry))
	}
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
	Version     string `json:"version"`
	Severity    string `json:"severity,omitempty"`
	Retry       string `json:"retry,omitempty"`
	Layer       string `json:"layer,omitempty"`
	Receipt     string `json:"receipt,omitempty"`
}

// closeFrameMaxBytes is RFC 6455's close-frame reason payload limit (125 bytes
// total, minus 2 bytes for the close-status code = 123 bytes for UTF-8 reason).
const closeFrameMaxBytes = 123

// CloseFramePayload returns a JSON document for the WebSocket close-frame
// Reason field. If the full document would exceed RFC 6455's 123-byte limit,
// optional fields drop in this order: receipt, layer, retry, severity, version.
// The block_reason field is always present (or the result is "{}").
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
	// Even the bare {block_reason} can in principle exceed the limit if a
	// future code is unusually long. Return what we have; the WebSocket
	// caller is responsible for the final truncation policy.
	return out
}

// mustMarshal is json.Marshal with a known-good fixed-shape struct. The
// struct has no funky types (no interface{}, no time.Time, no big.Int) so
// json.Marshal cannot fail. We treat any error as a programming bug.
func mustMarshal(p closeFramePayload) string {
	b, err := json.Marshal(p)
	if err != nil {
		// Programmer error: closeFramePayload only contains strings.
		// Surface a stable sentinel rather than panic in a server path.
		return `{"block_reason":"parse_error","version":"1"}`
	}
	return string(b)
}
