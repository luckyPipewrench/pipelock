// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package blockreason emits the X-Pipelock-Block-Reason header set on every
// pipelock block path. The header carries a small, finite vocabulary of
// machine-readable reason codes so agents can react intelligently to a block
// instead of treating every 403 as opaque.
//
// The schema is locked at v1. See docs/specs/block-reason-header.md for the
// canonical reason vocabulary, severity values, retry hints, layer-label
// mapping, receipt format, and privacy rules.
//
// Construction: callers MUST use New(reason, severity, retry) which validates
// every required field against the fixed v1 vocabulary. Optional fields use
// the WithLayer / WithReceipt builders, both of which validate before
// returning. Direct struct literals (Info{...}) bypass validation; use them
// only inside this package's tests.
//
// Privacy: the validators reject any value that is not in the fixed vocabulary
// or the documented opaque-ID format. Headers and close-frame payloads emitted
// by this package therefore cannot carry matched secret content, DLP pattern
// names, agent identifiers, or session IDs even if a future caller mistakenly
// tries.
package blockreason

import (
	"encoding/json"
	"errors"
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

	// layerMaxLen bounds the layer header value. The longest scanner label
	// at v1 is "subdomain_entropy" (17 chars); 32 leaves headroom.
	layerMaxLen = 32
	// receiptLen is the fixed Crockford-base32 ULID length. Receipts that
	// don't match this length are rejected at WithReceipt time.
	receiptLen = 26
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
	AirlockActive          Reason = "airlock_active"
	KillSwitchActive       Reason = "kill_switch_active"
	EnvelopeVerifyFailed   Reason = "envelope_verify_failed"
	OutboundEnvelopeFailed Reason = "outbound_envelope_failed"
	RedirectScanDenied     Reason = "redirect_scan_denied"
	AuthorityMismatch      Reason = "authority_mismatch"
	EscalationLevel        Reason = "escalation_level"
	SessionAnomaly         Reason = "session_anomaly"
	CrossRequestDeny       Reason = "cross_request_deny"
	CompressedResponse     Reason = "compressed_response"
	BrowserShieldOversize  Reason = "browser_shield_oversize"

	// Generic.
	ParseError         Reason = "parse_error"
	Timeout            Reason = "timeout"
	PatternUnavailable Reason = "pattern_unavailable"
	NotEnabled         Reason = "not_enabled"
	BadRequest         Reason = "bad_request"

	// Contract / learn-and-lock layer. The first four are real blocks
	// produced by the runtime evaluator under an active contract;
	// ContractObservedOnly is an info-tier annotation surfaced in
	// shadow / capture modes when the live verdict would have blocked but
	// the configured mode does not enforce. ContractObservedOnly never
	// appears on a 4xx response surface, so it is exempt from the
	// production-emit-site matrix gate.
	ContractDefaultDeny    Reason = "contract_default_deny"
	ContractEnforceDefault Reason = "contract_enforce_default"
	ContractNonDefaultPort Reason = "contract_non_default_port"
	ContractInvalidPath    Reason = "contract_invalid_path"
	ContractObservedOnly   Reason = "contract_observed_only"

	// BlockReasonOverflow is the dedicated sentinel CloseFramePayload uses
	// when an Info has somehow accumulated a Reason value too long to fit
	// the bare {block_reason: <code>} payload within RFC 6455's 123-byte
	// close-frame limit. Distinct from ParseError because it preserves the
	// signal that the block emit metadata itself was malformed, rather than
	// silently re-classifying the block as a parser failure.
	BlockReasonOverflow Reason = "block_reason_overflow"
)

// validReasons is the fixed v1 allowlist enforced at construction.
var validReasons = map[Reason]struct{}{
	SchemeBlocked:          {},
	DomainBlocklist:        {},
	SSRFPrivateIP:          {},
	SSRFMetadata:           {},
	SSRFDNSRebind:          {},
	PathEntropy:            {},
	SubdomainEntropy:       {},
	URLLength:              {},
	RateLimit:              {},
	DataBudget:             {},
	DLPMatch:               {},
	PromptInjection:        {},
	RedactionFailure:       {},
	MediaPolicy:            {},
	ToolPolicyDeny:         {},
	ToolChainBlocked:       {},
	ToolPoisoning:          {},
	SessionBinding:         {},
	AirlockActive:          {},
	KillSwitchActive:       {},
	EnvelopeVerifyFailed:   {},
	OutboundEnvelopeFailed: {},
	RedirectScanDenied:     {},
	AuthorityMismatch:      {},
	EscalationLevel:        {},
	SessionAnomaly:         {},
	CrossRequestDeny:       {},
	CompressedResponse:     {},
	BrowserShieldOversize:  {},
	ParseError:             {},
	Timeout:                {},
	PatternUnavailable:     {},
	NotEnabled:             {},
	BadRequest:             {},
	BlockReasonOverflow:    {},
	ContractDefaultDeny:    {},
	ContractEnforceDefault: {},
	ContractNonDefaultPort: {},
	ContractInvalidPath:    {},
	ContractObservedOnly:   {},
}

// AllReasons returns every Reason in the canonical allowlist. The returned
// slice is freshly allocated on each call so callers can sort or filter
// without affecting the package state. Order is not guaranteed.
func AllReasons() []Reason {
	out := make([]Reason, 0, len(validReasons))
	for r := range validReasons {
		out = append(out, r)
	}
	return out
}

// Severity matches pipelock's existing severity vocabulary in
// internal/config/schema.go (SeverityInfo / SeverityWarn / SeverityCritical).
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarn     Severity = "warn"
	SeverityCritical Severity = "critical"
)

var validSeverities = map[Severity]struct{}{
	SeverityInfo:     {},
	SeverityWarn:     {},
	SeverityCritical: {},
}

// Retry hints tell the agent whether and how to retry.
type Retry string

const (
	// RetryNone means the block is permanent for this request as-is.
	RetryNone Retry = "none"
	// RetryTransient means the condition is time-bound; backoff may help.
	RetryTransient Retry = "transient"
	// RetryPolicy means the agent should only retry after an operator
	// changes pipelock policy.
	RetryPolicy Retry = "policy"
	// RetryCanonicalize means the request as posed will not succeed because
	// it carries a non-canonical input (today: a URL path that fails RFC 3986
	// canonicalization). The agent SHOULD canonicalize the request and retry;
	// no operator change is required. The wire value mirrors the spec hint
	// "retry-with-canonical-path" so consumers see actionable guidance in
	// X-Pipelock-Block-Reason-Retry instead of a generic "none".
	RetryCanonicalize Retry = "retry-with-canonical-path"
)

var validRetries = map[Retry]struct{}{
	RetryNone:         {},
	RetryTransient:    {},
	RetryPolicy:       {},
	RetryCanonicalize: {},
}

// Construction errors. Use errors.Is to pattern-match.
var (
	ErrInvalidReason   = errors.New("blockreason: reason is not in the v1 vocabulary")
	ErrInvalidSeverity = errors.New("blockreason: severity is not in the v1 vocabulary")
	ErrInvalidRetry    = errors.New("blockreason: retry is not in the v1 vocabulary")
	ErrInvalidLayer    = errors.New("blockreason: layer must be ASCII alphanumeric/underscore and within length bound")
	ErrInvalidReceipt  = errors.New("blockreason: receipt must be ULID-shaped (Crockford base32, 26 chars) or empty")
)

// Info is the operational metadata for a block.
//
// Info instances should always come from New() + WithLayer() / WithReceipt().
// The fields are exported because the surrounding codebase prefers exported
// fields for tests; do not rely on direct struct construction outside this
// package's tests.
type Info struct {
	Reason   Reason
	Severity Severity
	Retry    Retry
	Layer    string
	Receipt  string
}

// New constructs an Info, validating reason / severity / retry against the
// fixed v1 vocabulary. Returns ErrInvalidReason / ErrInvalidSeverity /
// ErrInvalidRetry on a vocabulary miss.
//
// Designed for the enforcement hot path: never panics. Call sites should
// propagate the error to a fail-closed branch — typically by treating an
// invalid Info as a programming bug while still emitting the underlying
// 4xx without the reason headers.
func New(reason Reason, severity Severity, retry Retry) (Info, error) {
	if _, ok := validReasons[reason]; !ok {
		return Info{}, fmt.Errorf("%w: %q", ErrInvalidReason, reason)
	}
	if _, ok := validSeverities[severity]; !ok {
		return Info{}, fmt.Errorf("%w: %q", ErrInvalidSeverity, severity)
	}
	if _, ok := validRetries[retry]; !ok {
		return Info{}, fmt.Errorf("%w: %q", ErrInvalidRetry, retry)
	}
	return Info{Reason: reason, Severity: severity, Retry: retry}, nil
}

// MustNew is the panicking variant of New. Reserved for compile-time-known
// constants and tests; never use it on the request hot path.
func MustNew(reason Reason, severity Severity, retry Retry) Info {
	info, err := New(reason, severity, retry)
	if err != nil {
		panic(fmt.Sprintf("blockreason.MustNew: %v", err))
	}
	return info
}

// WithLayer returns a copy of i with the Layer label set. Layer should be
// one of the internal/scanner/ Scanner* constants for operator correlation.
// Returns ErrInvalidLayer if layer contains any non-ASCII-alphanumeric/underscore
// byte or exceeds layerMaxLen. Empty layer is allowed (clears the optional field).
func (i Info) WithLayer(layer string) (Info, error) {
	if !validLayer(layer) {
		return Info{}, fmt.Errorf("%w: %q", ErrInvalidLayer, layer)
	}
	i.Layer = layer
	return i, nil
}

// WithReceipt returns a copy of i with the Receipt set. Receipt MUST be
// either empty or a 26-character Crockford-base32 ULID (the format the
// receipt subsystem emits). The strict validation prevents arbitrary
// strings — and therefore arbitrary attacker-controlled metadata — from
// reaching agent-visible response headers via the Receipt slot.
func (i Info) WithReceipt(receipt string) (Info, error) {
	if !validReceipt(receipt) {
		return Info{}, fmt.Errorf("%w: %q", ErrInvalidReceipt, receipt)
	}
	i.Receipt = receipt
	return i, nil
}

// isLayerByte returns true for the byte alphabet that internal/scanner/
// Scanner* constants use: ASCII alphanumeric and underscore.
func isLayerByte(c byte) bool {
	return (c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') ||
		c == '_'
}

// validLayer permits only the layer byte alphabet, bounded by layerMaxLen.
// Empty is allowed (clears the optional Layer field).
func validLayer(s string) bool {
	if len(s) > layerMaxLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isLayerByte(s[i]) {
			return false
		}
	}
	return true
}

// isReceiptByte returns true for the Crockford-base32 ULID alphabet:
// 0-9 plus A-Z minus I, L, O, U (excluded to avoid ambiguity).
func isReceiptByte(c byte) bool {
	switch {
	case c >= '0' && c <= '9':
		return true
	case c >= 'A' && c <= 'Z' && c != 'I' && c != 'L' && c != 'O' && c != 'U':
		return true
	}
	return false
}

// validReceipt permits only the receipt byte alphabet at the fixed
// receiptLen, or empty (clears the optional Receipt field).
func validReceipt(s string) bool {
	if s == "" {
		return true
	}
	if len(s) != receiptLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isReceiptByte(s[i]) {
			return false
		}
	}
	return true
}

// SetHeaders writes all four required headers (reason, version, severity,
// retry) and any populated optional headers onto h. Call BEFORE the
// response's WriteHeader; net/http only honors headers set before status.
//
// SetHeaders trusts the Info to be well-formed (constructed via New +
// WithLayer + WithReceipt). Empty required slots indicate a contract
// violation; the headers still emit but downstream consumers may treat
// the block as malformed.
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

// closeFrameOverflowFallback preserves the operational signal that the block
// metadata was malformed (BlockReasonOverflow) rather than silently
// reclassifying the block as a parser failure. Always fits within
// closeFrameMaxBytes (44 bytes).
const closeFrameOverflowFallback = `{"block_reason":"block_reason_overflow","version":"1"}`

// CloseFramePayload returns a JSON document for the WebSocket close-frame
// Reason field. The result is GUARANTEED to be at most closeFrameMaxBytes
// bytes (RFC 6455's 123-byte ceiling). To honor the ceiling, optional
// fields drop in this order: receipt, layer, retry, severity, version.
// If even the bare {"block_reason":"<code>"} would overflow because the
// Reason value is unusually long, CloseFramePayload returns
// closeFrameOverflowFallback (block_reason_overflow). The fallback
// preserves the security signal that the block metadata is malformed,
// rather than silently downgrading to parse_error.
//
// CloseFramePayload trusts the Info was constructed via New(); a zero Info
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
	return closeFrameOverflowFallback
}

// mustMarshal is json.Marshal with a known-good fixed-shape struct. The
// struct has only string fields (no interface{}, no time.Time) so
// json.Marshal cannot fail on real input. The error fallback is defensive
// code; it would surface the BlockReasonOverflow sentinel rather than a
// silent zero value.
func mustMarshal(p closeFramePayload) string {
	b, err := json.Marshal(p)
	if err != nil {
		return closeFrameOverflowFallback
	}
	return string(b)
}

// SeverityFor returns the canonical severity for a block-reason code per
// docs/specs/block-reason-header.md. The mapping is locked at v1; new
// reasons must add a case here at the same time the constant is added.
// Unknown reasons return SeverityCritical so a missing-mapping bug
// fails closed (the reason is real enough to constructor-validate, but
// the operator gets the strictest severity until the table is updated).
func SeverityFor(reason Reason) Severity {
	switch reason {
	case NotEnabled, BadRequest, ContractObservedOnly:
		return SeverityInfo
	case SchemeBlocked,
		PathEntropy,
		SubdomainEntropy,
		URLLength,
		RateLimit,
		DataBudget,
		MediaPolicy,
		ParseError,
		Timeout,
		PatternUnavailable,
		CompressedResponse,
		BrowserShieldOversize,
		BlockReasonOverflow,
		ContractNonDefaultPort,
		ContractInvalidPath:
		return SeverityWarn
	default:
		return SeverityCritical
	}
}

// RetryFor returns the canonical retry hint for a block-reason code per
// docs/specs/block-reason-header.md. As with SeverityFor, the mapping is
// locked at v1 and unknown reasons fail closed: an unrecognised reason
// returns RetryNone so the agent does not retry blindly.
func RetryFor(reason Reason) Retry {
	switch reason {
	case SSRFDNSRebind,
		RateLimit,
		AirlockActive,
		KillSwitchActive,
		EscalationLevel,
		RedactionFailure,
		Timeout,
		PatternUnavailable,
		OutboundEnvelopeFailed,
		SessionAnomaly,
		BlockReasonOverflow:
		return RetryTransient
	case DomainBlocklist,
		PathEntropy,
		SubdomainEntropy,
		URLLength,
		DataBudget,
		MediaPolicy,
		ToolPolicyDeny,
		SessionBinding,
		AuthorityMismatch,
		NotEnabled,
		CompressedResponse,
		BrowserShieldOversize:
		return RetryPolicy
	case ContractInvalidPath:
		return RetryCanonicalize
	default:
		return RetryNone
	}
}

// NewForReason is the recommended constructor for production block paths.
// It looks up the canonical severity + retry pair from the v1 spec
// (SeverityFor / RetryFor) so call sites cannot accidentally emit a
// mismatched pair such as `dlp_match` + `info` + `policy`. Equivalent to
// New(reason, SeverityFor(reason), RetryFor(reason)).
//
// The lower-level New constructor remains available for tests and edge
// cases that legitimately need to assemble an Info with a non-canonical
// pair (e.g. the redteam suite proving the validators reject every axis).
// Production callers should default to NewForReason.
func NewForReason(reason Reason) (Info, error) {
	return New(reason, SeverityFor(reason), RetryFor(reason))
}

// MustNewForReason is NewForReason that panics on construction error.
// Use only at startup or in test setup; production paths should use
// NewForReason and route an error to a parse_error fallback.
func MustNewForReason(reason Reason) Info {
	info, err := NewForReason(reason)
	if err != nil {
		panic(err)
	}
	return info
}
