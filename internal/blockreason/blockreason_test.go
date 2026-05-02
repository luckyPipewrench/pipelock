// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package blockreason

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestNew_RequiredTriple(t *testing.T) {
	t.Parallel()
	info := New(DLPMatch, SeverityCritical, RetryNone)
	if info.Reason != DLPMatch {
		t.Errorf("Reason = %q, want %q", info.Reason, DLPMatch)
	}
	if info.Severity != SeverityCritical {
		t.Errorf("Severity = %q, want %q", info.Severity, SeverityCritical)
	}
	if info.Retry != RetryNone {
		t.Errorf("Retry = %q, want %q", info.Retry, RetryNone)
	}
}

func TestNew_PanicsOnEmptyRequiredField(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		reason   Reason
		severity Severity
		retry    Retry
	}{
		{"empty reason", "", SeverityCritical, RetryNone},
		{"empty severity", DLPMatch, "", RetryNone},
		{"empty retry", DLPMatch, SeverityCritical, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r == nil {
					t.Errorf("expected panic for %s, got none", tc.name)
				}
			}()
			_ = New(tc.reason, tc.severity, tc.retry)
		})
	}
}

func TestWithLayer_AndWithReceipt(t *testing.T) {
	t.Parallel()
	info := New(DLPMatch, SeverityCritical, RetryNone).
		WithLayer("dlp").
		WithReceipt("01HZ8EXAMPLE")
	if info.Layer != "dlp" {
		t.Errorf("Layer = %q, want %q", info.Layer, "dlp")
	}
	if info.Receipt != "01HZ8EXAMPLE" {
		t.Errorf("Receipt = %q, want %q", info.Receipt, "01HZ8EXAMPLE")
	}
}

func TestSetHeaders_AlwaysEmitsRequiredFour(t *testing.T) {
	t.Parallel()
	// Required headers must always emit. Empty values still surface so a
	// downstream consumer can detect a malformed block from a misconstructed
	// Info — the only way to get an empty required header is bypassing New().
	info := New(SSRFPrivateIP, SeverityCritical, RetryNone)
	h := make(http.Header)
	info.SetHeaders(h)

	required := map[string]string{
		HeaderReason:   "ssrf_private_ip",
		HeaderVersion:  "1",
		HeaderSeverity: "critical",
		HeaderRetry:    "none",
	}
	for k, want := range required {
		if got := h.Get(k); got != want {
			t.Errorf("required header %s = %q, want %q", k, got, want)
		}
	}
}

func TestSetHeaders_OptionalFieldsSurfaceWhenSet(t *testing.T) {
	t.Parallel()
	info := New(DLPMatch, SeverityCritical, RetryNone).
		WithLayer("dlp").
		WithReceipt("01HZ8EXAMPLE")
	h := make(http.Header)
	info.SetHeaders(h)

	if got := h.Get(HeaderLayer); got != "dlp" {
		t.Errorf("HeaderLayer = %q, want %q", got, "dlp")
	}
	if got := h.Get(HeaderReceipt); got != "01HZ8EXAMPLE" {
		t.Errorf("HeaderReceipt = %q, want %q", got, "01HZ8EXAMPLE")
	}
}

func TestSetHeaders_OmitsOptionalFieldsWhenUnset(t *testing.T) {
	t.Parallel()
	info := New(PromptInjection, SeverityCritical, RetryNone)
	h := make(http.Header)
	info.SetHeaders(h)

	if h.Get(HeaderLayer) != "" {
		t.Errorf("HeaderLayer should be empty, got %q", h.Get(HeaderLayer))
	}
	if h.Get(HeaderReceipt) != "" {
		t.Errorf("HeaderReceipt should be empty, got %q", h.Get(HeaderReceipt))
	}
}

func TestCloseFramePayload_FullShape(t *testing.T) {
	t.Parallel()
	info := New(DLPMatch, SeverityCritical, RetryNone).
		WithLayer("dlp").
		WithReceipt("rcpt1")
	got := info.CloseFramePayload()

	if len(got) > closeFrameMaxBytes {
		t.Errorf("payload %d bytes exceeds RFC 6455 limit %d", len(got), closeFrameMaxBytes)
	}
	var parsed map[string]string
	if err := json.Unmarshal([]byte(got), &parsed); err != nil {
		t.Fatalf("payload not valid JSON: %v (%q)", err, got)
	}
	want := map[string]string{
		"block_reason": "dlp_match",
		"version":      "1",
		"severity":     "critical",
		"retry":        "none",
		"layer":        "dlp",
		"receipt":      "rcpt1",
	}
	for k, v := range want {
		if parsed[k] != v {
			t.Errorf("payload[%q] = %q, want %q", k, parsed[k], v)
		}
	}
}

func TestCloseFramePayload_ZeroInfoSentinel(t *testing.T) {
	t.Parallel()
	got := Info{}.CloseFramePayload()
	if got != "{}" {
		t.Errorf("zero-Info payload = %q, want \"{}\"", got)
	}
}

func TestCloseFramePayload_AlwaysFitsRFC6455Limit(t *testing.T) {
	t.Parallel()
	// Invariant: the helper owns RFC 6455 framing semantics. Every output
	// must fit within closeFrameMaxBytes regardless of input. This test
	// covers normal, optional-field-truncated, and overlong-Reason cases.
	cases := []struct {
		name string
		info Info
	}{
		{"normal", New(DLPMatch, SeverityCritical, RetryNone)},
		{"with optional fields", New(DLPMatch, SeverityCritical, RetryNone).
			WithLayer("dlp").WithReceipt("01HZ8EXAMPLE")},
		{"large receipt forces drop", New(ToolPolicyDeny, SeverityCritical, RetryPolicy).
			WithLayer(strings.Repeat("L", 50)).
			WithReceipt(strings.Repeat("R", 90))},
		{"overlong reason forces fallback", Info{
			Reason: Reason(strings.Repeat("X", 200)),
		}},
		{"barely-fitting reason at floor", Info{
			Reason: Reason(strings.Repeat("X", 100)),
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.info.CloseFramePayload()
			if len(got) > closeFrameMaxBytes {
				t.Errorf("payload %d bytes exceeds RFC 6455 limit %d (%q)",
					len(got), closeFrameMaxBytes, got)
			}
			var parsed map[string]string
			if err := json.Unmarshal([]byte(got), &parsed); err != nil {
				t.Fatalf("payload not valid JSON: %v (%q)", err, got)
			}
			if parsed["block_reason"] == "" {
				t.Errorf("block_reason missing: %q", got)
			}
		})
	}
}

func TestCloseFramePayload_OverlongReasonReturnsFallback(t *testing.T) {
	t.Parallel()
	// When the Reason itself exceeds what can fit in a bare
	// {"block_reason":"..."} document, CloseFramePayload returns a fixed
	// fallback rather than a malformed close frame.
	info := Info{Reason: Reason(strings.Repeat("X", 200))}
	got := info.CloseFramePayload()
	if got != closeFrameOverflowFallback {
		t.Errorf("overlong-reason payload = %q, want fallback %q",
			got, closeFrameOverflowFallback)
	}
	if len(got) > closeFrameMaxBytes {
		t.Errorf("fallback %d bytes exceeds RFC 6455 limit %d", len(got), closeFrameMaxBytes)
	}
}

func TestCloseFramePayload_ProgressiveTruncation(t *testing.T) {
	t.Parallel()
	// Force each truncation step to fire so the fall-through algorithm is
	// fully exercised. The receipt drops first, then layer, then retry,
	// then severity, then version. block_reason always remains.
	info := New(ToolPolicyDeny, SeverityCritical, RetryPolicy).
		WithLayer(strings.Repeat("L", 50)).
		WithReceipt(strings.Repeat("R", 90))
	got := info.CloseFramePayload()

	if len(got) > closeFrameMaxBytes {
		t.Errorf("progressive truncation failed: %d bytes > %d (%q)",
			len(got), closeFrameMaxBytes, got)
	}
	var parsed map[string]string
	if err := json.Unmarshal([]byte(got), &parsed); err != nil {
		t.Fatalf("not JSON after truncation: %v (%q)", err, got)
	}
	if parsed["block_reason"] != "tool_policy_deny" {
		t.Errorf("block_reason missing after truncation: %q", got)
	}
}

func TestReasonConstants_AllSnakeCase(t *testing.T) {
	t.Parallel()
	// Privacy and contract: every constant is a code consumers will
	// permanently see in the wild. Renaming is a breaking change. This
	// test snapshots the v1 vocabulary so silent renames trip CI.
	codes := []Reason{
		// Egress / network
		SchemeBlocked, DomainBlocklist, SSRFPrivateIP, SSRFMetadata, SSRFDNSRebind,
		PathEntropy, SubdomainEntropy, URLLength, RateLimit, DataBudget,
		// Content
		DLPMatch, PromptInjection, RedactionFailure, MediaPolicy,
		// MCP
		ToolPolicyDeny, ToolChainBlocked, ToolPoisoning, SessionBinding,
		// Posture
		AirlockActive, KillSwitchActive, EnvelopeVerifyFailed, AuthorityMismatch, EscalationLevel,
		// Generic
		ParseError, Timeout, PatternUnavailable, NotEnabled, BadRequest,
	}
	for _, r := range codes {
		s := string(r)
		if s == "" {
			t.Errorf("Reason constant has empty value")
		}
		if s != strings.ToLower(s) {
			t.Errorf("Reason %q is not lowercase", r)
		}
	}
}

func TestSeverityConstants_MatchExistingVocabulary(t *testing.T) {
	t.Parallel()
	// Severity values must match internal/config/schema.go vocabulary
	// (info / warn / critical) so operators can correlate header-driven
	// agent behavior with their existing emit / receipt streams.
	cases := map[Severity]string{
		SeverityInfo:     "info",
		SeverityWarn:     "warn",
		SeverityCritical: "critical",
	}
	for s, want := range cases {
		if string(s) != want {
			t.Errorf("Severity %v = %q, want %q", s, string(s), want)
		}
	}
}

func TestRetryConstants_v1Vocabulary(t *testing.T) {
	t.Parallel()
	cases := map[Retry]string{
		RetryNone:      "none",
		RetryTransient: "transient",
		RetryPolicy:    "policy",
	}
	for r, want := range cases {
		if string(r) != want {
			t.Errorf("Retry %v = %q, want %q", r, string(r), want)
		}
	}
}

func TestSetHeaders_DoesNotLeakSecretContent(t *testing.T) {
	t.Parallel()
	// Privacy invariant: the Info struct deliberately exposes only
	// {Reason, Severity, Retry, Layer, Receipt}. None of those fields
	// can carry matched content, pattern names, or agent identifiers
	// without an explicit (and reviewable) call-site decision. This test
	// pins the surface so a future field addition trips review.
	info := New(DLPMatch, SeverityCritical, RetryNone)
	h := make(http.Header)
	info.SetHeaders(h)

	for k, vs := range h {
		for _, v := range vs {
			lc := strings.ToLower(v)
			if strings.Contains(lc, "akia") ||
				strings.Contains(lc, "sk-") ||
				strings.Contains(lc, "ghp_") {
				t.Errorf("header %s = %q looks like a secret leak", k, v)
			}
		}
	}
}

func TestMustMarshal_FixedShapeProducesValidJSON(t *testing.T) {
	t.Parallel()
	got := mustMarshal(closeFramePayload{
		BlockReason: "dlp_match",
		Version:     "1",
	})
	if got == "" {
		t.Errorf("mustMarshal returned empty for valid input")
	}
	var parsed map[string]string
	if err := json.Unmarshal([]byte(got), &parsed); err != nil {
		t.Fatalf("mustMarshal output not valid JSON: %v (%q)", err, got)
	}
	if parsed["block_reason"] != "dlp_match" {
		t.Errorf("block_reason round-trip failed: got %q", parsed["block_reason"])
	}
}
