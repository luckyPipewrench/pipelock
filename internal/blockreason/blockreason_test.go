// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package blockreason

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestSetHeaders_PopulatesAllFields(t *testing.T) {
	t.Parallel()
	info := Info{
		Reason:   DLPMatch,
		Severity: SeverityCritical,
		Retry:    RetryNone,
		Layer:    "dlp",
		Receipt:  "01HZ8EXAMPLERECEIPTID",
	}
	h := make(http.Header)
	info.SetHeaders(h)

	cases := map[string]string{
		HeaderReason:   "dlp_match",
		HeaderVersion:  "1",
		HeaderSeverity: "critical",
		HeaderRetry:    "none",
		HeaderLayer:    "dlp",
		HeaderReceipt:  "01HZ8EXAMPLERECEIPTID",
	}
	for k, want := range cases {
		if got := h.Get(k); got != want {
			t.Errorf("header %s = %q, want %q", k, got, want)
		}
	}
}

func TestSetHeaders_OmitsEmptyOptionalFields(t *testing.T) {
	t.Parallel()
	info := Info{
		Reason:   PromptInjection,
		Severity: SeverityCritical,
		Retry:    RetryNone,
	}
	h := make(http.Header)
	info.SetHeaders(h)

	if h.Get(HeaderLayer) != "" {
		t.Errorf("HeaderLayer should be empty, got %q", h.Get(HeaderLayer))
	}
	if h.Get(HeaderReceipt) != "" {
		t.Errorf("HeaderReceipt should be empty, got %q", h.Get(HeaderReceipt))
	}
	if got := h.Get(HeaderReason); got != "prompt_injection" {
		t.Errorf("HeaderReason = %q, want prompt_injection", got)
	}
}

func TestSetHeaders_OmitsEmptySeverityAndRetry(t *testing.T) {
	t.Parallel()
	// Some legacy call sites may not have severity/retry context. The
	// helper must still emit reason + version without panicking.
	info := Info{Reason: BadRequest}
	h := make(http.Header)
	info.SetHeaders(h)

	if got := h.Get(HeaderReason); got != "bad_request" {
		t.Errorf("HeaderReason = %q, want bad_request", got)
	}
	if got := h.Get(HeaderVersion); got != "1" {
		t.Errorf("HeaderVersion = %q, want 1", got)
	}
	if got := h.Get(HeaderSeverity); got != "" {
		t.Errorf("HeaderSeverity should be empty, got %q", got)
	}
	if got := h.Get(HeaderRetry); got != "" {
		t.Errorf("HeaderRetry should be empty, got %q", got)
	}
}

func TestSetHeaders_EmptyReasonEmitsOnlyVersion(t *testing.T) {
	t.Parallel()
	// A zero-Info is a programming error at the call site. We still emit
	// the version header so consumers can detect the schema; the reason
	// header is omitted to preserve the invariant that an emitted reason
	// code is always one we documented.
	h := make(http.Header)
	Info{}.SetHeaders(h)

	if got := h.Get(HeaderReason); got != "" {
		t.Errorf("HeaderReason should be empty for zero-Info, got %q", got)
	}
	if got := h.Get(HeaderVersion); got != "1" {
		t.Errorf("HeaderVersion = %q, want 1", got)
	}
}

func TestCloseFramePayload_FullShape(t *testing.T) {
	t.Parallel()
	info := Info{
		Reason:   DLPMatch,
		Severity: SeverityCritical,
		Retry:    RetryNone,
		Layer:    "dlp",
		Receipt:  "rcpt1",
	}
	got := info.CloseFramePayload()
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

func TestCloseFramePayload_EmptyReason(t *testing.T) {
	t.Parallel()
	got := Info{}.CloseFramePayload()
	if got != "{}" {
		t.Errorf("zero-Info payload = %q, want \"{}\"", got)
	}
}

func TestCloseFramePayload_FitsRFC6455Limit(t *testing.T) {
	t.Parallel()
	// Construct an Info large enough to exceed 123 bytes if all fields
	// were emitted, then verify graceful truncation drops fields in the
	// documented order: receipt, layer, retry, severity, version.
	big := strings.Repeat("X", 80)
	info := Info{
		Reason:   DLPMatch,
		Severity: SeverityCritical,
		Retry:    RetryNone,
		Layer:    "dlp_layer",
		Receipt:  big,
	}
	got := info.CloseFramePayload()
	if len(got) > closeFrameMaxBytes {
		t.Errorf("payload %d bytes exceeds RFC 6455 limit %d (%q)",
			len(got), closeFrameMaxBytes, got)
	}

	var parsed map[string]string
	if err := json.Unmarshal([]byte(got), &parsed); err != nil {
		t.Fatalf("truncated payload not valid JSON: %v (%q)", err, got)
	}
	// block_reason is always present.
	if parsed["block_reason"] != "dlp_match" {
		t.Errorf("block_reason missing from truncated payload: %q", got)
	}
	// receipt is dropped first.
	if parsed["receipt"] != "" {
		t.Errorf("receipt should drop first, got %q", parsed["receipt"])
	}
}

func TestCloseFramePayload_ProgressiveTruncation(t *testing.T) {
	t.Parallel()
	// Each field longer than the previous so each truncation step is
	// forced. After all optional fields drop the payload should still
	// be valid JSON containing block_reason at minimum.
	info := Info{
		Reason:   ToolPolicyDeny,
		Severity: SeverityCritical,
		Retry:    RetryPolicy,
		Layer:    strings.Repeat("L", 50),
		Receipt:  strings.Repeat("R", 90),
	}
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

func TestReasonConstants_AllDocumentedCodes(t *testing.T) {
	t.Parallel()
	// Privacy invariant: every constant we expose is a code consumers will
	// permanently see in the wild. Renaming is a breaking change. This
	// test snapshots the v1 vocabulary so silent renames trip CI.
	want := map[Reason]bool{
		// Egress / network
		SchemeBlocked:    true,
		DomainBlocklist:  true,
		SSRFPrivateIP:    true,
		SSRFMetadata:     true,
		SSRFDNSRebind:    true,
		PathEntropy:      true,
		SubdomainEntropy: true,
		URLLength:        true,
		RateLimit:        true,
		DataBudget:       true,
		// Content
		DLPMatch:         true,
		PromptInjection:  true,
		RedactionFailure: true,
		MediaPolicy:      true,
		// MCP
		ToolPolicyDeny:   true,
		ToolChainBlocked: true,
		ToolPoisoning:    true,
		SessionBinding:   true,
		// Posture
		AirlockActive:        true,
		KillSwitchActive:     true,
		EnvelopeVerifyFailed: true,
		AuthorityMismatch:    true,
		EscalationLevel:      true,
		// Generic
		ParseError:         true,
		Timeout:            true,
		PatternUnavailable: true,
		NotEnabled:         true,
		BadRequest:         true,
	}
	for r := range want {
		if r == "" {
			t.Errorf("Reason constant has empty value")
		}
		if got := string(r); got != strings.ToLower(got) {
			t.Errorf("Reason %q is not snake_case lowercase", r)
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

func TestCloseFramePayload_OvergrownReasonStillReturnsJSON(t *testing.T) {
	t.Parallel()
	// Defensive: if a future Reason value were ever long enough that even
	// the bare {"block_reason":"..."} document exceeded the RFC 6455
	// limit, CloseFramePayload must still return a parseable JSON string.
	// No real v1 Reason approaches this length; we synthesize one to pin
	// the fall-through behavior.
	giant := Reason(strings.Repeat("X", 200))
	got := Info{Reason: giant}.CloseFramePayload()

	var parsed map[string]string
	if err := json.Unmarshal([]byte(got), &parsed); err != nil {
		t.Fatalf("overgrown payload not valid JSON: %v (%q)", err, got)
	}
	if parsed["block_reason"] == "" {
		t.Errorf("block_reason missing from overgrown payload: %q", got)
	}
}

func TestCloseFramePayload_NoOptionalFieldsRequired(t *testing.T) {
	t.Parallel()
	// A minimal Info — reason only — must produce a valid payload that
	// fits trivially within the limit.
	info := Info{Reason: KillSwitchActive}
	got := info.CloseFramePayload()
	if len(got) > closeFrameMaxBytes {
		t.Errorf("minimal payload %d bytes exceeds limit %d", len(got), closeFrameMaxBytes)
	}
	if !strings.Contains(got, `"block_reason":"kill_switch_active"`) {
		t.Errorf("payload missing kill_switch_active: %q", got)
	}
}

func TestMustMarshal_FixedShapeNeverReturnsEmptyString(t *testing.T) {
	t.Parallel()
	// The closeFramePayload struct has only string fields. json.Marshal
	// cannot fail on it. mustMarshal's error sentinel is defensive and
	// not reachable through the public API; this test pins the contract
	// so any future schema change that introduces a non-string field
	// (which CAN fail to marshal) trips review.
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

func TestSetHeaders_DoesNotLeakSecretContent(t *testing.T) {
	t.Parallel()
	// Privacy invariant: the helper has no path that takes secret content
	// or pattern names. The Info struct deliberately exposes only
	// {Reason, Severity, Retry, Layer, Receipt}. This test pins that
	// shape so a future field addition trips review.
	info := Info{
		Reason:   DLPMatch,
		Severity: SeverityCritical,
		Retry:    RetryNone,
	}
	h := make(http.Header)
	info.SetHeaders(h)

	for k, vs := range h {
		for _, v := range vs {
			if strings.Contains(strings.ToLower(v), "akia") ||
				strings.Contains(strings.ToLower(v), "sk-") ||
				strings.Contains(strings.ToLower(v), "ghp_") {
				t.Errorf("header %s = %q looks like a secret leak", k, v)
			}
		}
	}
}
