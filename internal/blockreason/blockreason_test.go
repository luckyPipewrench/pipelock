// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package blockreason

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
)

// validULID is a 26-char Crockford-base32 string (no I, L, O, U).
const validULID = "01J0GNYZ7XSQRTQ8FPYM5BHX2K"

func TestNew_AcceptsValidTriple(t *testing.T) {
	t.Parallel()
	info, err := New(DLPMatch, SeverityCritical, RetryNone)
	if err != nil {
		t.Fatalf("New returned error for valid input: %v", err)
	}
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

func TestNew_RejectsInvalidVocabulary(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		reason   Reason
		severity Severity
		retry    Retry
		wantErr  error
	}{
		{"unknown reason", "made_up_reason", SeverityCritical, RetryNone, ErrInvalidReason},
		{"empty reason", "", SeverityCritical, RetryNone, ErrInvalidReason},
		{"unknown severity", DLPMatch, "boom", RetryNone, ErrInvalidSeverity},
		{"empty severity", DLPMatch, "", RetryNone, ErrInvalidSeverity},
		{"unknown retry", DLPMatch, SeverityCritical, "later", ErrInvalidRetry},
		{"empty retry", DLPMatch, SeverityCritical, "", ErrInvalidRetry},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(tc.reason, tc.severity, tc.retry)
			if err == nil {
				t.Errorf("expected error for %s, got nil", tc.name)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("error = %v, want wrap of %v", err, tc.wantErr)
			}
		})
	}
}

func TestMustNew_PanicsOnInvalid(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("expected panic for invalid MustNew")
		}
	}()
	_ = MustNew("nope", SeverityCritical, RetryNone)
}

func TestMustNew_OkOnValid(t *testing.T) {
	t.Parallel()
	info := MustNew(DLPMatch, SeverityCritical, RetryNone)
	if info.Reason != DLPMatch {
		t.Errorf("Reason = %q", info.Reason)
	}
}

func TestWithLayer_AcceptsValidScannerLabel(t *testing.T) {
	t.Parallel()
	base := MustNew(DLPMatch, SeverityCritical, RetryNone)
	got, err := base.WithLayer("dlp")
	if err != nil {
		t.Fatalf("WithLayer error: %v", err)
	}
	if got.Layer != "dlp" {
		t.Errorf("Layer = %q, want dlp", got.Layer)
	}
}

func TestWithLayer_RejectsInvalid(t *testing.T) {
	t.Parallel()
	base := MustNew(DLPMatch, SeverityCritical, RetryNone)
	cases := []struct {
		name  string
		layer string
	}{
		{"control char", "dlp\n"},
		{"slash", "dl/p"},
		{"space", "dl p"},
		{"too long", strings.Repeat("a", layerMaxLen+1)},
		{"non-ascii", "dlp" + "\xc3\xa9"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := base.WithLayer(tc.layer)
			if !errors.Is(err, ErrInvalidLayer) {
				t.Errorf("error = %v, want wrap of ErrInvalidLayer", err)
			}
		})
	}
}

func TestWithLayer_EmptyAllowed(t *testing.T) {
	t.Parallel()
	base := MustNew(DLPMatch, SeverityCritical, RetryNone)
	got, err := base.WithLayer("")
	if err != nil {
		t.Fatalf("empty layer rejected: %v", err)
	}
	if got.Layer != "" {
		t.Errorf("Layer = %q, want empty", got.Layer)
	}
}

func TestWithReceipt_AcceptsValidULID(t *testing.T) {
	t.Parallel()
	base := MustNew(DLPMatch, SeverityCritical, RetryNone)
	got, err := base.WithReceipt(validULID)
	if err != nil {
		t.Fatalf("WithReceipt error: %v", err)
	}
	if got.Receipt != validULID {
		t.Errorf("Receipt = %q, want %q", got.Receipt, validULID)
	}
}

func TestWithReceipt_RejectsNonULIDShapes(t *testing.T) {
	t.Parallel()
	base := MustNew(DLPMatch, SeverityCritical, RetryNone)
	cases := []struct {
		name    string
		receipt string
	}{
		{"too short", "01HZ8"},
		{"too long", validULID + "EXTRA"},
		{"contains lowercase", strings.ToLower(validULID)},
		{"contains forbidden I", "I1HZ8EXAMPLERECEIPTID00000"},
		{"contains forbidden L", "L1HZ8EXAMPLERECEIPTID00000"},
		{"contains forbidden O", "O1HZ8EXAMPLERECEIPTID00000"},
		{"contains forbidden U", "U1HZ8EXAMPLERECEIPTID00000"},
		{"contains punctuation", "01HZ8-XAMPLERECEIPTID00000"},
		{"contains control", "01HZ8\nXAMPLERECEIPTID00000"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := base.WithReceipt(tc.receipt)
			if !errors.Is(err, ErrInvalidReceipt) {
				t.Errorf("error = %v, want wrap of ErrInvalidReceipt", err)
			}
		})
	}
}

func TestWithReceipt_EmptyAllowed(t *testing.T) {
	t.Parallel()
	base := MustNew(DLPMatch, SeverityCritical, RetryNone)
	got, err := base.WithReceipt("")
	if err != nil {
		t.Fatalf("empty receipt rejected: %v", err)
	}
	if got.Receipt != "" {
		t.Errorf("Receipt = %q, want empty", got.Receipt)
	}
}

func TestSetHeaders_AlwaysEmitsRequiredFour(t *testing.T) {
	t.Parallel()
	info := MustNew(SSRFPrivateIP, SeverityCritical, RetryNone)
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
	info := MustNew(DLPMatch, SeverityCritical, RetryNone)
	info, err := info.WithLayer("dlp")
	if err != nil {
		t.Fatalf("WithLayer: %v", err)
	}
	info, err = info.WithReceipt(validULID)
	if err != nil {
		t.Fatalf("WithReceipt: %v", err)
	}
	h := make(http.Header)
	info.SetHeaders(h)

	if got := h.Get(HeaderLayer); got != "dlp" {
		t.Errorf("HeaderLayer = %q, want dlp", got)
	}
	if got := h.Get(HeaderReceipt); got != validULID {
		t.Errorf("HeaderReceipt = %q, want %q", got, validULID)
	}
}

func TestSetHeaders_OmitsOptionalFieldsWhenUnset(t *testing.T) {
	t.Parallel()
	info := MustNew(PromptInjection, SeverityCritical, RetryNone)
	h := make(http.Header)
	info.SetHeaders(h)

	if h.Get(HeaderLayer) != "" {
		t.Errorf("HeaderLayer should be empty, got %q", h.Get(HeaderLayer))
	}
	if h.Get(HeaderReceipt) != "" {
		t.Errorf("HeaderReceipt should be empty, got %q", h.Get(HeaderReceipt))
	}
}

func TestCloseFramePayload_FullShapeWithoutReceipt(t *testing.T) {
	t.Parallel()
	// Without the optional receipt the document fits with all other fields
	// present. The full Reason+Severity+Retry+Layer+Receipt combination
	// runs over the 123-byte ceiling; receipt dropping is exercised in the
	// truncation tests.
	info := MustNew(DLPMatch, SeverityCritical, RetryNone)
	info, _ = info.WithLayer("dlp")
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
	}
	for k, v := range want {
		if parsed[k] != v {
			t.Errorf("payload[%q] = %q, want %q", k, parsed[k], v)
		}
	}
}

func TestCloseFramePayload_ReceiptDropsToFitLimit(t *testing.T) {
	t.Parallel()
	// With every optional field populated the full document exceeds 123
	// bytes. Receipt is the first field documented to drop, so it should
	// be absent while the required fields remain.
	info := MustNew(DLPMatch, SeverityCritical, RetryNone)
	info, _ = info.WithLayer("dlp")
	info, _ = info.WithReceipt(validULID)
	got := info.CloseFramePayload()

	if len(got) > closeFrameMaxBytes {
		t.Errorf("payload %d bytes exceeds RFC 6455 limit %d", len(got), closeFrameMaxBytes)
	}
	var parsed map[string]string
	if err := json.Unmarshal([]byte(got), &parsed); err != nil {
		t.Fatalf("payload not valid JSON: %v (%q)", err, got)
	}
	if parsed["receipt"] != "" {
		t.Errorf("receipt should drop first to fit limit, got %q", parsed["receipt"])
	}
	if parsed["block_reason"] != "dlp_match" {
		t.Errorf("block_reason missing: got %q", parsed["block_reason"])
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
	hugeReceipt := MustNew(ToolPolicyDeny, SeverityCritical, RetryPolicy)
	cases := []struct {
		name string
		info Info
	}{
		{"normal", MustNew(DLPMatch, SeverityCritical, RetryNone)},
		// Direct struct-literal Info bypassing validators on purpose, to
		// exercise the truncation algorithm with synthetic oversize values
		// that the public API would refuse.
		{"large receipt forces drop", Info{
			Reason:   ToolPolicyDeny,
			Severity: SeverityCritical,
			Retry:    RetryPolicy,
			Layer:    strings.Repeat("L", 50),
			Receipt:  strings.Repeat("R", 90),
		}},
		{"overlong reason forces fallback", Info{
			Reason: Reason(strings.Repeat("X", 200)),
		}},
		{"barely-fitting reason at floor", Info{
			Reason: Reason(strings.Repeat("X", 100)),
		}},
		{"valid info with no optional", hugeReceipt},
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

func TestCloseFramePayload_OverlongReasonReturnsOverflowSignal(t *testing.T) {
	t.Parallel()
	// Direct struct literal with an oversize Reason. The public API rejects
	// this at construction (New), but CloseFramePayload must still defend
	// against it because Info is a value type Go cannot prevent direct
	// construction of. The fallback uses BlockReasonOverflow, NOT
	// ParseError, so audit fidelity is preserved.
	info := Info{Reason: Reason(strings.Repeat("X", 200))}
	got := info.CloseFramePayload()
	if got != closeFrameOverflowFallback {
		t.Errorf("overlong-reason payload = %q, want fallback %q",
			got, closeFrameOverflowFallback)
	}
	if len(got) > closeFrameMaxBytes {
		t.Errorf("fallback %d bytes exceeds RFC 6455 limit %d", len(got), closeFrameMaxBytes)
	}
	if !strings.Contains(got, string(BlockReasonOverflow)) {
		t.Errorf("overflow payload does not carry BlockReasonOverflow signal: %q", got)
	}
}

func TestReasonConstants_AllSnakeCase(t *testing.T) {
	t.Parallel()
	for r := range validReasons {
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
	// Privacy: Info exposes only {Reason, Severity, Retry, Layer, Receipt},
	// each of which is constructor-validated against the v1 vocabulary or
	// opaque-ID format. No path through the public API can put attacker-
	// controlled or secret content into a header.
	info := MustNew(DLPMatch, SeverityCritical, RetryNone)
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

// specCanonicalPairs is the ground truth from docs/specs/block-reason-header.md.
// Every Reason in validReasons MUST appear here with its spec-canonical
// (Severity, Retry) pair. The vocabulary-coverage test below enforces that
// adding a Reason without updating this table is a build break, so the spec
// table and the helper functions cannot drift apart in either direction.
var specCanonicalPairs = map[Reason]struct {
	severity Severity
	retry    Retry
}{
	// Egress / network layer.
	SchemeBlocked:    {SeverityWarn, RetryNone},
	DomainBlocklist:  {SeverityCritical, RetryPolicy},
	SSRFPrivateIP:    {SeverityCritical, RetryNone},
	SSRFMetadata:     {SeverityCritical, RetryNone},
	SSRFDNSRebind:    {SeverityCritical, RetryTransient},
	PathEntropy:      {SeverityWarn, RetryPolicy},
	SubdomainEntropy: {SeverityWarn, RetryPolicy},
	URLLength:        {SeverityWarn, RetryPolicy},
	RateLimit:        {SeverityWarn, RetryTransient},
	DataBudget:       {SeverityWarn, RetryPolicy},

	// Content / payload layer.
	DLPMatch:         {SeverityCritical, RetryNone},
	PromptInjection:  {SeverityCritical, RetryNone},
	RedactionFailure: {SeverityCritical, RetryTransient},
	MediaPolicy:      {SeverityWarn, RetryPolicy},

	// MCP / tool layer.
	ToolPolicyDeny:   {SeverityCritical, RetryPolicy},
	ToolChainBlocked: {SeverityCritical, RetryNone},
	ToolPoisoning:    {SeverityCritical, RetryNone},
	SessionBinding:   {SeverityCritical, RetryPolicy},

	// Posture / runtime layer.
	AirlockActive:          {SeverityCritical, RetryTransient},
	KillSwitchActive:       {SeverityCritical, RetryTransient},
	EnvelopeVerifyFailed:   {SeverityCritical, RetryNone},
	OutboundEnvelopeFailed: {SeverityCritical, RetryTransient},
	RedirectScanDenied:     {SeverityCritical, RetryNone},
	AuthorityMismatch:      {SeverityCritical, RetryPolicy},
	EscalationLevel:        {SeverityCritical, RetryTransient},
	SessionAnomaly:         {SeverityCritical, RetryTransient},
	CrossRequestDeny:       {SeverityCritical, RetryNone},
	CompressedResponse:     {SeverityWarn, RetryPolicy},
	BrowserShieldOversize:  {SeverityWarn, RetryPolicy},

	// Generic.
	ParseError:         {SeverityWarn, RetryNone},
	Timeout:            {SeverityWarn, RetryTransient},
	PatternUnavailable: {SeverityWarn, RetryTransient},
	NotEnabled:         {SeverityInfo, RetryPolicy},
	BadRequest:         {SeverityInfo, RetryNone},

	// Internal sentinel.
	BlockReasonOverflow: {SeverityWarn, RetryTransient},
}

// TestSpecCanonicalPairs_VocabularyCoverage asserts the test ground-truth
// table is exhaustive: every Reason in validReasons has an entry, and the
// table has no entries that are not in validReasons. This guarantees adding
// a new Reason cannot silently bypass the spec-conformance test below.
func TestSpecCanonicalPairs_VocabularyCoverage(t *testing.T) {
	t.Parallel()
	for reason := range validReasons {
		if _, ok := specCanonicalPairs[reason]; !ok {
			t.Errorf("Reason %q is in validReasons but missing from specCanonicalPairs (update docs/specs/block-reason-header.md and the test table together)", reason)
		}
	}
	for reason := range specCanonicalPairs {
		if _, ok := validReasons[reason]; !ok {
			t.Errorf("Reason %q is in specCanonicalPairs but not in validReasons (stale test entry?)", reason)
		}
	}
}

func TestSeverityFor_AllVocabulary(t *testing.T) {
	t.Parallel()
	for reason, want := range specCanonicalPairs {
		t.Run(string(reason), func(t *testing.T) {
			got := SeverityFor(reason)
			if got != want.severity {
				t.Fatalf("SeverityFor(%q) = %q, want %q (spec)", reason, got, want.severity)
			}
		})
	}
	// Unknown reason fails closed to critical.
	if got := SeverityFor(Reason("not_a_real_reason")); got != SeverityCritical {
		t.Fatalf("SeverityFor unknown = %q, want SeverityCritical (fail-closed)", got)
	}
}

func TestRetryFor_AllVocabulary(t *testing.T) {
	t.Parallel()
	for reason, want := range specCanonicalPairs {
		t.Run(string(reason), func(t *testing.T) {
			got := RetryFor(reason)
			if got != want.retry {
				t.Fatalf("RetryFor(%q) = %q, want %q (spec)", reason, got, want.retry)
			}
		})
	}
	// Unknown reason fails closed to none.
	if got := RetryFor(Reason("not_a_real_reason")); got != RetryNone {
		t.Fatalf("RetryFor unknown = %q, want RetryNone (fail-closed)", got)
	}
}

func TestNewForReason_BuildsValidInfoForEveryReason(t *testing.T) {
	t.Parallel()
	for reason := range validReasons {
		t.Run(string(reason), func(t *testing.T) {
			info, err := NewForReason(reason)
			if err != nil {
				t.Fatalf("NewForReason(%q): %v", reason, err)
			}
			if info.Reason != reason {
				t.Fatalf("info.Reason = %q, want %q", info.Reason, reason)
			}
			if info.Severity != SeverityFor(reason) {
				t.Fatalf("info.Severity = %q, want SeverityFor(%q) = %q",
					info.Severity, reason, SeverityFor(reason))
			}
			if info.Retry != RetryFor(reason) {
				t.Fatalf("info.Retry = %q, want RetryFor(%q) = %q",
					info.Retry, reason, RetryFor(reason))
			}
		})
	}
}

func TestNewForReason_InvalidReasonRejects(t *testing.T) {
	t.Parallel()
	if _, err := NewForReason(Reason("not_a_real_reason")); err == nil {
		t.Fatal("NewForReason on unknown reason expected error, got nil")
	}
}

func TestMustNewForReason_PanicsOnInvalid(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("MustNewForReason on unknown reason expected panic, got nil")
		}
	}()
	_ = MustNewForReason(Reason("not_a_real_reason"))
}

func TestMustNewForReason_HappyPath(t *testing.T) {
	t.Parallel()
	info := MustNewForReason(DLPMatch)
	if info.Reason != DLPMatch {
		t.Fatalf("info.Reason = %q, want %q", info.Reason, DLPMatch)
	}
}
