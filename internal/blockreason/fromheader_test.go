// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package blockreason

import (
	"net/http"
	"testing"
)

// TestFromHeaderDecodesEmittedSet is the round trip that matters: whatever
// SetHeaders writes, FromHeader must read back. The two sides share a file so
// that a vocabulary change cannot move one without the other.
func TestFromHeaderDecodesEmittedSet(t *testing.T) {
	t.Parallel()
	want := MustNewForReason(PromptInjection)
	want, err := want.WithLayer("response_scan")
	if err != nil {
		t.Fatalf("WithLayer: %v", err)
	}
	h := http.Header{}
	want.SetHeaders(h)

	got, ok := FromHeader(h)
	if !ok {
		t.Fatal("FromHeader refused a header set this package just emitted")
	}
	if got != want {
		t.Fatalf("round trip lost data: got %+v, want %+v", got, want)
	}
}

func TestFromHeaderRoundTripsEveryReason(t *testing.T) {
	t.Parallel()
	for _, reason := range AllReasons() {
		h := http.Header{}
		MustNewForReason(reason).SetHeaders(h)
		got, ok := FromHeader(h)
		if !ok {
			t.Fatalf("reason %q did not decode", reason)
		}
		if got.Reason != reason {
			t.Fatalf("reason %q decoded as %q", reason, got.Reason)
		}
		if got.Severity != SeverityFor(reason) || got.Retry != RetryFor(reason) {
			t.Fatalf("reason %q decoded severity/retry %q/%q, want %q/%q",
				reason, got.Severity, got.Retry, SeverityFor(reason), RetryFor(reason))
		}
	}
}

// TestFromHeaderRejectsNonPipelockResponses is the negative direction. An
// ordinary upstream 4xx must never decode as a Pipelock block, or the CLI will
// tell an operator their proxy did something it did not do.
func TestFromHeaderRejectsNonPipelockResponses(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		header http.Header
	}{
		{"nil header", nil},
		{"empty header", http.Header{}},
		{
			"ordinary upstream 403",
			http.Header{
				"Content-Type": []string{"text/html"},
				"Server":       []string{"nginx"},
			},
		},
		{
			"reason header present but empty",
			http.Header{HeaderReason: []string{""}},
		},
		{
			"reason outside the v1 vocabulary",
			http.Header{HeaderReason: []string{"made_up_reason"}},
		},
		{
			"reason casing does not match the vocabulary",
			http.Header{HeaderReason: []string{"PROMPT_INJECTION"}},
		},
		{
			"other block-reason fields present without a reason",
			http.Header{
				HeaderSeverity: []string{string(SeverityCritical)},
				HeaderRetry:    []string{string(RetryNone)},
				HeaderLayer:    []string{"response_scan"},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got, ok := FromHeader(tc.header); ok {
				t.Fatalf("decoded a non-Pipelock response as a block: %+v", got)
			}
		})
	}
}

// TestFromHeaderFallsBackToCanonicalMapping covers a wire set whose severity or
// retry is absent or junk. The reason code is authoritative, so the decoder
// recovers the canonical pair rather than discarding a real block.
func TestFromHeaderFallsBackToCanonicalMapping(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		header http.Header
	}{
		{
			"severity and retry absent",
			http.Header{HeaderReason: []string{string(PromptInjection)}},
		},
		{
			"severity and retry outside the vocabulary",
			http.Header{
				HeaderReason:   []string{string(PromptInjection)},
				HeaderSeverity: []string{"catastrophic"},
				HeaderRetry:    []string{"maybe"},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, ok := FromHeader(tc.header)
			if !ok {
				t.Fatal("a valid reason code should still decode")
			}
			if got.Severity != SeverityFor(PromptInjection) {
				t.Fatalf("severity = %q, want canonical %q", got.Severity, SeverityFor(PromptInjection))
			}
			if got.Retry != RetryFor(PromptInjection) {
				t.Fatalf("retry = %q, want canonical %q", got.Retry, RetryFor(PromptInjection))
			}
		})
	}
}

// TestFromHeaderDropsInvalidOptionalFields: a malformed optional field must
// degrade the explanation, not throw away a block that really happened.
func TestFromHeaderDropsInvalidOptionalFields(t *testing.T) {
	t.Parallel()
	h := http.Header{
		HeaderReason:  []string{string(PromptInjection)},
		HeaderLayer:   []string{"response scan; rm -rf /"},
		HeaderReceipt: []string{"not-a-ulid"},
	}
	got, ok := FromHeader(h)
	if !ok {
		t.Fatal("invalid optional fields must not discard the block")
	}
	if got.Layer != "" {
		t.Fatalf("kept an invalid layer: %q", got.Layer)
	}
	if got.Receipt != "" {
		t.Fatalf("kept an invalid receipt: %q", got.Receipt)
	}
}
