// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package coveragecert

import (
	"encoding/hex"
	"math"
	"strings"
	"testing"
	"time"
)

// These cases use intentionally signed malformed input: the signature is
// valid for the supplied bytes, but the signed body must still fail closed
// when it cannot be canonicalized into an honest certificate.
func TestReleaseAssuranceVerifyRejectsMalformedSignedSessionSets(t *testing.T) {
	t.Parallel()

	pub, priv := genTestKey(t)
	trusted := map[string]struct{}{hex.EncodeToString(pub): {}}
	control, err := Sign(validBody(pub), priv)
	if err != nil {
		t.Fatalf("Sign(canonical control): %v", err)
	}
	if _, err := Verify(control, trusted); err != nil {
		t.Fatalf("Verify(canonical trusted control): %v", err)
	}
	tests := []struct {
		name   string
		modify func(*Body)
		want   string
	}{
		{
			name: "null sessions",
			modify: func(body *Body) {
				body.Sessions = nil
			},
			want: "sessions must be an array",
		},
		{
			name: "out of order session identifiers",
			modify: func(body *Body) {
				body.Sessions[0], body.Sessions[1] = body.Sessions[1], body.Sessions[0]
			},
			want: "sessions must be sorted",
		},
		{
			name: "broken chain reported as limited",
			modify: func(body *Body) {
				body.Sessions[1].CompletenessStatus = completenessLimited
				body.Sessions[1].CompletenessReason = reasonBoundedClosed
			},
			want: "broken chains must report",
		},
		{
			name: "session identifier with surrounding whitespace",
			modify: func(body *Body) {
				body.Sessions[0].ID = " session-001"
			},
			want: "leading or trailing whitespace",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := validBody(pub)
			tt.modify(&body)
			cert := signCoverageCertBodyUnchecked(t, body, pub, priv)

			_, err := Verify(cert, trusted)
			if err == nil {
				t.Fatal("Verify accepted a signed malformed session set")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Verify error = %q, want %q", err, tt.want)
			}
		})
	}
}

func TestReleaseAssuranceValidateRejectsReceiptOverflow(t *testing.T) {
	t.Parallel()

	pub, _ := genTestKey(t)
	body := validBody(pub)
	body.Sessions = []SessionCoverage{
		{
			ID:                 "session-a",
			ReceiptCount:       math.MaxUint64,
			ChainIntact:        true,
			Anchored:           anchorLocal,
			CompletenessStatus: completenessLimited,
			CompletenessReason: reasonBoundedClosed,
		},
		{
			ID:                 "session-b",
			ReceiptCount:       1,
			ChainIntact:        true,
			Anchored:           anchorLocal,
			CompletenessStatus: completenessLimited,
			CompletenessReason: reasonBoundedClosed,
		},
	}

	if err := body.Validate(); err == nil || !strings.Contains(err.Error(), "total_receipts overflow") {
		t.Fatalf("Validate error = %v, want total_receipts overflow", err)
	}
}

// JSON certificates cannot express MaxUint64 under the canonical JSON number
// rules, so Verify rejects this malformed shape before it reaches aggregate
// diagnostics. The helper remains the only reachable consumer of this shape
// for an in-memory producer and must retain the overflow diagnostic.
func TestReleaseAssuranceReDerivationReportsReceiptOverflow(t *testing.T) {
	t.Parallel()

	pub, _ := genTestKey(t)
	body := validBody(pub)
	body.Sessions[0].ReceiptCount = math.MaxUint64
	body.Sessions[1].ReceiptCount = 1

	mismatches := rederiveAggregates(body)
	if !strings.Contains(strings.Join(mismatches, "\n"), "overflowed uint64") {
		t.Fatalf("re-derived mismatches = %q, want overflow diagnostic", mismatches)
	}
}

func TestReleaseAssuranceValidateAcceptsCanonicalProducerBody(t *testing.T) {
	t.Parallel()

	pub, _ := genTestKey(t)
	if err := validBody(pub).Validate(); err != nil {
		t.Fatalf("Validate(canonical producer body) = %v", err)
	}
}

func TestReleaseAssuranceVerifyEscapesBackslashesAndSupplementaryRunes(t *testing.T) {
	t.Parallel()

	pub, priv := genTestKey(t)
	body := validBody(pub)
	body.Agent = "agent\\\U0001f680"
	cert, err := Sign(body, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	result, err := Verify(cert, map[string]struct{}{hex.EncodeToString(pub): {}})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	lines := strings.Join(result.Lines, "\n")
	if !strings.Contains(lines, `Agent: agent\\\U0001f680`) {
		t.Fatalf("verify lines = %q, want escaped backslash and supplementary rune", lines)
	}
}

func TestReleaseAssuranceRejectsMissingCertificateWindow(t *testing.T) {
	t.Parallel()

	pub, priv := genTestKey(t)
	tests := []struct {
		name   string
		modify func(*Body)
		want   string
	}{
		{
			name: "start",
			modify: func(body *Body) {
				body.WindowStart = time.Time{}
			},
			want: "window_start is required",
		},
		{
			name: "end",
			modify: func(body *Body) {
				body.WindowEnd = time.Time{}
			},
			want: "window_end is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := validBody(pub)
			tt.modify(&body)
			_, err := Sign(body, priv)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Sign error = %v, want %q", err, tt.want)
			}
		})
	}
}
