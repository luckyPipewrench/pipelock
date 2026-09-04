// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// keepUnsuppressedDLP partitions SSE DLP matches into the ones that still
// decide the verdict and the ones a suppress entry deliberately drops. A core
// floor pattern is never dropped, and a dropped match is returned so the
// caller can record it.
func TestKeepUnsuppressedDLP(t *testing.T) {
	t.Parallel()

	const target = "https://api.vendor.example/sse"
	suppressed := []config.SuppressEntry{{Rule: "Custom Vendor Token", Path: target, Reason: "provider-bound"}}
	custom := scanner.TextDLPMatch{PatternName: "Custom Vendor Token", Severity: "high"}
	core := scanner.TextDLPMatch{PatternName: "AWS Access ID", Severity: "critical"}
	other := scanner.TextDLPMatch{PatternName: "Other Token", Severity: "high"}

	for _, tc := range []struct {
		name        string
		res         scanner.TextDLPResult
		suppress    []config.SuppressEntry
		wantKept    int
		wantDropped int
		wantClean   bool
	}{
		{name: "clean result is untouched", res: scanner.TextDLPResult{Clean: true}, suppress: suppressed, wantClean: true},
		{name: "no suppress entries drops nothing", res: scanner.TextDLPResult{Matches: []scanner.TextDLPMatch{custom}}, wantKept: 1},
		{name: "suppressed custom match is dropped and the result goes clean", res: scanner.TextDLPResult{Matches: []scanner.TextDLPMatch{custom}}, suppress: suppressed, wantDropped: 1, wantClean: true},
		{name: "core floor match survives a matching suppress entry", res: scanner.TextDLPResult{Matches: []scanner.TextDLPMatch{core}}, suppress: []config.SuppressEntry{{Rule: "AWS Access ID", Path: target}}, wantKept: 1},
		{name: "unsuppressed match keeps the result dirty beside a dropped one", res: scanner.TextDLPResult{Matches: []scanner.TextDLPMatch{custom, other}}, suppress: suppressed, wantKept: 1, wantDropped: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, dropped := keepUnsuppressedDLP(tc.res, target, tc.suppress)
			if len(got.Matches) != tc.wantKept {
				t.Fatalf("kept = %d, want %d (%+v)", len(got.Matches), tc.wantKept, got.Matches)
			}
			if len(dropped) != tc.wantDropped {
				t.Fatalf("dropped = %d, want %d (%+v)", len(dropped), tc.wantDropped, dropped)
			}
			if got.Clean != tc.wantClean {
				t.Fatalf("Clean = %v, want %v", got.Clean, tc.wantClean)
			}
		})
	}
}

func TestRecordDroppedSSEDLP(t *testing.T) {
	t.Parallel()

	matches := []scanner.TextDLPMatch{{PatternName: "Custom Vendor Token"}, {PatternName: "Other Token"}}

	// A nil callback is a no-op, never a panic.
	recordDroppedSSEDLP(GenericSSEScanOptions{}, matches)

	var seen []string
	var reasons []string
	recordDroppedSSEDLP(GenericSSEScanOptions{OnDroppedDLP: func(m scanner.TextDLPMatch, reason string) {
		seen = append(seen, m.PatternName)
		reasons = append(reasons, reason)
	}}, matches)
	if len(seen) != 2 || seen[0] != "Custom Vendor Token" || seen[1] != "Other Token" {
		t.Fatalf("recorded = %v, want both matches in order", seen)
	}
	for _, r := range reasons {
		if r != "suppressed" {
			t.Fatalf("reason = %q, want suppressed", r)
		}
	}
}
