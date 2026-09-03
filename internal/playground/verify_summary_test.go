// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !js

package playground

import (
	"strings"
	"testing"
)

// A seal failure has to say which check failed and why. Reporting only that
// something failed sent an operator hunting through source for a reason the
// report was already holding.
func TestVerifyReport_FailureSummary(t *testing.T) {
	rep := VerifyReport{
		Checks: []Check{
			{Name: "launch-manifest-signature", OK: true},
			{Name: "orchestrator-delegation", OK: false, Reason: "delegation does not bind the launch manifest"},
			{Name: "live-demo-semantics", OK: false},
		},
	}

	got := rep.FailureSummary()
	for _, want := range []string{
		"orchestrator-delegation: delegation does not bind the launch manifest",
		"live-demo-semantics",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("summary %q must name %q", got, want)
		}
	}
	if strings.Contains(got, "launch-manifest-signature") {
		t.Fatalf("summary %q must not name a check that passed", got)
	}
}

// An all-passing report must not produce an empty reason that reads as a
// nameless failure.
func TestVerifyReport_FailureSummary_NoFailures(t *testing.T) {
	rep := VerifyReport{Checks: []Check{{Name: "launch-manifest-signature", OK: true}}}
	if got := rep.FailureSummary(); got != "no failed checks" {
		t.Fatalf("summary = %q, want %q", got, "no failed checks")
	}
}
