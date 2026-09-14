// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package ceereason

import (
	"strings"
	"testing"
)

// TestClientReasonsCarryNoTuningState pins the property the package exists
// for: nothing the agent can read names a knob, a number, or a pattern.
func TestClientReasonsCarryNoTuningState(t *testing.T) {
	for _, reason := range []string{
		ClientFragmentMatch, ClientEntropyBudget, ClientInspectionDepth,
		ClientSessionCapacity, ClientOwnerMismatch,
	} {
		if strings.ContainsAny(reason, "0123456789_:") || strings.Contains(reason, "max_") {
			t.Fatalf("client reason %q carries a number, knob or pattern shape", reason)
		}
		if !strings.HasPrefix(reason, "cross-request ") {
			t.Fatalf("client reason %q does not name the cross-request class", reason)
		}
	}
	for _, kind := range []string{KindEntropyBudget, KindInspectionDepth, KindSessionCapacity, KindOwnerMismatch} {
		if strings.ContainsAny(kind, " /:") {
			t.Fatalf("block kind %q is not a bounded token", kind)
		}
	}
}
