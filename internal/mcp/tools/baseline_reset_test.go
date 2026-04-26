// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"testing"
)

// TestToolBaseline_ResetDriftState_ClearsHashes verifies the core
// post-condition of ResetDriftState: hashes/descs/params are cleared so
// the next CheckAndUpdate call treats every tool as a first-insertion
// against the new ground truth.
func TestToolBaseline_ResetDriftState_ClearsHashes(t *testing.T) {
	tb := NewToolBaseline()
	tb.CheckAndUpdate("tool-a", "hash-a")
	tb.CheckAndUpdate("tool-b", "hash-b")
	tb.StoreDesc("tool-a", "describe-a")
	tb.StoreParams("tool-a", []string{"param1"})

	tb.ResetDriftState()

	// After reset, tool-a is unknown again — first insertion, no drift.
	drifted, prev := tb.CheckAndUpdate("tool-a", "hash-a-new")
	if drifted {
		t.Error("ResetDriftState left tool-a in hashes; expected first-insertion semantics")
	}
	if prev != "" {
		t.Errorf("expected empty prev hash after reset, got %q", prev)
	}

	// DiffSummary against an unknown tool should return "" (no prior data).
	if summary := tb.DiffSummary("tool-b", "anything", []string{"x"}); summary != "" {
		t.Errorf("DiffSummary on reset baseline returned %q, expected \"\"", summary)
	}
}

// TestToolBaseline_ResetDriftState_PreservesKnownTools is the dual
// guarantee: session binding state survives reset so the
// BindingUnknownAction enforcement does not lose its accumulated tool
// inventory across a detect_drift toggle.
func TestToolBaseline_ResetDriftState_PreservesKnownTools(t *testing.T) {
	tb := NewToolBaseline()
	tb.SetKnownTools([]string{"tool-a", "tool-b"})
	if !tb.HasBaseline() {
		t.Fatal("HasBaseline returned false after SetKnownTools")
	}

	tb.ResetDriftState()

	if !tb.HasBaseline() {
		t.Error("ResetDriftState dropped hasBaseline; session binding would treat next tools/list as first")
	}
	// Verify knownTools survived. Use HasKnownTool if exposed; otherwise
	// SetKnownTools again with a new tool and confirm the existing two are
	// still in the set by checking ShouldSkip behavior or similar.
	if !tb.IsKnownTool("tool-a") {
		t.Error("tool-a was dropped from knownTools")
	}
	if !tb.IsKnownTool("tool-b") {
		t.Error("tool-b was dropped from knownTools")
	}
}

// TestToolBaseline_ResetDriftState_Idempotent verifies repeat resets are
// safe no-ops on an already-empty drift state.
func TestToolBaseline_ResetDriftState_Idempotent(t *testing.T) {
	tb := NewToolBaseline()
	tb.ResetDriftState()
	tb.ResetDriftState()

	drifted, prev := tb.CheckAndUpdate("tool-x", "hash-x")
	if drifted || prev != "" {
		t.Error("expected first-insertion after repeat resets")
	}
}

// TestDetectDriftRisingEdge_StateMatrix walks every transition pair and
// asserts the prescribed behavior. This is the helper that proxy_http.go
// and server.go invoke via Observe; the four-cell transition matrix
// lives here.
//
// The first Observe call NEVER reports a rising edge regardless of value:
// it records the initial state without claiming a transition, so an
// initial config load with detect_drift=true cannot clobber a pre-seeded
// baseline. Only subsequent calls observing an actual false→true flip
// fire Reset.
func TestDetectDriftRisingEdge_StateMatrix(t *testing.T) {
	cases := []struct {
		name             string
		first            bool
		second           bool
		expectFirstEdge  bool
		expectSecondEdge bool
	}{
		// First call is always initialization, never a rising edge.
		{name: "false_then_false", first: false, second: false, expectFirstEdge: false, expectSecondEdge: false},
		{name: "true_then_true_initialization_then_steady", first: true, second: true, expectFirstEdge: false, expectSecondEdge: false},
		// false_then_true is the canonical rising edge after initialization.
		{name: "false_then_true", first: false, second: true, expectFirstEdge: false, expectSecondEdge: true},
		// true_then_false is a falling edge after initialization, no Reset.
		{name: "true_then_false", first: true, second: false, expectFirstEdge: false, expectSecondEdge: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var d DetectDriftRisingEdge
			if got := d.Observe(tc.first); got != tc.expectFirstEdge {
				t.Errorf("first Observe(%v) = %v, want %v", tc.first, got, tc.expectFirstEdge)
			}
			if got := d.Observe(tc.second); got != tc.expectSecondEdge {
				t.Errorf("second Observe(%v) = %v, want %v", tc.second, got, tc.expectSecondEdge)
			}
		})
	}
}

// TestDetectDriftRisingEdge_InitialTrueDoesNotReset proves the
// initialization gate: an empty fresh helper observing detect_drift=true
// for the first time must NOT call ResetDriftState on a baseline that
// was already pre-seeded with state. Without the gate, a pre-existing
// baseline (persisted state, golden-vector seeding, or any future
// pre-population path) would be silently discarded on first config read.
func TestDetectDriftRisingEdge_InitialTrueDoesNotReset(t *testing.T) {
	tb := NewToolBaseline()
	tb.CheckAndUpdate("tool-a", "hash-a-original")

	var edge DetectDriftRisingEdge
	if edge.Observe(true) {
		t.Fatal("first Observe(true) reported a rising edge; would clobber a pre-seeded baseline")
	}
	if drifted, prev := tb.CheckAndUpdate("tool-a", "hash-a-tampered"); !drifted || prev != "hash-a-original" {
		t.Errorf("baseline lost across initialization: drifted=%v prev=%q", drifted, prev)
	}
}

// TestDetectDriftRisingEdge_ResetEffect proves the closure-equivalent
// composition: the helper drives ResetDriftState exactly when expected
// across realistic toggle sequences. Confirms NEW poisoned tools added
// during the disabled window produce first-insertion semantics on the
// re-seeded baseline (the attacker reload-cycle bypass this fix closes).
func TestDetectDriftRisingEdge_ResetEffect(t *testing.T) {
	tb := NewToolBaseline()
	var edge DetectDriftRisingEdge

	// State 1: drift enabled from boot. The first Observe is initialization,
	// not a transition; the caller must not Reset on initialization. Seed
	// the baseline directly to model a fresh listener serving its first
	// tools/list.
	if edge.Observe(true) {
		t.Fatal("initial Observe(true) reported a rising edge; would clobber baseline")
	}
	tb.CheckAndUpdate("tool-a", "hash-a-original")
	tb.CheckAndUpdate("tool-b", "hash-b-original")

	// State 2: operator disables drift. Maps preserved — verify by
	// probing with a different hash; drift must still be reported.
	if edge.Observe(false) {
		t.Fatal("Observe(false) reported a rising edge")
	}
	if drifted, prev := tb.CheckAndUpdate("tool-a", "hash-a-different"); !drifted || prev != "hash-a-original" {
		t.Errorf("disabled window dropped tool-a hashes: drifted=%v prev=%q", drifted, prev)
	}
	// Restore tool-a to its original so the rest of the test reads cleanly.
	tb.CheckAndUpdate("tool-a", "hash-a-original")

	// State 3: attacker adds tool-c during the disabled window. The
	// production path skips CheckAndUpdate while drift is off, so the
	// poisoned tool never enters the hashes map.

	// State 4: operator re-enables drift. Rising edge fires Reset.
	if !edge.Observe(true) {
		t.Fatal("Observe(true) after Observe(false) did not report a rising edge")
	}
	tb.ResetDriftState()

	// State 5: next tools/list arrives with the poisoned tool-c plus
	// existing tool-a / tool-b. After reset all are first-insertion;
	// drift is suppressed for this transition (the documented trade-off:
	// the operator accepted that re-enabling drift re-seeds ground truth).
	if drifted, prev := tb.CheckAndUpdate("tool-a", "hash-a-original"); drifted || prev != "" {
		t.Error("post-reset CheckAndUpdate should be first-insertion")
	}
	if drifted, prev := tb.CheckAndUpdate("tool-c", "hash-c-poisoned"); drifted || prev != "" {
		t.Error("post-reset CheckAndUpdate on new tool should be first-insertion")
	}
}
