// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package baseline

import "testing"

// TestBaseline_RestartDurability_LockedProfileReloadsAndEnforces proves that a
// ratified/locked profile survives a process restart: a brand-new Manager over
// the same ProfileDir must reload the persisted locked profile and keep
// enforcing deviations. A restart that silently dropped enforcement would be a
// fail-open across the exact boundary (process restart) the design flagged.
func TestBaseline_RestartDurability_LockedProfileReloadsAndEnforces(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		Enabled:          true,
		LearningWindow:   3,
		DeviationAction:  "block",
		ProfileDir:       dir,
		SensitivitySigma: 2.0,
	}

	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	for range 3 {
		mgr.RecordSession(testAgent, normalMetrics())
	}
	if err := mgr.Ratify(testAgent); err != nil {
		t.Fatalf("Ratify: %v", err)
	}
	if state := mgr.GetState(testAgent); state != StateLocked {
		t.Fatalf("pre-restart state = %q, want %q", state, StateLocked)
	}

	// Simulate a process restart: a fresh Manager over the SAME ProfileDir.
	restarted, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager (restart): %v", err)
	}
	if state := restarted.GetState(testAgent); state != StateLocked {
		t.Fatalf("post-restart state = %q, want %q (durability lost)", state, StateLocked)
	}

	// The reloaded locked profile must still enforce.
	if devs := restarted.Check(testAgent, SessionMetrics{ToolCalls: 999}); len(devs) == 0 {
		t.Fatal("restarted locked profile did not flag a deviation (fail-open across restart)")
	}
	// ...and must not flag a normal session (no spurious block after reload).
	if devs := restarted.Check(testAgent, normalMetrics()); len(devs) != 0 {
		t.Fatalf("restarted profile flagged a normal session: %d deviations", len(devs))
	}
}
