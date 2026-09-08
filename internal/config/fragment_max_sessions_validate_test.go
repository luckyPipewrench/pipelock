// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import "testing"

// The global fragment-stream ledger is the control the capacity block names in its
// operator message, so it has to reject a value that cannot hold a working set. A
// ledger of zero or one turns cross-request detection into blanket denial: the
// second stream is refused and the refusal is a block.
//
// This exists because the field shipped with a default and a normalization step
// and no Validate rule, while both of its siblings under the same enabled guard
// and the identically-named session_profiling.max_sessions all had one. An
// unvalidated knob that reads as configured is the class this repository already
// carries an open finding about.
func TestValidate_FragmentReassemblyMaxSessionsMustBePositive(t *testing.T) {
	t.Parallel()

	for _, value := range []int{0, -1} {
		cfg := Defaults()
		cfg.CrossRequestDetection.Enabled = true
		cfg.CrossRequestDetection.Action = ActionBlock
		cfg.CrossRequestDetection.FragmentReassembly.Enabled = true
		cfg.CrossRequestDetection.FragmentReassembly.MaxBufferBytes = 65536
		cfg.CrossRequestDetection.FragmentReassembly.WindowMinutes = 5
		cfg.CrossRequestDetection.FragmentReassembly.MaxSessions = value

		err := cfg.Validate()
		if err == nil {
			t.Fatalf("Validate() accepted max_sessions = %d; a ledger that cannot hold a working set makes the capacity block deny ordinary traffic", value)
		}
		if got := err.Error(); got != "cross_request_detection.fragment_reassembly.max_sessions must be > 0" {
			t.Fatalf("Validate() error = %q, want the max_sessions rule; a different rule firing first would leave this one unproven", got)
		}
	}
}

// The rule must not fire on a configuration that never enables the feature, or it
// becomes an over-strict guard that refuses a config the operator deliberately
// left unconfigured.
func TestValidate_FragmentReassemblyMaxSessionsIgnoredWhenDisabled(t *testing.T) {
	t.Parallel()

	// Entropy budget carries the parent, so the "both sub-detectors disabled"
	// no-op rule does not fire and fragment reassembly is genuinely the only
	// disabled half.
	cfg := Defaults()
	cfg.CrossRequestDetection.Enabled = true
	cfg.CrossRequestDetection.Action = ActionBlock
	cfg.CrossRequestDetection.EntropyBudget.Enabled = true
	cfg.CrossRequestDetection.EntropyBudget.Action = ActionBlock
	cfg.CrossRequestDetection.EntropyBudget.BitsPerWindow = 256
	cfg.CrossRequestDetection.EntropyBudget.WindowMinutes = 5
	cfg.CrossRequestDetection.FragmentReassembly.Enabled = false
	cfg.CrossRequestDetection.FragmentReassembly.MaxSessions = 0

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() rejected an unconfigured disabled fragment reassembly: %v", err)
	}
}
