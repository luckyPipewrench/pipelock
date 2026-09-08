// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

// These drive LoadBytes, the path an operator's file actually takes, rather than
// calling Validate directly. The first version of this test called Validate on a
// hand-built struct and passed while the rule was UNREACHABLE in production:
// normalization coerced any non-positive max_sessions to the default before
// Validate ever saw it, so an operator's `max_sessions: 0` was silently replaced
// rather than refused. A guard proven only against a state production never
// occupies is not proven.
func TestLoadBytes_FragmentMaxSessionsRejectsAnExplicitNonPositiveValue(t *testing.T) {
	t.Parallel()

	base := `
cross_request_detection:
  enabled: true
  action: block
  fragment_reassembly:
    enabled: true
    max_buffer_bytes: 65536
    window_minutes: 5
`

	for _, value := range []string{"0", "-1"} {
		cfg, err := LoadBytes([]byte(base + "    max_sessions: " + value + "\n"))
		if err == nil {
			t.Fatalf("LoadBytes accepted max_sessions: %s; a ledger that cannot hold a working set makes the capacity block deny ordinary traffic", value)
		}
		if cfg != nil {
			t.Fatalf("LoadBytes returned a config alongside its error for max_sessions: %s", value)
		}
		if !strings.Contains(err.Error(), "cross_request_detection.fragment_reassembly.max_sessions must be > 0") {
			t.Fatalf("error = %q, want the max_sessions rule; another rule firing first would leave this one unproven", err)
		}
	}
}

// Omitting the field is the ordinary case and must keep working, or the guard
// above becomes an over-strict rule that refuses every existing config.
func TestLoadBytes_FragmentMaxSessionsOmittedTakesTheDefault(t *testing.T) {
	t.Parallel()

	cfg, err := LoadBytes([]byte(`
cross_request_detection:
  enabled: true
  action: block
  fragment_reassembly:
    enabled: true
    max_buffer_bytes: 65536
    window_minutes: 5
`))
	if err != nil {
		t.Fatalf("LoadBytes rejected a config that omits max_sessions: %v", err)
	}
	if cfg.CrossRequestDetection.FragmentReassembly.MaxSessions != nil {
		t.Fatal("omitted max_sessions materialized during load; validation could then no longer tell omitted from explicit")
	}
	if got := cfg.CrossRequestDetection.FragmentReassembly.ResolvedMaxSessions(); got != DefaultCrossRequestFragmentMaxSessions {
		t.Fatalf("resolved max_sessions = %d, want the default %d", got, DefaultCrossRequestFragmentMaxSessions)
	}
}

// A positive explicit value is preserved end to end, which is the control that
// shows the rejection above is attributable to the value being non-positive.
func TestLoadBytes_FragmentMaxSessionsExplicitPositiveIsKept(t *testing.T) {
	t.Parallel()

	cfg, err := LoadBytes([]byte(`
cross_request_detection:
  enabled: true
  action: block
  fragment_reassembly:
    enabled: true
    max_buffer_bytes: 65536
    window_minutes: 5
    max_sessions: 250
`))
	if err != nil {
		t.Fatalf("LoadBytes rejected an explicit positive max_sessions: %v", err)
	}
	if got := cfg.CrossRequestDetection.FragmentReassembly.ResolvedMaxSessions(); got != 250 {
		t.Fatalf("resolved max_sessions = %d, want 250", got)
	}
}

// The rule must not fire on a configuration that never enables the feature, or
// it refuses a config the operator deliberately left unconfigured.
func TestValidate_FragmentMaxSessionsIgnoredWhenDisabled(t *testing.T) {
	t.Parallel()

	// Entropy budget carries the parent, so the "both sub-detectors disabled"
	// no-op rule does not fire and fragment reassembly is genuinely the only
	// disabled half.
	zero := 0
	cfg := Defaults()
	cfg.CrossRequestDetection.Enabled = true
	cfg.CrossRequestDetection.Action = ActionBlock
	cfg.CrossRequestDetection.EntropyBudget.Enabled = true
	cfg.CrossRequestDetection.EntropyBudget.Action = ActionBlock
	cfg.CrossRequestDetection.EntropyBudget.BitsPerWindow = 256
	cfg.CrossRequestDetection.EntropyBudget.WindowMinutes = 5
	cfg.CrossRequestDetection.FragmentReassembly.Enabled = false
	cfg.CrossRequestDetection.FragmentReassembly.MaxSessions = &zero

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() rejected an unconfigured disabled fragment reassembly: %v", err)
	}
}
