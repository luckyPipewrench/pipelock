// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestTaint_FailSafeClassification_ConfigStates exercises the six config states
// required for a security-sensitive boolean: omitted, YAML null/blank, explicit
// false, explicit true, reload-with-change, and reload-without-change. The
// default MUST be false (fail-safe classification is opt-in), omission must not
// silently enable it, and toggling it on reload must apply cleanly without being
// treated as a posture teardown.
func TestTaint_FailSafeClassification_ConfigStates(t *testing.T) {
	const base = "taint:\n  enabled: true\n"

	load := func(t *testing.T, extra string) *Config {
		t.Helper()
		path := filepath.Join(t.TempDir(), "pipelock.yaml")
		if err := os.WriteFile(path, []byte(base+extra), 0o600); err != nil {
			t.Fatalf("write config: %v", err)
		}
		cfg, err := Load(path)
		if err != nil {
			t.Fatalf("Load(): %v", err)
		}
		return cfg
	}

	valueStates := []struct {
		name  string
		extra string
		want  bool
	}{
		{"omitted", "", false},
		{"yaml_null_blank", "  fail_safe_classification:\n", false},
		{"explicit_false", "  fail_safe_classification: false\n", false},
		{"explicit_true", "  fail_safe_classification: true\n", true},
	}
	for _, s := range valueStates {
		t.Run(s.name, func(t *testing.T) {
			if got := load(t, s.extra).Taint.FailSafeClassification; got != s.want {
				t.Fatalf("fail_safe_classification = %v, want %v", got, s.want)
			}
		})
	}

	// Reload WITH change (off -> on): the new value is applied and the toggle is
	// not flagged as a reload teardown (it is a hot-reloadable classification knob).
	t.Run("reload_with_change", func(t *testing.T) {
		old := load(t, "  fail_safe_classification: false\n")
		updated := load(t, "  fail_safe_classification: true\n")
		if old.Taint.FailSafeClassification {
			t.Fatal("old config should have fail-safe off")
		}
		if !updated.Taint.FailSafeClassification {
			t.Fatal("reloaded config lost the enabled toggle")
		}
		for _, w := range ValidateReload(old, updated) {
			if strings.Contains(w.Field, "fail_safe_classification") {
				t.Fatalf("hot-reloadable toggle wrongly flagged on reload: %+v", w)
			}
		}
	})

	// Reload WITHOUT change: value is stable and not flagged.
	t.Run("reload_without_change", func(t *testing.T) {
		old := load(t, "  fail_safe_classification: true\n")
		same := load(t, "  fail_safe_classification: true\n")
		if !same.Taint.FailSafeClassification {
			t.Fatal("value not stable across an unchanged reload")
		}
		for _, w := range ValidateReload(old, same) {
			if strings.Contains(w.Field, "fail_safe_classification") {
				t.Fatalf("unchanged toggle flagged on reload: %+v", w)
			}
		}
	})
}
