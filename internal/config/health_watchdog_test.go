// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestHealthWatchdog_DefaultsEnabled verifies Defaults() produces an enabled
// watchdog with the documented 2-second tick.
func TestHealthWatchdog_DefaultsEnabled(t *testing.T) {
	cfg := Defaults()
	if !cfg.HealthWatchdog.Enabled {
		t.Errorf("expected Enabled=true, got false")
	}
	if cfg.HealthWatchdog.IntervalSeconds != 2 {
		t.Errorf("expected IntervalSeconds=2, got %d", cfg.HealthWatchdog.IntervalSeconds)
	}
	// ExposeSubsystems defaults to false: the per-subsystem map on /health
	// is opt-in because exposing scanner / config / killswitch breakdown
	// to unauthenticated callers helps attacker reconnaissance against a
	// security boundary product.
	if cfg.HealthWatchdog.ExposeSubsystems {
		t.Errorf("expected ExposeSubsystems=false (default-secure), got true")
	}
}

// TestHealthWatchdog_IntervalDuration covers the helper's positive, zero, and
// negative branches.
func TestHealthWatchdog_IntervalDuration(t *testing.T) {
	cases := []struct {
		name string
		in   int
		want time.Duration
	}{
		{"positive", 5, 5 * time.Second},
		{"zero defaults to 2s", 0, 2 * time.Second},
		{"negative defaults to 2s", -1, 2 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := HealthWatchdog{IntervalSeconds: tc.in}
			if got := h.IntervalDuration(); got != tc.want {
				t.Errorf("IntervalDuration()=%v, want %v", got, tc.want)
			}
		})
	}
}

// TestHealthWatchdog_ApplyDefaults_FillsZeroInterval covers the
// ApplyDefaults path: an explicitly-zero IntervalSeconds is bumped to 2.
func TestHealthWatchdog_ApplyDefaults_FillsZeroInterval(t *testing.T) {
	cfg := &Config{}
	cfg.ApplyDefaults()
	if cfg.HealthWatchdog.IntervalSeconds != 2 {
		t.Errorf("expected IntervalSeconds=2 after ApplyDefaults, got %d", cfg.HealthWatchdog.IntervalSeconds)
	}
}

// TestHealthWatchdog_Load_OmittedSection verifies the 6-state coverage rule
// (state 1: section omitted entirely from YAML). Should default to enabled.
func TestHealthWatchdog_Load_OmittedSection(t *testing.T) {
	cfgPath := writeTempConfig(t, `version: 1
mode: balanced
`)
	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.HealthWatchdog.Enabled {
		t.Errorf("omitted section should default Enabled=true; got false")
	}
	if cfg.HealthWatchdog.IntervalSeconds != 2 {
		t.Errorf("omitted section should default IntervalSeconds=2; got %d", cfg.HealthWatchdog.IntervalSeconds)
	}
}

// TestHealthWatchdog_Load_NullSection covers state 2: YAML `null` for the
// whole section.
func TestHealthWatchdog_Load_NullSection(t *testing.T) {
	cfgPath := writeTempConfig(t, `version: 1
mode: balanced
health_watchdog: ~
`)
	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.HealthWatchdog.Enabled {
		t.Errorf("null section should default Enabled=true; got false")
	}
}

// TestHealthWatchdog_Load_BlankEnabled covers state 2b: section present but
// `enabled` key blank/null.
func TestHealthWatchdog_Load_BlankEnabled(t *testing.T) {
	cfgPath := writeTempConfig(t, `version: 1
mode: balanced
health_watchdog:
  enabled: ~
`)
	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.HealthWatchdog.Enabled {
		t.Errorf("blank enabled should default to true; got false")
	}
}

// TestHealthWatchdog_Load_ExplicitFalse covers state 3.
func TestHealthWatchdog_Load_ExplicitFalse(t *testing.T) {
	cfgPath := writeTempConfig(t, `version: 1
mode: balanced
health_watchdog:
  enabled: false
`)
	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.HealthWatchdog.Enabled {
		t.Errorf("explicit false should be respected; got true")
	}
}

// TestHealthWatchdog_Load_ExplicitTrue covers state 4.
func TestHealthWatchdog_Load_ExplicitTrue(t *testing.T) {
	cfgPath := writeTempConfig(t, `version: 1
mode: balanced
health_watchdog:
  enabled: true
  interval_seconds: 5
`)
	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.HealthWatchdog.Enabled {
		t.Errorf("explicit true should be respected; got false")
	}
	if cfg.HealthWatchdog.IntervalSeconds != 5 {
		t.Errorf("explicit interval_seconds should be respected; got %d", cfg.HealthWatchdog.IntervalSeconds)
	}
}

// TestHealthWatchdog_Reload_PreservesDisabled covers state 5/6: reload with
// and without change. The first load disables; the second load (same YAML)
// must keep it disabled. Reload with a re-enabled YAML must take effect.
func TestHealthWatchdog_Reload_StateChanges(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "pipelock.yaml")

	// State 5 prep: disabled
	if err := os.WriteFile(cfgPath, []byte(`version: 1
mode: balanced
health_watchdog:
  enabled: false
`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg1, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("first Load: %v", err)
	}
	if cfg1.HealthWatchdog.Enabled {
		t.Fatalf("expected disabled after first load")
	}

	// State 6: reload identical YAML — must stay disabled.
	cfg2, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("idempotent reload: %v", err)
	}
	if cfg2.HealthWatchdog.Enabled {
		t.Errorf("idempotent reload flipped Enabled to true")
	}

	// State 5: change YAML to re-enable, reload — must take effect.
	if err := os.WriteFile(cfgPath, []byte(`version: 1
mode: balanced
health_watchdog:
  enabled: true
  interval_seconds: 4
`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg3, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("changing reload: %v", err)
	}
	if !cfg3.HealthWatchdog.Enabled {
		t.Errorf("reload with enabled:true did not enable")
	}
	if cfg3.HealthWatchdog.IntervalSeconds != 4 {
		t.Errorf("reload IntervalSeconds=%d, want 4", cfg3.HealthWatchdog.IntervalSeconds)
	}
}

// TestHealthWatchdog_NotInCanonicalHash verifies the operational-not-policy
// invariant: changing watchdog settings must not alter the canonical policy
// hash. Otherwise downstream verifiers would see spurious policy churn.
func TestHealthWatchdog_NotInCanonicalHash(t *testing.T) {
	a := Defaults()
	b := Defaults()
	b.HealthWatchdog.Enabled = false
	b.HealthWatchdog.IntervalSeconds = 99

	if a.CanonicalPolicyHash() != b.CanonicalPolicyHash() {
		t.Fatalf("canonical hash diverged on watchdog change: %s vs %s",
			a.CanonicalPolicyHash(), b.CanonicalPolicyHash())
	}
}

func TestValidateReload_HealthWatchdogChanged(t *testing.T) {
	old := Defaults()
	updated := Defaults()
	updated.HealthWatchdog.IntervalSeconds = old.HealthWatchdog.IntervalSeconds + 1

	warnings := ValidateReload(old, updated)
	found := false
	for _, w := range warnings {
		if w.Field == "health_watchdog" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected reload warning for health_watchdog change")
	}
}

func TestValidateReload_HealthWatchdogUnchanged_NoWarning(t *testing.T) {
	old := Defaults()
	updated := Defaults()

	warnings := ValidateReload(old, updated)
	for _, w := range warnings {
		if w.Field == "health_watchdog" {
			t.Fatalf("unexpected health_watchdog warning: %+v", w)
		}
	}
}

// writeTempConfig writes the given YAML body to a temp file and returns its
// path. Used by table tests that load minimal configs.
func writeTempConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "pipelock.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return p
}
