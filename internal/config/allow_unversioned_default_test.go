// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"testing"
)

// allow_unversioned_bundle_load remains accepted so existing configuration does
// not fail validation. The loader now warns and loads unprovable development
// builds regardless of this retained compatibility value.
func TestAllowUnversionedBundleLoadParsingMatrix(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		yaml string
		want bool
	}{
		{name: "omitted preserves false", yaml: "mode: balanced\nrules:\n  rules_dir: /tmp/x\n", want: false},
		{name: "yaml null preserves false", yaml: "mode: balanced\nrules:\n  allow_unversioned_bundle_load:\n", want: false},
		{name: "explicit false remains accepted", yaml: "mode: balanced\nrules:\n  allow_unversioned_bundle_load: false\n", want: false},
		{name: "explicit true remains accepted", yaml: "mode: balanced\nrules:\n  allow_unversioned_bundle_load: true\n", want: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "pipelock.yaml")
			if err := os.WriteFile(path, []byte(tc.yaml), 0o600); err != nil {
				t.Fatalf("write config: %v", err)
			}
			cfg, err := Load(path)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if got := cfg.Rules.AllowUnversionedBundleLoad; got != tc.want {
				t.Fatalf("AllowUnversionedBundleLoad = %v, want %v", got, tc.want)
			}
		})
	}
}

// Reload preserves the accepted compatibility value in both directions.
func TestAllowUnversionedBundleLoadReloadBothDirections(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "pipelock.yaml")

	write := func(body string) *Config {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("write config: %v", err)
		}
		cfg, err := Load(path)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		return cfg
	}

	if got := write("mode: balanced\nrules:\n  allow_unversioned_bundle_load: false\n").Rules.AllowUnversionedBundleLoad; got {
		t.Fatalf("initial load = %v, want false", got)
	}
	if got := write("mode: balanced\nrules:\n  allow_unversioned_bundle_load: true\n").Rules.AllowUnversionedBundleLoad; !got {
		t.Fatalf("reload to true = %v, want true", got)
	}
	if got := write("mode: balanced\nrules:\n  allow_unversioned_bundle_load: true\n").Rules.AllowUnversionedBundleLoad; !got {
		t.Fatalf("reload with no change = %v, want true", got)
	}
	if got := write("mode: balanced\nrules:\n  allow_unversioned_bundle_load: false\n").Rules.AllowUnversionedBundleLoad; got {
		t.Fatalf("reload back to false = %v, want false; a relaxed posture must not persist", got)
	}
}
