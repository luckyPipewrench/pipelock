// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestMergeIntoConfigUnprovableVersionWarnsAndLoadsAcrossReloads(t *testing.T) {
	rulesDir := t.TempDir()
	writeMinVersionBundle(t, rulesDir)

	cfg := config.Defaults()
	cfg.Rules.RulesDir = rulesDir
	cfg.Rules.TrustEmbeddedKeys = true

	const unprovable = "0.0.0-dev.unknown"

	tests := []struct {
		name        string
		version     string
		mutate      func()
		wantLoaded  bool
		wantWarning bool
		wantError   bool
	}{
		{name: "first load uses default", version: unprovable, wantLoaded: true, wantWarning: true},
		{name: "strict opt-in refuses", version: unprovable, mutate: func() { cfg.Rules.AllowUnversionedBundleLoad = false }, wantError: true},
		{name: "reload to warn and load", version: unprovable, mutate: func() { cfg.Rules.AllowUnversionedBundleLoad = true }, wantLoaded: true, wantWarning: true},
		{name: "unrelated reload", version: unprovable, mutate: func() { cfg.KillSwitch.APIToken = "rotated-token" }, wantLoaded: true, wantWarning: true},
		{name: "released binary below minimum", version: "0.0.0", wantError: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.mutate != nil {
				tc.mutate()
			}
			result := MergeIntoConfig(cfg, tc.version)
			if got := len(result.Loaded) > 0; got != tc.wantLoaded {
				t.Fatalf("loaded = %v, errors = %v, want loaded = %v", got, errorStrings(result), tc.wantLoaded)
			}
			if got := len(result.Warnings) > 0; got != tc.wantWarning {
				t.Fatalf("warnings = %v, want warning = %v", result.Warnings, tc.wantWarning)
			}
			if got := len(result.Errors) > 0; got != tc.wantError {
				t.Fatalf("errors = %v, want error = %v", errorStrings(result), tc.wantError)
			}
			if tc.wantWarning {
				warning := strings.Join(result.Warnings, " ")
				for _, want := range []string{"minver", "0.1.0", unprovable} {
					if !strings.Contains(warning, want) {
						t.Errorf("warning = %q, want %q", warning, want)
					}
				}
			}
		})
	}
}

func errorStrings(r *LoadResult) []string {
	out := make([]string, 0, len(r.Errors))
	for _, e := range r.Errors {
		out = append(out, e.Name+": "+e.Reason)
	}
	return out
}

func writeMinVersionBundle(t *testing.T, rulesDir string) {
	t.Helper()
	dir := filepath.Join(rulesDir, "minver")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeUnsignedBundle(t, dir, &Bundle{
		FormatVersion: 1,
		Name:          "minver",
		Version:       "2026.07.1",
		Tier:          "community",
		Author:        "test",
		Description:   "min version gate fixture",
		MinPipelock:   "0.1.0",
		Rules: []Rule{{
			ID:          "minver-1",
			Name:        "minver rule",
			Description: "fixture rule for the min version gate",
			Type:        "dlp",
			Pattern:     RulePattern{Regex: "MINVERTOKEN[0-9]{4}"},
			Status:      StatusStable,
			Severity:    "high",
			Confidence:  "high",
		}},
	})
}
