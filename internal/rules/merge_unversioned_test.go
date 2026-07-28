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

// The refusal message tells the operator to set allow_unversioned_bundle_load.
// The RUNTIME merge path has to honour it, or that advice is a dead end: the
// operator changes the config, nothing changes, and the knob reads as broken.
func TestMergeIntoConfigHonoursUnversionedOverride(t *testing.T) {
	rulesDir := t.TempDir()
	writeMinVersionBundle(t, rulesDir)

	cfg := config.Defaults()
	cfg.Rules.RulesDir = rulesDir
	cfg.Rules.TrustEmbeddedKeys = true

	// A version that cannot be proven is the condition the override exists for.
	const unprovable = "0.0.0-dev.unknown"

	refused := MergeIntoConfig(cfg, unprovable)
	if len(refused.Errors) == 0 {
		t.Fatal("expected the min_pipelock refusal without the override; got none, so this test cannot prove the override does anything")
	}
	if !strings.Contains(strings.Join(errorStrings(refused), " "), "min_pipelock") {
		t.Fatalf("refusal was not the version gate: %v", errorStrings(refused))
	}

	cfg.Rules.AllowUnversionedBundleLoad = true
	allowed := MergeIntoConfig(cfg, unprovable)
	if len(allowed.Errors) != 0 {
		t.Fatalf("override set but the runtime still refused: %v", errorStrings(allowed))
	}
	if len(allowed.Loaded) == 0 {
		t.Fatal("override set and no error, but no bundle loaded")
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
