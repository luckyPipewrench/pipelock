// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"os"
	"path/filepath"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
)

// ResolveRulesDir returns the effective rules directory.
// Priority: explicit override, then $XDG_DATA_HOME/pipelock/rules/, then ~/.local/share/pipelock/rules/.
func ResolveRulesDir(override string) string {
	if override != "" {
		return override
	}
	if xdg := os.Getenv("XDG_DATA_HOME"); xdg != "" && filepath.IsAbs(xdg) {
		return filepath.Join(xdg, "pipelock", "rules")
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".local", "share", "pipelock", "rules")
}

// MergeIntoConfig loads all bundles from the configured rules directory,
// merges DLP and injection patterns into cfg in-place, and returns the
// LoadResult (including ToolPoison patterns and any errors).
func MergeIntoConfig(cfg *config.Config, pipelockVersion string) *LoadResult {
	rulesDir := ResolveRulesDir(cfg.Rules.RulesDir)
	result := LoadBundles(rulesDir, LoadOptions{
		MinConfidence:       cfg.Rules.MinConfidence,
		IncludeExperimental: cfg.Rules.IncludeExperimental,
		Disabled:            cfg.Rules.Disabled,
		TrustedKeys:         cfg.Rules.TrustedKeys,
		PipelockVersion:     pipelockVersion,
		TierKeyMapping:      buildTierKeyMapping(cfg.Rules.TrustedKeys),
	})
	cfg.DLP.Patterns = append(cfg.DLP.Patterns, result.DLP...)
	cfg.ResponseScanning.Patterns = append(cfg.ResponseScanning.Patterns, result.Injection...)
	return result
}

// buildTierKeyMapping extracts tier→key_fingerprint bindings from trusted keys.
// Only keys with a non-empty Tier field are included. The fingerprint format
// matches KeyFingerprint (hex-encoded raw public key bytes).
func buildTierKeyMapping(keys []config.TrustedKey) map[string]string {
	mapping := make(map[string]string)
	for _, k := range keys {
		if k.Tier != "" {
			// TrustedKey.PublicKey is already hex-encoded, same format
			// as KeyFingerprint output.
			mapping[k.Tier] = k.PublicKey
		}
	}
	// Official (embedded) keys are NOT added here — they are verified
	// separately by isOfficialFingerprint in the loader. Adding them
	// would break key rotation when the keyring has multiple keys
	// (last-writer-wins on the map).
	if len(mapping) == 0 {
		return nil
	}
	return mapping
}

// ConvertToolPoison converts CompiledToolPoisonRule slices to ExtraPoisonPattern
// slices for use in ToolScanConfig.
func ConvertToolPoison(rules []CompiledToolPoisonRule) []*tools.ExtraPoisonPattern {
	if len(rules) == 0 {
		return nil
	}
	out := make([]*tools.ExtraPoisonPattern, len(rules))
	for i, r := range rules {
		out[i] = &tools.ExtraPoisonPattern{
			Name:          r.Name,
			RuleID:        r.RuleID,
			Re:            r.Re,
			ScanField:     r.ScanField,
			Bundle:        r.Bundle,
			BundleVersion: r.BundleVersion,
		}
	}
	return out
}
