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
	})
	cfg.DLP.Patterns = append(cfg.DLP.Patterns, result.DLP...)
	cfg.ResponseScanning.Patterns = append(cfg.ResponseScanning.Patterns, result.Injection...)
	return result
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
