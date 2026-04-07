// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
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

// compiledStandardDLPNames is the set of DLP pattern names from
// config.Defaults() that belong to the standard tier (non-core). When a
// signed standard bundle loads, these are replaced by bundle patterns.
// Must match the 40 non-core DLP names in config.Defaults().
var compiledStandardDLPNames = map[string]bool{
	"Anthropic API Key":           true,
	"OpenAI API Key":              true,
	"OpenAI Service Key":          true,
	"Fireworks API Key":           true,
	"Google API Key":              true,
	"Google OAuth Client Secret":  true,
	"Stripe Key":                  true,
	"Stripe Webhook Secret":       true,
	"Google OAuth Token":          true,
	"Slack App Token":             true,
	"Discord Bot Token":           true,
	"Twilio API Key":              true,
	"SendGrid API Key":            true,
	"Mailgun API Key":             true,
	"New Relic API Key":           true,
	"Hugging Face Token":          true,
	"Databricks Token":            true,
	"Replicate API Token":         true,
	"Together AI Key":             true,
	"Pinecone API Key":            true,
	"Groq API Key":                true,
	"xAI API Key":                 true,
	"DigitalOcean Token":          true,
	"HashiCorp Vault Token":       true,
	"Vercel Token":                true,
	"Supabase Service Key":        true,
	"npm Token":                   true,
	"PyPI Token":                  true,
	"Linear API Key":              true,
	"Notion API Key":              true,
	"Sentry Auth Token":           true,
	"JWT Token":                   true,
	"Bitcoin WIF Private Key":     true,
	"Extended Private Key":        true,
	"Ethereum Private Key":        true,
	"Social Security Number":      true,
	"Google OAuth Client ID":      true,
	"Credential in URL":           true,
	"Environment Variable Secret": true,
	"Credit Card Number":          true,
	"IBAN":                        true,
}

// compiledStandardResponseNames is the set of response pattern names from
// config.Defaults() that belong to the standard tier (non-core).
var compiledStandardResponseNames = map[string]bool{
	"New Instructions":             true,
	"Jailbreak Attempt":            true,
	"Behavior Override":            true,
	"Encoded Payload":              true,
	"Tool Invocation":              true,
	"Authority Escalation":         true,
	"Instruction Downgrade":        true,
	"Instruction Dismissal":        true,
	"Priority Override":            true,
	"Auth Material Requirement":    true,
	"Memory Persistence Directive": true,
	"Preference Poisoning":         true,
	"Silent Credential Handling":   true,
	"CJK Instruction Override ZH":  true,
	"CJK Instruction Override JP":  true,
	"CJK Instruction Override KR":  true,
	"CJK Jailbreak Mode":           true,
}

// MergeIntoConfig loads all bundles from the configured rules directory,
// applies standard tier source selection, and merges patterns into cfg.
//
// Standard tier source selection:
//   - If a signed pipelock-standard bundle loads: its patterns replace the
//     compiled standard-tier defaults (non-core patterns from Defaults()).
//   - If missing/invalid: compiled standard defaults remain as fallback.
//   - include_defaults: false disables the entire standard tier regardless
//     of source (only core scanner patterns remain active).
//
// Community and pro bundle patterns are always additive.
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

	// Check if include_defaults is explicitly false (disables standard tier).
	dlpDefaultsDisabled := cfg.DLP.IncludeDefaults != nil && !*cfg.DLP.IncludeDefaults
	responseDefaultsDisabled := cfg.ResponseScanning.IncludeDefaults != nil && !*cfg.ResponseScanning.IncludeDefaults

	// Find the standard bundle in loaded bundles (if any).
	standardLoaded := false
	for _, lb := range result.Loaded {
		if lb.Name == StandardBundleName {
			standardLoaded = true
			break
		}
	}

	// Separate standard bundle patterns from community/pro patterns.
	var standardDLP []config.DLPPattern
	var standardInj []config.ResponseScanPattern
	var otherDLP []config.DLPPattern
	var otherInj []config.ResponseScanPattern
	for _, p := range result.DLP {
		if p.Bundle == StandardBundleName {
			standardDLP = append(standardDLP, p)
		} else {
			otherDLP = append(otherDLP, p)
		}
	}
	for _, p := range result.Injection {
		if p.Bundle == StandardBundleName {
			standardInj = append(standardInj, p)
		} else {
			otherInj = append(otherInj, p)
		}
	}

	// Standard tier source selection (per-subsystem).
	//
	// At this point, cfg.DLP.Patterns and cfg.ResponseScanning.Patterns
	// contain the post-ApplyDefaults() patterns:
	//   - include_defaults: true/nil  → compiled defaults + user overrides
	//   - include_defaults: false     → user patterns only
	//
	// Each subsystem is handled independently so operators can disable
	// standard DLP defaults while keeping standard response defaults.

	// DLP subsystem.
	if dlpDefaultsDisabled {
		// Compiled standard DLP defaults already stripped by ApplyDefaults.
		// Don't add bundle standard DLP patterns either.
	} else if standardLoaded {
		cfg.DLP.Patterns = removeStandardTierDLP(cfg.DLP.Patterns)
		cfg.DLP.Patterns = append(cfg.DLP.Patterns, standardDLP...)
	}

	// Response subsystem.
	if responseDefaultsDisabled {
		// Compiled standard response defaults already stripped by ApplyDefaults.
	} else if standardLoaded {
		cfg.ResponseScanning.Patterns = removeStandardTierResponse(cfg.ResponseScanning.Patterns)
		cfg.ResponseScanning.Patterns = append(cfg.ResponseScanning.Patterns, standardInj...)
	}

	// Overall standard source for diagnostics.
	if dlpDefaultsDisabled && responseDefaultsDisabled {
		result.Standard = StandardSourceNone
	} else if standardLoaded {
		result.Standard = StandardSourceBundle
	} else {
		result.Standard = StandardSourceCompiled
	}

	// Community and pro bundles are always additive.
	cfg.DLP.Patterns = append(cfg.DLP.Patterns, otherDLP...)
	cfg.ResponseScanning.Patterns = append(cfg.ResponseScanning.Patterns, otherInj...)

	return result
}

// removeStandardTierDLP removes compiled standard-tier DLP patterns, keeping
// core-equivalent compiled patterns, user-defined patterns (any name not in
// the compiled defaults set), and bundle-sourced patterns.
func removeStandardTierDLP(patterns []config.DLPPattern) []config.DLPPattern {
	kept := make([]config.DLPPattern, 0, len(patterns))
	for _, p := range patterns {
		// Bundle-sourced patterns are never removed here.
		if p.Bundle != "" {
			kept = append(kept, p)
			continue
		}
		// Only remove patterns whose names match compiled standard defaults.
		// Core names and unknown names (user-defined) are preserved.
		if compiledStandardDLPNames[p.Name] {
			continue // replaced by standard bundle
		}
		kept = append(kept, p)
	}
	return kept
}

// removeStandardTierResponse removes compiled standard-tier response patterns.
func removeStandardTierResponse(patterns []config.ResponseScanPattern) []config.ResponseScanPattern {
	kept := make([]config.ResponseScanPattern, 0, len(patterns))
	for _, p := range patterns {
		if p.Bundle != "" {
			kept = append(kept, p)
			continue
		}
		if compiledStandardResponseNames[p.Name] {
			continue
		}
		kept = append(kept, p)
	}
	return kept
}

// buildTierKeyMapping extracts tier→key_fingerprint bindings from trusted keys.
// Only keys with a non-empty Tier field are included. The fingerprint format
// matches KeyFingerprint (hex-encoded raw public key bytes).
func buildTierKeyMapping(keys []config.TrustedKey) map[string]string {
	mapping := make(map[string]string)
	for _, k := range keys {
		if k.Tier != "" {
			if existing, dup := mapping[k.Tier]; dup {
				// First key wins. Log but don't error — config validation
				// is the right place for strict checks.
				_, _ = fmt.Fprintf(os.Stderr, "pipelock: warning: duplicate tier binding for %q: key %q ignored, keeping %q\n",
					k.Tier, k.PublicKey, existing)
				continue
			}
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
