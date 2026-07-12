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
// Name matching is intentional: if a shipped default DLP rule is renamed or
// split, update this map in the same change so bundle replacement cannot drift.
// Must match the non-core DLP names in config.Defaults().
var compiledStandardDLPNames = map[string]bool{
	"Anthropic API Key":           true,
	"OpenAI API Key":              true,
	"OpenAI Service Key":          true,
	"Fireworks API Key":           true,
	"LLM Router API Key":          true,
	"Answer Engine API Key":       true,
	"Web Research API Key":        true,
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
	// secret-pattern expansion (standard tier; "GCP Service
	// Account Key" is core, not listed here).
	"GitLab Deploy Token":                true,
	"GitLab Runner Token":                true,
	"GitLab CI Job Token":                true,
	"GitLab Pipeline Trigger Token":      true,
	"GitLab OAuth Application Secret":    true,
	"GitLab SCIM Token":                  true,
	"GitLab Service Token":               true,
	"PostgreSQL Connection String":       true,
	"MySQL Connection String":            true,
	"MongoDB Connection String":          true,
	"Redis Connection String":            true,
	"GCP Service Account Private Key ID": true,
	"Azure Storage Account Key":          true,
	"Azure SAS Token":                    true,
}

// compiledStandardResponseNames is the set of response pattern names from
// config.Defaults() that belong to the standard tier (non-core).
var compiledStandardResponseNames = map[string]bool{
	"New Instructions":                             true,
	"Jailbreak Attempt":                            true,
	"Behavior Override":                            true,
	"Encoded Payload":                              true,
	"Tool Invocation":                              true,
	"Authority Escalation":                         true,
	"Instruction Downgrade":                        true,
	"Instruction Dismissal":                        true,
	"Priority Override":                            true,
	"Auth Material Requirement":                    true,
	"Markdown Link Credential Exfiltration":        true,
	"Markdown Link Credential Value Exfiltration":  true,
	"Markdown Link Credential Follow Exfiltration": true,
	"Memory Persistence Directive":                 true,
	"Preference Poisoning":                         true,
	"Silent Credential Handling":                   true,
	"Spanish Instruction Override":                 true,
	"Spanish System Prompt Disclosure":             true,
	"Cross-Lingual Instruction Override":           true,
	"Cross-Lingual System Prompt Disclosure":       true,
	"CJK Instruction Override ZH":                  true,
	"CJK Instruction Override JP":                  true,
	"CJK Instruction Override KR":                  true,
	"CJK Jailbreak Mode":                           true,
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

	// Fail closed on a bundle LOAD failure. A bundle that failed to load
	// (signature, lockfile, min-version, or filesystem error) is NOT in the
	// resolved sets built below, so proceeding would strip previously-validated
	// bundle patterns from an already-resolved config (re-resolution happens on
	// every hot reload and conductor policy apply) and fall back to compiled
	// defaults — a fail-open weakening triggered by a transient error. Preserve
	// the caller's existing resolved patterns instead; the caller surfaces
	// result.Errors, and the reload downgrade guard still rejects any real
	// weakening under strict mode.
	if len(result.Errors) > 0 {
		return result
	}

	// Check if include_defaults is explicitly false (disables standard tier).
	dlpDefaultsDisabled := cfg.DLP.IncludeDefaults != nil && !*cfg.DLP.IncludeDefaults
	responseDefaultsDisabled := cfg.ResponseScanning.IncludeDefaults != nil && !*cfg.ResponseScanning.IncludeDefaults

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

	// Standard-tier availability is PER SURFACE, not a single "is the standard
	// bundle loaded" flag: a standard bundle may populate DLP but not response
	// (or vice versa). Keying both surfaces off one flag would let a partial
	// standard bundle strip the compiled fallback from the surface it did NOT
	// provide and leave it empty (a fail-open detection loss). Each surface
	// uses the bundle only when the bundle actually provided patterns for it,
	// and otherwise restores the compiled fallback.
	standardDLPLoaded := len(standardDLP) > 0
	standardResponseLoaded := len(standardInj) > 0

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
	cfg.DLP.Patterns = removeBundleDLP(cfg.DLP.Patterns)
	if dlpDefaultsDisabled {
		result.StandardDLP = StandardSourceNone
	} else if standardDLPLoaded {
		cfg.DLP.Patterns = removeStandardTierDLP(cfg.DLP.Patterns)
		cfg.DLP.Patterns = append(cfg.DLP.Patterns, standardDLP...)
		result.StandardDLP = StandardSourceBundle
	} else {
		cfg.DLP.Patterns = restoreCompiledStandardDLP(cfg.DLP.Patterns)
		result.StandardDLP = StandardSourceCompiled
	}

	// Response subsystem.
	cfg.ResponseScanning.Patterns = removeBundleResponse(cfg.ResponseScanning.Patterns)
	if responseDefaultsDisabled {
		result.StandardResponse = StandardSourceNone
	} else if standardResponseLoaded {
		cfg.ResponseScanning.Patterns = removeStandardTierResponse(cfg.ResponseScanning.Patterns)
		cfg.ResponseScanning.Patterns = append(cfg.ResponseScanning.Patterns, standardInj...)
		result.StandardResponse = StandardSourceBundle
	} else {
		cfg.ResponseScanning.Patterns = restoreCompiledStandardResponse(cfg.ResponseScanning.Patterns)
		result.StandardResponse = StandardSourceCompiled
	}

	// Community and pro bundles are always additive.
	cfg.DLP.Patterns = append(cfg.DLP.Patterns, otherDLP...)
	cfg.ResponseScanning.Patterns = append(cfg.ResponseScanning.Patterns, otherInj...)

	return result
}

// removeBundlePatterns drops every bundle-sourced pattern (Bundle != "") so a
// re-resolution can re-apply the current bundle load without doubling patterns.
// One generic keeps the DLP and response idempotency semantics identical.
func removeBundlePatterns[T any](patterns []T, bundleOf func(T) string) []T {
	kept := make([]T, 0, len(patterns))
	for _, p := range patterns {
		if bundleOf(p) != "" {
			continue
		}
		kept = append(kept, p)
	}
	return kept
}

// restoreCompiledStandardPatterns rebuilds the compiled standard-tier fallback
// (used when no standard bundle provides this surface) in first-load order so a
// re-resolution's canonical policy hash matches a fresh load. It restores the
// compiled standard patterns that a prior standard-bundle resolution stripped,
// keeps any compiled default that is still present, drops nothing the operator
// overrode (non-compiled = user override), and preserves all non-default
// (user/community/pro) patterns. One generic keeps DLP and response identical.
func restoreCompiledStandardPatterns[T any](
	patterns, defaults []T,
	nameOf func(T) string,
	compiledOf func(T) bool,
	compiledStandardNames map[string]bool,
) []T {
	defaultNames := make(map[string]struct{}, len(defaults))
	for _, p := range defaults {
		defaultNames[nameOf(p)] = struct{}{}
	}

	existingCompiledDefaults := make(map[string]struct{}, len(patterns))
	userOverrides := make(map[string]struct{}, len(patterns))
	for _, p := range patterns {
		if _, ok := defaultNames[nameOf(p)]; ok && compiledOf(p) {
			existingCompiledDefaults[nameOf(p)] = struct{}{}
		}
		if !compiledOf(p) {
			userOverrides[nameOf(p)] = struct{}{}
		}
	}

	restored := make([]T, 0, len(patterns)+len(compiledStandardNames))
	for _, p := range defaults {
		if _, overridden := userOverrides[nameOf(p)]; overridden {
			continue
		}
		if !compiledStandardNames[nameOf(p)] {
			if _, present := existingCompiledDefaults[nameOf(p)]; !present {
				continue
			}
		}
		restored = append(restored, p)
	}
	for _, p := range patterns {
		if _, isDefault := defaultNames[nameOf(p)]; isDefault && compiledOf(p) {
			continue
		}
		restored = append(restored, p)
	}
	return restored
}

func removeBundleDLP(patterns []config.DLPPattern) []config.DLPPattern {
	return removeBundlePatterns(patterns, func(p config.DLPPattern) string { return p.Bundle })
}

func removeBundleResponse(patterns []config.ResponseScanPattern) []config.ResponseScanPattern {
	return removeBundlePatterns(patterns, func(p config.ResponseScanPattern) string { return p.Bundle })
}

func restoreCompiledStandardDLP(patterns []config.DLPPattern) []config.DLPPattern {
	return restoreCompiledStandardPatterns(patterns, config.Defaults().DLP.Patterns,
		func(p config.DLPPattern) string { return p.Name },
		func(p config.DLPPattern) bool { return p.Compiled },
		compiledStandardDLPNames)
}

func restoreCompiledStandardResponse(patterns []config.ResponseScanPattern) []config.ResponseScanPattern {
	return restoreCompiledStandardPatterns(patterns, config.Defaults().ResponseScanning.Patterns,
		func(p config.ResponseScanPattern) string { return p.Name },
		func(p config.ResponseScanPattern) bool { return p.Compiled },
		compiledStandardResponseNames)
}

// removeStandardTierDLP removes compiled standard-tier DLP patterns, keeping
// core-equivalent compiled patterns, user-defined patterns (any name not in
// the compiled defaults set), and bundle-sourced patterns.
func removeStandardTierDLP(patterns []config.DLPPattern) []config.DLPPattern {
	kept := make([]config.DLPPattern, 0, len(patterns))
	for _, p := range patterns {
		// Only remove patterns that are compiled defaults (p.Compiled=true)
		// AND belong to the standard tier (not core). User-supplied patterns
		// with the same name as a default are preserved (Compiled=false).
		if p.Compiled && compiledStandardDLPNames[p.Name] {
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
		if p.Compiled && compiledStandardResponseNames[p.Name] {
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
				// First key wins. Log but don't error - config validation
				// is the right place for strict checks.
				_, _ = fmt.Fprintf(os.Stderr, "pipelock: warning: duplicate tier binding for %q: key %q ignored, keeping %q\n",
					k.Tier, k.PublicKey, existing)
				continue
			}
			mapping[k.Tier] = k.PublicKey
		}
	}
	// Official (embedded) keys are NOT added here - they are verified
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
