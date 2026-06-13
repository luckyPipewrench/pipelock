// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"fmt"
	"sort"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// Semantic config-validation checks for the doctor command.
//
// These catch exemptions that are syntactically valid but INERT: they parse
// fine, but no scanner that could honor them is enabled, or they name a knob
// the blocking scanner does not consult. An inert exemption is worse than no
// exemption: it trains an operator to believe a false positive is fixed when
// the block silently persists.
//
// The knob -> scanner consultation map (authoritative, derived from the
// scanner call sites, not from docs):
//
//   - Top-level `suppress:` is consulted by body DLP and header DLP
//     (request_body_scanning), by response scanning, and by generic SSE
//     scanning (response_scanning.sse_streaming), plus the `pipelock audit`
//     and `pipelock git` project/secret scanners. URL-query DLP does NOT
//     consult suppress; it only honors per-pattern dlp.patterns[].exempt_domains.
//   - Default DLP patterns and user dlp.patterns are matched by URL DLP AND
//     body/header DLP (same pattern namespace). response_scanning.patterns are
//     matched by response scanning only.
//
// All checks below are deliberately CONSERVATIVE: a finding is only emitted
// when inertness is provable from the loaded config model. Ambiguous cases are
// skipped rather than risk a false alarm that would itself erode trust.

const (
	doctorCheckSuppressSemantics  = "config_suppress_semantics"
	doctorCheckExemptionSemantics = "config_exemption_semantics"

	// nextSuppressURLDLP is the correct knob for a URL-query DLP false
	// positive (suppress does not reach URL DLP).
	nextSuppressURLDLP = "to exempt a URL-query match, set dlp.patterns[].exempt_domains for this pattern; suppress: only reaches body/header DLP, generic SSE DLP, response scanning, and the audit/git scanners"
)

// checkDoctorConfigSemantics runs the semantic config-validation checks and
// returns one doctorReportCheck per finding. When the config has no semantic
// problems it returns a single ok check so the surface is always represented
// in the report.
func checkDoctorConfigSemantics(cfg *config.Config) []doctorReportCheck {
	var checks []doctorReportCheck
	checks = append(checks, checkDoctorSuppressEntries(cfg)...)
	checks = append(checks, checkDoctorInertExemptions(cfg)...)
	if len(checks) == 0 {
		return []doctorReportCheck{{
			Name:    doctorCheckSuppressSemantics,
			Surface: doctorSurfaceConfig,
			Status:  doctorStatusOK,
			Detail:  "suppress entries and scanner exemptions are consistent with enabled scanners",
		}}
	}
	return checks
}

// dlpPatternNames returns the set of active DLP pattern names (defaults + user,
// already merged by config normalization at load), lowercased for the
// case-insensitive match that IsSuppressed performs.
func dlpPatternNames(cfg *config.Config) map[string]struct{} {
	names := make(map[string]struct{}, len(cfg.DLP.Patterns))
	for _, p := range cfg.DLP.Patterns {
		if p.Name != "" {
			names[strings.ToLower(p.Name)] = struct{}{}
		}
	}
	return names
}

// responsePatternNames returns the set of active response-scan pattern names
// (defaults + user, already merged at load), lowercased.
func responsePatternNames(cfg *config.Config) map[string]struct{} {
	names := make(map[string]struct{}, len(cfg.ResponseScanning.Patterns))
	for _, p := range cfg.ResponseScanning.Patterns {
		if p.Name != "" {
			names[strings.ToLower(p.Name)] = struct{}{}
		}
	}
	return names
}

// suppressConsumingDLPScannerEnabled reports whether any LIVE proxy scanner
// that both consults suppress AND matches DLP patterns is enabled. URL DLP is
// deliberately excluded because it does not consult suppress.
func suppressConsumingDLPScannerEnabled(cfg *config.Config) bool {
	return cfg.RequestBodyScanning.Enabled ||
		cfg.ResponseScanning.SSEStreaming.Enabled
}

// checkDoctorSuppressEntries classifies each suppress entry against the active
// pattern namespaces and enabled scanners.
func checkDoctorSuppressEntries(cfg *config.Config) []doctorReportCheck {
	if len(cfg.Suppress) == 0 {
		return nil
	}
	dlpNames := dlpPatternNames(cfg)
	respNames := responsePatternNames(cfg)

	var checks []doctorReportCheck
	// Collapse duplicate rule names so an operator with the same rule on many
	// paths gets one finding per distinct rule, not one per path. Preserve
	// first-seen order for deterministic output, then sort the emitted checks.
	seen := make(map[string]struct{})
	for _, entry := range cfg.Suppress {
		ruleKey := strings.ToLower(entry.Rule)
		if entry.Rule == "" {
			continue // shape validation already rejects empty rule
		}
		if _, dup := seen[ruleKey]; dup {
			continue
		}
		seen[ruleKey] = struct{}{}

		_, isDLP := dlpNames[ruleKey]
		_, isResp := respNames[ruleKey]

		switch {
		case !isDLP && !isResp:
			// Unknown pattern name for proxy namespaces: matches no active
			// DLP or response-scan pattern, so no proxy scanner can honor this
			// suppress. Audit/git project scanners have additional finding
			// names, so keep the warning explicitly scoped.
			checks = append(checks, doctorReportCheck{
				Name:       doctorCheckSuppressSemantics,
				Surface:    doctorSurfaceConfig,
				Status:     doctorStatusWarn,
				Configured: true,
				Detail: fmt.Sprintf(
					"suppress entry names pattern %q, which matches no active DLP or response-scanning pattern; this exemption is inert for the proxy enforcement path",
					entry.Rule),
				Next: "fix the rule name to match a pattern in dlp.patterns or response_scanning.patterns, move audit/git-only suppressions to the config used for those commands, or remove the entry; run `pipelock doctor` again to confirm",
			})
		case isResp && !isDLP && !cfg.ResponseScanning.Enabled:
			// Response-only pattern, response scanning off. The only scanners
			// that match this name (response scanning and its SSE injection
			// path) are disabled, so the suppress is inert.
			checks = append(checks, doctorReportCheck{
				Name:       doctorCheckSuppressSemantics,
				Surface:    doctorSurfaceConfig,
				Status:     doctorStatusWarn,
				Configured: true,
				Detail: fmt.Sprintf(
					"suppress entry names response-scanning pattern %q, but response_scanning.enabled=false; no enabled scanner matches this pattern, so the suppress is inert",
					entry.Rule),
				Next: "enable response_scanning to make this suppress effective, or remove the entry",
			})
		case isDLP && !isResp && !suppressConsumingDLPScannerEnabled(cfg):
			// DLP pattern, but no live proxy scanner that consults suppress is
			// enabled. URL DLP would still match this pattern, but it ignores
			// suppress entirely, so the suppress cannot affect any proxy path.
			// Note: the audit/git project scanners still consult suppress, so
			// the entry is not universally dead -- this warning is scoped to
			// the proxy enforcement path the doctor reports on.
			checks = append(checks, doctorReportCheck{
				Name:       doctorCheckSuppressSemantics,
				Surface:    doctorSurfaceConfig,
				Status:     doctorStatusWarn,
				Configured: true,
				Detail: fmt.Sprintf(
					"suppress entry names DLP pattern %q, but no suppress-consulting DLP proxy scanner is enabled (request_body_scanning=false, sse_streaming=false; response_scanning uses a separate pattern namespace); URL-query DLP would match this pattern but does not consult suppress, so the suppress has no effect on the proxy path",
					entry.Rule),
				Next: nextSuppressURLDLP,
			})
		case isDLP && isResp && !cfg.ResponseScanning.Enabled && !suppressConsumingDLPScannerEnabled(cfg):
			// Same rule name exists in both namespaces, but every proxy scanner
			// that could honor either namespace is off.
			checks = append(checks, doctorReportCheck{
				Name:       doctorCheckSuppressSemantics,
				Surface:    doctorSurfaceConfig,
				Status:     doctorStatusWarn,
				Configured: true,
				Detail: fmt.Sprintf(
					"suppress entry names pattern %q in both DLP and response-scanning namespaces, but response_scanning=false and no suppress-consulting DLP proxy scanner is enabled; URL-query DLP would match this pattern but does not consult suppress, so the suppress has no effect on the proxy path",
					entry.Rule),
				Next: "enable the scanner path this suppress is meant to affect, or use dlp.patterns[].exempt_domains for URL-query DLP false positives",
			})
		}
	}
	sortDoctorChecks(checks)
	return checks
}

// checkDoctorInertExemptions flags exempt_domains lists configured on scanners
// that are disabled, so the exemption cannot affect anything.
func checkDoctorInertExemptions(cfg *config.Config) []doctorReportCheck {
	var checks []doctorReportCheck

	if len(cfg.ResponseScanning.ExemptDomains) > 0 && !cfg.ResponseScanning.Enabled {
		checks = append(checks, doctorReportCheck{
			Name:       doctorCheckExemptionSemantics,
			Surface:    doctorSurfaceConfig,
			Status:     doctorStatusWarn,
			Configured: true,
			Detail:     "response_scanning.exempt_domains is set but response_scanning.enabled=false; this exemption is inert",
			Next:       "enable response_scanning to make the exemption effective, or remove the exempt_domains list",
		})
	}

	if len(cfg.AdaptiveEnforcement.ExemptDomains) > 0 && !cfg.AdaptiveEnforcement.Enabled {
		checks = append(checks, doctorReportCheck{
			Name:       doctorCheckExemptionSemantics,
			Surface:    doctorSurfaceConfig,
			Status:     doctorStatusWarn,
			Configured: true,
			Detail:     "adaptive_enforcement.exempt_domains is set but adaptive_enforcement.enabled=false; the escalation exemption is inert",
			Next:       "enable adaptive_enforcement to make the exemption effective, or remove the exempt_domains list",
		})
	}

	return checks
}

// sortDoctorChecks orders checks by name then detail for deterministic output.
// Map-iteration order over pattern-name sets must not leak into the report.
func sortDoctorChecks(checks []doctorReportCheck) {
	sort.SliceStable(checks, func(i, j int) bool {
		if checks[i].Name != checks[j].Name {
			return checks[i].Name < checks[j].Name
		}
		return checks[i].Detail < checks[j].Detail
	})
}
