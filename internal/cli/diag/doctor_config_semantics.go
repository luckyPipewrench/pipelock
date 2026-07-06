// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

var (
	cachedConfigDefaultsOnce sync.Once
	cachedConfigDefaults     *config.Config
)

// configDefaults returns a lazily-computed, shared, defaults-applied Config.
// Defaults do not change at runtime, so this avoids rebuilding every default
// pattern literal on each AnalyzeConfigSemantics call, which runs on every
// dashboard GET /exemptions request. Callers must treat the returned config
// and its slices as read-only.
func configDefaults() *config.Config {
	cachedConfigDefaultsOnce.Do(func() {
		cfg := config.Defaults()
		cfg.ApplyDefaults()
		cachedConfigDefaults = cfg
	})
	return cachedConfigDefaults
}

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

	ConfigSemanticKindInert       = "inert"
	ConfigSemanticKindMisdirected = "misdirected"
	ConfigSemanticKindAdvisory    = "advisory"

	ConfigSemanticSeverityWarn = "warn"

	// nextSuppressURLDLP is the correct knob for a URL-query DLP false
	// positive (suppress does not reach URL DLP).
	nextSuppressURLDLP = "to exempt a URL-query match, set dlp.patterns[].exempt_domains for this pattern; suppress: only reaches body/header DLP, generic SSE DLP, response scanning, and the audit/git scanners"
)

// ConfigSemanticFinding is a reusable semantic finding for syntactically valid
// config that does not do what an operator is likely to expect.
type ConfigSemanticFinding struct {
	Kind     string
	Scope    string
	Subject  string
	Detail   string
	Next     string
	Severity string
}

// AnalyzeConfigSemantics returns semantic findings for the loaded config.
// It is deliberately conservative: findings are emitted only when the config
// model proves a knob is inert, misdirected, or missing advisory metadata.
func AnalyzeConfigSemantics(cfg *config.Config) []ConfigSemanticFinding {
	if cfg == nil {
		return nil
	}
	var findings []ConfigSemanticFinding
	findings = append(findings, analyzeDoctorSuppressEntries(cfg)...)
	findings = append(findings, analyzeDoctorInertExemptions(cfg)...)
	return findings
}

// checkDoctorConfigSemantics runs the semantic config-validation checks and
// returns one doctorReportCheck per finding. When the config has no semantic
// problems it returns a single ok check so the surface is always represented
// in the report.
func checkDoctorConfigSemantics(cfg *config.Config) []doctorReportCheck {
	checks := semanticFindingsToDoctorChecks(AnalyzeConfigSemantics(cfg))
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

func newConfigSemanticFinding(kind, scope, subject, detail, next string) ConfigSemanticFinding {
	return ConfigSemanticFinding{
		Kind:     kind,
		Scope:    scope,
		Subject:  normalizeConfigSemanticSubject(scope, subject),
		Detail:   detail,
		Next:     next,
		Severity: ConfigSemanticSeverityWarn,
	}
}

func normalizeConfigSemanticSubject(scope, subject string) string {
	subject = strings.TrimSpace(subject)
	switch scope {
	case ConfigScopeSuppress, ConfigScopeRequestBodyIgnoreHeaders:
		return strings.ToLower(subject)
	default:
		return subject
	}
}

func semanticFindingsToDoctorChecks(findings []ConfigSemanticFinding) []doctorReportCheck {
	checks := make([]doctorReportCheck, 0, len(findings))
	for _, finding := range findings {
		name := doctorCheckExemptionSemantics
		if finding.Scope == ConfigScopeSuppress {
			name = doctorCheckSuppressSemantics
		}
		status := doctorStatusWarn
		if finding.Severity != "" {
			status = finding.Severity
		}
		checks = append(checks, doctorReportCheck{
			Name:       name,
			Surface:    doctorSurfaceConfig,
			Status:     status,
			Configured: true,
			Detail:     finding.Detail,
			Next:       finding.Next,
		})
	}
	return checks
}

// analyzeDoctorSuppressEntries classifies each suppress entry against the
// active pattern namespaces and enabled scanners.
func analyzeDoctorSuppressEntries(cfg *config.Config) []ConfigSemanticFinding {
	if len(cfg.Suppress) == 0 {
		return nil
	}
	dlpNames := dlpPatternNames(cfg)
	respNames := responsePatternNames(cfg)

	var findings []ConfigSemanticFinding
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
			findings = append(findings, newConfigSemanticFinding(
				ConfigSemanticKindInert,
				ConfigScopeSuppress,
				ruleKey,
				fmt.Sprintf(
					"suppress entry names pattern %q, which matches no active DLP or response-scanning pattern; this exemption is inert for the proxy enforcement path",
					entry.Rule),
				"fix the rule name to match a pattern in dlp.patterns or response_scanning.patterns, move audit/git-only suppressions to the config used for those commands, or remove the entry; run `pipelock doctor` again to confirm",
			))
		case isResp && !isDLP && !cfg.ResponseScanning.Enabled:
			// Response-only pattern, response scanning off. The only scanners
			// that match this name (response scanning and its SSE injection
			// path) are disabled, so the suppress is inert.
			findings = append(findings, newConfigSemanticFinding(
				ConfigSemanticKindInert,
				ConfigScopeSuppress,
				ruleKey,
				fmt.Sprintf(
					"suppress entry names response-scanning pattern %q, but response_scanning.enabled=false; no enabled scanner matches this pattern, so the suppress is inert",
					entry.Rule),
				"enable response_scanning to make this suppress effective, or remove the entry",
			))
		case isDLP && !isResp && !suppressConsumingDLPScannerEnabled(cfg):
			// DLP pattern, but no live proxy scanner that consults suppress is
			// enabled. URL DLP would still match this pattern, but it ignores
			// suppress entirely, so the suppress cannot affect any proxy path.
			// Note: the audit/git project scanners still consult suppress, so
			// the entry is not universally dead -- this warning is scoped to
			// the proxy enforcement path the doctor reports on.
			findings = append(findings, newConfigSemanticFinding(
				ConfigSemanticKindMisdirected,
				ConfigScopeSuppress,
				ruleKey,
				fmt.Sprintf(
					"suppress entry names DLP pattern %q, but no suppress-consulting DLP proxy scanner is enabled (request_body_scanning=false, sse_streaming=false; response_scanning uses a separate pattern namespace); URL-query DLP would match this pattern but does not consult suppress, so the suppress has no effect on the proxy path",
					entry.Rule),
				nextSuppressURLDLP,
			))
		case isDLP && isResp && !cfg.ResponseScanning.Enabled && !suppressConsumingDLPScannerEnabled(cfg):
			// Same rule name exists in both namespaces, but every proxy scanner
			// that could honor either namespace is off.
			findings = append(findings, newConfigSemanticFinding(
				ConfigSemanticKindMisdirected,
				ConfigScopeSuppress,
				ruleKey,
				fmt.Sprintf(
					"suppress entry names pattern %q in both DLP and response-scanning namespaces, but response_scanning=false and no suppress-consulting DLP proxy scanner is enabled; URL-query DLP would match this pattern but does not consult suppress, so the suppress has no effect on the proxy path",
					entry.Rule),
				"enable the scanner path this suppress is meant to affect, or use dlp.patterns[].exempt_domains for URL-query DLP false positives",
			))
		}
	}
	sortConfigSemanticFindings(findings)
	return findings
}

// checkDoctorSuppressEntries classifies each suppress entry against the active
// pattern namespaces and enabled scanners.
func checkDoctorSuppressEntries(cfg *config.Config) []doctorReportCheck {
	return semanticFindingsToDoctorChecks(analyzeDoctorSuppressEntries(cfg))
}

// analyzeDoctorInertExemptions flags exempt_domains lists configured on
// scanners that are disabled, so the exemption cannot affect anything.
func analyzeDoctorInertExemptions(cfg *config.Config) []ConfigSemanticFinding {
	var findings []ConfigSemanticFinding

	if !cfg.ResponseScanning.Enabled {
		for _, domain := range cfg.ResponseScanning.ExemptDomains {
			findings = append(findings, newConfigSemanticFinding(
				ConfigSemanticKindInert,
				ConfigScopeResponseExemptDomains,
				domain,
				"response_scanning.exempt_domains is set but response_scanning.enabled=false; this exemption is inert",
				"enable response_scanning to make the exemption effective, or remove the exempt_domains list",
			))
		}
		for _, entry := range cfg.ResponseScanning.MCPServers {
			findings = append(findings, newConfigSemanticFinding(
				ConfigSemanticKindInert,
				ConfigScopeResponseMCPServers,
				entry.Server,
				fmt.Sprintf("response_scanning.mcp_servers marks %q but response_scanning.enabled=false; this MCP response trust exemption is inert", entry.Server),
				"enable response_scanning to make the MCP response trust effective, or remove the mcp_servers entry",
			))
		}
	}

	if !cfg.AdaptiveEnforcement.Enabled {
		for _, domain := range cfg.AdaptiveEnforcement.ExemptDomains {
			findings = append(findings, newConfigSemanticFinding(
				ConfigSemanticKindInert,
				ConfigScopeAdaptiveExemptDomains,
				domain,
				"adaptive_enforcement.exempt_domains is set but adaptive_enforcement.enabled=false; the escalation exemption is inert",
				"enable adaptive_enforcement to make the exemption effective, or remove the exempt_domains list",
			))
		}
	}

	if !cfg.CrossRequestDetection.Enabled || !cfg.CrossRequestDetection.EntropyBudget.Enabled {
		for _, domain := range cfg.CrossRequestDetection.EntropyBudget.ExemptDomains {
			detail := "cross_request_detection.entropy_budget.exempt_domains is set but cross_request_detection.enabled=false; this entropy-budget exemption is inert"
			next := "enable cross_request_detection and cross_request_detection.entropy_budget to make the exemption effective, or remove the exempt_domains list"
			if cfg.CrossRequestDetection.Enabled {
				detail = "cross_request_detection.entropy_budget.exempt_domains is set but cross_request_detection.entropy_budget.enabled=false; this entropy-budget exemption is inert"
			}
			findings = append(findings, newConfigSemanticFinding(
				ConfigSemanticKindInert,
				ConfigScopeCrossRequestEntropyExempt,
				domain,
				detail,
				next,
			))
		}
	}

	browserShieldDefaultExemptDomains := configDefaults().BrowserShield.ExemptDomains
	for _, domain := range operatorAddedStrings(cfg.BrowserShield.ExemptDomains, browserShieldDefaultExemptDomains) {
		if cfg.BrowserShield.Enabled {
			continue
		}
		findings = append(findings, newConfigSemanticFinding(
			ConfigSemanticKindInert,
			ConfigScopeBrowserShieldExemptDomains,
			domain,
			"browser_shield.exempt_domains is set but browser_shield.enabled=false; this shield exemption is inert",
			"enable browser_shield to make the exemption effective, or remove the exempt_domains entry",
		))
	}

	tlsInterceptionDefaultPassthroughDomains := configDefaults().TLSInterception.PassthroughDomains
	for _, domain := range operatorAddedStrings(cfg.TLSInterception.PassthroughDomains, tlsInterceptionDefaultPassthroughDomains) {
		if cfg.TLSInterception.Enabled {
			continue
		}
		findings = append(findings, newConfigSemanticFinding(
			ConfigSemanticKindInert,
			ConfigScopeTLSPassthroughDomains,
			domain,
			"tls_interception.passthrough_domains is set but tls_interception.enabled=false; this CONNECT passthrough exemption is inert",
			"enable tls_interception to make the passthrough effective, or remove the passthrough_domains entry",
		))
	}

	if !requestHeaderIgnoreListConsumed(cfg.RequestBodyScanning) {
		// Auto-filled default headers are not an operator-authored exemption, so
		// they are never flagged; only operator-added (non-default) headers on an
		// unconsumed ignore-list are inert. This matches the browser_shield and
		// tls_interception disabled-feature handling. Distinguishing a
		// deliberately re-typed default from an auto-fill needs config-origin
		// metadata (not yet available).
		for _, header := range operatorAddedHeaderNames(cfg.RequestBodyScanning.IgnoreHeaders, defaultRequestBodyIgnoreHeaders()) {
			findings = append(findings, newConfigSemanticFinding(
				ConfigSemanticKindInert,
				ConfigScopeRequestBodyIgnoreHeaders,
				header,
				requestHeaderIgnoreListInertDetail(cfg.RequestBodyScanning),
				"enable request_body_scanning with scan_headers=true and header_mode=all to make ignore_headers effective, or remove the unused header exemption",
			))
		}
	}

	findings = append(findings, analyzeDoctorQueryEntropyParamExclusions(cfg)...)

	for _, entry := range cfg.ResponseScanning.MCPServers {
		if !cfg.ResponseScanning.Enabled {
			continue
		}
		if entry.Trust != config.ResponseTrustReasoning || cfg.TaintTrustsMCPServer(entry.Server) {
			continue
		}
		findings = append(findings, newConfigSemanticFinding(
			ConfigSemanticKindMisdirected,
			ConfigScopeResponseMCPServers,
			entry.Server,
			fmt.Sprintf(
				"response_scanning.mcp_servers marks %q as reasoning-trusted, but taint.allowlisted_domains does not apply to MCP response taint and taint.trusted_mcp_servers does not include this server",
				entry.Server),
			"if this MCP server is an operator-trusted source, add its --server-name value to taint.trusted_mcp_servers; otherwise leave it untrusted for taint",
		))
	}

	return findings
}

func requestHeaderIgnoreListConsumed(cfg config.RequestBodyScanning) bool {
	return cfg.Enabled && cfg.ScanHeaders && cfg.HeaderMode == config.HeaderModeAll
}

func requestHeaderIgnoreListInertDetail(cfg config.RequestBodyScanning) string {
	switch {
	case !cfg.Enabled:
		return "request_body_scanning.ignore_headers is set but request_body_scanning.enabled=false; this header exemption is inert"
	case !cfg.ScanHeaders:
		return "request_body_scanning.ignore_headers is set but request_body_scanning.scan_headers=false; this header exemption is inert"
	case cfg.HeaderMode != config.HeaderModeAll:
		return "request_body_scanning.ignore_headers is set but request_body_scanning.header_mode is not all; this header exemption is inert"
	default:
		return "request_body_scanning.ignore_headers is set but header ignore-list scanning is disabled; this header exemption is inert"
	}
}

func operatorAddedStrings(entries, defaults []string) []string {
	return operatorAddedValues(entries, defaults, strings.TrimSpace)
}

func operatorAddedHeaderNames(entries, defaults []string) []string {
	return operatorAddedValues(entries, defaults, func(entry string) string {
		return http.CanonicalHeaderKey(strings.TrimSpace(entry))
	})
}

func operatorAddedValues(entries, defaults []string, normalize func(string) string) []string {
	type normalizedValue struct {
		raw        string
		normalized string
	}
	values := make([]normalizedValue, 0, len(entries))
	for _, entry := range entries {
		normalized := normalize(entry)
		if normalized == "" {
			continue
		}
		values = append(values, normalizedValue{raw: entry, normalized: normalized})
	}
	if len(values) == 0 {
		return nil
	}

	defaultSet := make(map[string]struct{}, len(defaults))
	for _, entry := range defaults {
		normalized := normalize(entry)
		if normalized != "" {
			defaultSet[normalized] = struct{}{}
		}
	}

	var out []string
	for _, value := range values {
		if _, isDefault := defaultSet[value.normalized]; isDefault {
			continue
		}
		out = append(out, value.raw)
	}
	return out
}

func defaultRequestBodyIgnoreHeaders() []string {
	return configDefaults().RequestBodyScanning.IgnoreHeaders
}

func analyzeDoctorQueryEntropyParamExclusions(cfg *config.Config) []ConfigSemanticFinding {
	entries := cfg.FetchProxy.Monitoring.QueryEntropyParamExclusions
	if len(entries) == 0 {
		return nil
	}
	var findings []ConfigSemanticFinding
	for _, entry := range entries {
		tuple := queryEntropyParamAdvisoryTuple(entry)
		if cfg.FetchProxy.Monitoring.EntropyThreshold <= 0 {
			findings = append(findings, newQueryEntropyParamFinding(
				ConfigSemanticKindInert,
				tuple,
				fmt.Sprintf("query_entropy_param_exclusions entry %s is configured but fetch_proxy.monitoring.entropy_threshold<=0; this exemption is inert", tuple),
				"remove the endpoint-parameter exemption while entropy is disabled, or re-enable entropy before relying on the narrow exemption",
			))
		}
		if queryEntropyParamCoveredByHostWide(entry, cfg.FetchProxy.Monitoring.QueryEntropyExclusions) {
			findings = append(findings, newQueryEntropyParamFinding(
				ConfigSemanticKindMisdirected,
				tuple,
				fmt.Sprintf("query_entropy_param_exclusions entry %s is redundant because query_entropy_exclusions already covers host %s", tuple, entry.Host),
				"prefer the endpoint-parameter exemption and remove the broader host-wide query_entropy_exclusions entry if the broad bypass is not needed",
			))
		}
		if strings.TrimSpace(entry.Reason) == "" {
			findings = append(findings, queryEntropyParamLifecycleCheck(tuple, "reason", "add a short reason so future operators know why this narrow entropy exemption exists"))
		}
		if strings.TrimSpace(entry.Owner) == "" {
			findings = append(findings, queryEntropyParamLifecycleCheck(tuple, "owner", "add an owner so future operators know who can revalidate this exemption"))
		}
		expires := strings.TrimSpace(entry.Expires)
		if expires == "" {
			findings = append(findings, queryEntropyParamLifecycleCheck(tuple, "expires", "add an expires date in YYYY-MM-DD format so this exemption gets periodically reviewed"))
			continue
		}
		parsed, err := time.Parse("2006-01-02", expires)
		if err != nil {
			findings = append(findings, newQueryEntropyParamFinding(
				ConfigSemanticKindAdvisory,
				tuple,
				fmt.Sprintf("query_entropy_param_exclusions entry %s has invalid expires %q; expected YYYY-MM-DD", tuple, expires),
				"set expires to a valid YYYY-MM-DD date, or remove the exemption if it is no longer needed",
			))
			continue
		}
		if parsed.Before(todayUTC()) {
			findings = append(findings, newQueryEntropyParamFinding(
				ConfigSemanticKindAdvisory,
				tuple,
				fmt.Sprintf("query_entropy_param_exclusions entry %s expired on %s", tuple, expires),
				"review whether the endpoint still needs the exemption; remove it or renew expires with a future YYYY-MM-DD date",
			))
		}
	}
	sortConfigSemanticFindings(findings)
	return findings
}

func queryEntropyParamLifecycleCheck(tuple, field, next string) ConfigSemanticFinding {
	return newQueryEntropyParamFinding(
		ConfigSemanticKindAdvisory,
		tuple,
		fmt.Sprintf("query_entropy_param_exclusions entry %s is missing advisory %s", tuple, field),
		next,
	)
}

func newQueryEntropyParamFinding(kind, subject, detail, next string) ConfigSemanticFinding {
	return newConfigSemanticFinding(kind, "fetch_proxy.monitoring.query_entropy_param_exclusions", subject, detail, next)
}

func queryEntropyParamCoveredByHostWide(entry config.QueryEntropyParamExclusion, hostWide []string) bool {
	for _, pattern := range hostWide {
		if scanner.MatchDomain(entry.Host, pattern) {
			return true
		}
	}
	return false
}

func queryEntropyParamAdvisoryTuple(entry config.QueryEntropyParamExclusion) string {
	scheme := entry.Scheme
	if scheme == "" {
		scheme = config.QueryEntropyParamDefaultScheme
	}
	return fmt.Sprintf("%s://%s%s?%s", scheme, entry.Host, entry.Path, entry.Param)
}

func todayUTC() time.Time {
	y, m, d := time.Now().UTC().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

func sortConfigSemanticFindings(findings []ConfigSemanticFinding) {
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Scope != findings[j].Scope {
			return findings[i].Scope < findings[j].Scope
		}
		return findings[i].Detail < findings[j].Detail
	})
}
