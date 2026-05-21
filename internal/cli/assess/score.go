// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package assess

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/cli/audit"
	"github.com/luckyPipewrench/pipelock/internal/cli/diag"
	"github.com/luckyPipewrench/pipelock/internal/discover"
	"github.com/luckyPipewrench/pipelock/internal/report/compliance"
)

// Finding and cap source constants identify which primitive produced an entry.
const (
	sourceSimulate      = "simulate"
	sourceAuditScore    = "audit_score"
	sourceVerifyInstall = "verify_install"
	sourceDiscover      = "discover"
	sourceManifest      = "manifest"
)

// Verify status/category constants mirrored from verify_install.go to avoid
// circular imports with the parent cli package.
const (
	verifyStatusPass = "pass"
	verifyStatusFail = "fail"
	verifyStatusNA   = "not_applicable"

	verifyCatScanning    = "scanning"
	verifyCatContainment = "containment"

	verifyContainmentContained = "contained"
	verifyContainmentExposed   = "exposed"
)

// Audit score severity constants mirrored from audit_score.go.
const (
	scoreSevCritical = "critical"
	scoreSevWarning  = "warning"
	scoreSevInfo     = "info"
)

// shouldAttachCompliance decides whether the compliance framework catalog
// is attached to an assessment. The catalog asserts product capabilities,
// but presenting it inside an assessment implies "and this run verified
// those capabilities are present." Partial runs cannot honestly make
// that claim. Returns the omission reason when compliance should NOT be
// attached, or empty when it should.
//
// Compliance is omitted when:
//   - any primitive was skipped (--skip on `assess run`);
//   - any primitive's evidence is absent at finalize time (caught by
//     verifyEvidenceIntegrity, but defense-in-depth here);
//   - the operator passed --allow-partial.
func shouldAttachCompliance(manifest AssessManifest, sources AssessSources) string {
	if manifest.AllowPartial {
		return "assessment finalized with --allow-partial; framework coverage is only attached to fully-evidenced runs"
	}
	if len(manifest.SkippedPrimitives) > 0 {
		return fmt.Sprintf("assessment skipped primitives %v; framework coverage is only attached to fully-evidenced runs", manifest.SkippedPrimitives)
	}
	if sources.Simulate == nil || sources.AuditScore == nil || sources.VerifyInstall == nil || sources.Discover == nil {
		return "one or more evidence sources missing at finalize time; framework coverage is only attached to fully-evidenced runs"
	}
	return ""
}

// synthesizeAssessment combines all source outputs into a scored Assessment.
func synthesizeAssessment(manifest AssessManifest, sources AssessSources) Assessment {
	// Sanitize the manifest copy embedded into the assessment output.
	// manifest.json on disk keeps the absolute config path because run
	// and re-finalize need it to re-read and hash the config; the
	// shared Assessment artifact (rendered into assessment.json,
	// summary.json, attestation primary artifact, HTML reports) must
	// not embed an operator filesystem path. Drop everything except
	// the basename so a customer viewing a signed bundle cannot infer
	// where the assessment was run.
	if manifest.ConfigFile != "" && manifest.ConfigFile != configLabelDefaults {
		manifest.ConfigFile = filepath.Base(manifest.ConfigFile)
	}

	// Compute sections.
	sections := []AssessmentSection{
		scoreDetectionCoverage(sources.Simulate),
		scoreConfigPosture(sources.AuditScore),
		scoreDeploymentVerification(sources.VerifyInstall),
		scoreMCPProtection(sources.Discover),
	}
	sortAssessmentSections(sections)

	// Weighted average (only sections with MaxScore > 0).
	weights := defaultScoringWeights()
	weightMap := map[string]int{
		sectionDetectionCoverage:      weights.DetectionCoverage,
		sectionConfigPosture:          weights.ConfigPosture,
		sectionDeploymentVerification: weights.DeploymentVerification,
		sectionMCPProtection:          weights.MCPProtection,
	}
	totalWeight, weightedSum := 0, 0
	for _, s := range sections {
		w := weightMap[s.ID]
		if s.MaxScore > 0 { // only count applicable sections
			totalWeight += w
			weightedSum += s.Score * w
		}
	}
	overallScore := 0
	if totalWeight > 0 {
		overallScore = weightedSum / totalWeight
	}
	overallGrade := gradeFromPercentage(overallScore)

	// Grade caps.
	capReasons := computeGradeCaps(sources, manifest.AllowPartial)
	gradeCap := ""
	if len(capReasons) > 0 {
		// Find lowest cap.
		lowestCap := capReasons[0].Cap
		for _, cr := range capReasons[1:] {
			if gradeOrder(cr.Cap) > gradeOrder(lowestCap) {
				lowestCap = cr.Cap
			}
		}
		// Apply cap if it's lower than computed grade.
		if gradeOrder(lowestCap) > gradeOrder(overallGrade) {
			overallGrade = lowestCap
			gradeCap = lowestCap
		}
	}

	// Generate findings.
	findings := generateFindings(sources)

	// Compliance frameworks are only attached when this assessment can
	// honestly claim coverage — meaning every primitive ran and produced
	// evidence. Partial runs omit the section and record why in the
	// manifest so the operator (and any downstream reader) can tell
	// "no coverage claim" from "didn't bother to check."
	var complianceFrameworks []compliance.Framework
	if reason := shouldAttachCompliance(manifest, sources); reason == "" {
		complianceFrameworks = compliance.Catalog()
	} else {
		manifest.ComplianceOmittedReason = reason
	}

	return Assessment{
		SchemaVersion: assessSchemaVersion,
		Manifest:      manifest,
		OverallGrade:  overallGrade,
		OverallScore:  overallScore,
		GradeCap:      gradeCap,
		CapReasons:    capReasons,
		Weights:       weights,
		Sections:      sections,
		Findings:      findings,
		Sources:       sources,
		Compliance:    complianceFrameworks,
	}
}

// gradeOrder returns higher number for worse grades (for cap comparison).
func gradeOrder(grade string) int {
	switch grade {
	case assessGradeA:
		return 0
	case assessGradeB:
		return 1
	case assessGradeC:
		return 2
	case assessGradeD:
		return 3
	case assessGradeF:
		return 4
	default:
		return 5
	}
}

// scoreDetectionCoverage produces the detection coverage section from simulate output.
func scoreDetectionCoverage(sim *audit.SimulateResult) AssessmentSection {
	if sim == nil {
		return AssessmentSection{
			SchemaVersion: assessSchemaVersion,
			ID:            sectionDetectionCoverage,
			Name:          "Detection Coverage",
			Score:         0,
			MaxScore:      0,
			Grade:         assessGradeF,
			Applicable:    0,
			Total:         0,
		}
	}
	return AssessmentSection{
		SchemaVersion: assessSchemaVersion,
		ID:            sectionDetectionCoverage,
		Name:          "Detection Coverage",
		Score:         sim.Percentage,
		MaxScore:      100,
		Grade:         gradeFromPercentage(sim.Percentage),
		Detail:        fmt.Sprintf("%d/%d scenarios detected", sim.Passed, sim.Total-sim.KnownLimits),
		Applicable:    sim.Total - sim.KnownLimits,
		Total:         sim.Total,
	}
}

// scoreConfigPosture produces the config posture section from audit-score output.
func scoreConfigPosture(audit *audit.ScoreResult) AssessmentSection {
	if audit == nil {
		return AssessmentSection{
			SchemaVersion: assessSchemaVersion,
			ID:            sectionConfigPosture,
			Name:          "Config Posture",
			Score:         0,
			MaxScore:      0,
			Grade:         assessGradeF,
			Applicable:    0,
			Total:         0,
		}
	}
	return AssessmentSection{
		SchemaVersion: assessSchemaVersion,
		ID:            sectionConfigPosture,
		Name:          "Config Posture",
		Score:         audit.Percentage,
		MaxScore:      100,
		Grade:         gradeFromPercentage(audit.Percentage),
		Detail:        fmt.Sprintf("%d/%d points", audit.TotalScore, audit.MaxScore),
		Applicable:    len(audit.Categories),
		Total:         len(audit.Categories),
	}
}

// scoreDeploymentVerification produces the deployment verification section.
// Applicability-aware: only score checks that are not "not_applicable".
func scoreDeploymentVerification(verify *diag.VerifyReport) AssessmentSection {
	if verify == nil {
		return AssessmentSection{
			SchemaVersion: assessSchemaVersion,
			ID:            sectionDeploymentVerification,
			Name:          "Deployment Verification",
			Score:         0,
			MaxScore:      0,
			Grade:         assessGradeF,
			Applicable:    0,
			Total:         0,
		}
	}

	// An empty Checks slice is structurally indistinguishable from a
	// corrupt or stub VerifyReport. Without recorded checks, there is no
	// evidence anything was probed; treat as inapplicable (MaxScore=0)
	// so the section is excluded from the weighted average rather than
	// awarded a perfect score by accident.
	if len(verify.Checks) == 0 {
		return AssessmentSection{
			SchemaVersion: assessSchemaVersion,
			ID:            sectionDeploymentVerification,
			Name:          "Deployment Verification",
			Score:         0,
			MaxScore:      0,
			Grade:         assessGradeF,
			Detail:        "no checks recorded",
			Applicable:    0,
			Total:         0,
		}
	}

	applicable, passed := 0, 0
	for _, c := range verify.Checks {
		if c.Status == verifyStatusNA {
			continue
		}
		applicable++
		if c.Status == verifyStatusPass {
			passed++
		}
	}

	// All recorded checks were N/A (e.g., host-mode run with no containment
	// probes applicable). Reward because the report exists with checks —
	// distinguishes "we looked and nothing applied" from "we have nothing
	// to show".
	if applicable == 0 {
		return AssessmentSection{
			SchemaVersion: assessSchemaVersion,
			ID:            sectionDeploymentVerification,
			Name:          "Deployment Verification",
			Score:         100,
			MaxScore:      100,
			Grade:         assessGradeA,
			Detail:        "all checks not applicable",
			Applicable:    0,
			Total:         len(verify.Checks),
		}
	}

	pct := (passed * 100) / applicable
	return AssessmentSection{
		SchemaVersion: assessSchemaVersion,
		ID:            sectionDeploymentVerification,
		Name:          "Deployment Verification",
		Score:         pct,
		MaxScore:      100,
		Grade:         gradeFromPercentage(pct),
		Detail:        fmt.Sprintf("%d/%d applicable checks passed", passed, applicable),
		Applicable:    applicable,
		Total:         len(verify.Checks),
	}
}

// scoreMCPProtection produces the MCP protection section from discover output.
func scoreMCPProtection(disc *AssessDiscoverReport) AssessmentSection {
	if disc == nil {
		return AssessmentSection{
			SchemaVersion: assessSchemaVersion,
			ID:            sectionMCPProtection,
			Name:          "MCP Protection",
			Score:         0,
			MaxScore:      0,
			Grade:         assessGradeF,
			Applicable:    0,
			Total:         0,
		}
	}

	// Count parse errors across clients.
	parseErrors := 0
	for _, c := range disc.Clients {
		if c.ParseError != "" {
			parseErrors++
		}
	}

	totalServers := len(disc.Servers)

	// Zero servers AND clean scan (no parse errors): perfect score.
	if totalServers == 0 && parseErrors == 0 {
		return AssessmentSection{
			SchemaVersion: assessSchemaVersion,
			ID:            sectionMCPProtection,
			Name:          "MCP Protection",
			Score:         100,
			MaxScore:      100,
			Grade:         assessGradeA,
			Detail:        "no MCP servers configured",
			Applicable:    0,
			Total:         0,
		}
	}

	// Zero servers WITH parse errors: penalize proportionally.
	if totalServers == 0 && parseErrors > 0 {
		// Each parse error client contributes 0% for its estimated servers.
		// With no servers to score, the best we can say is 0.
		return AssessmentSection{
			SchemaVersion: assessSchemaVersion,
			ID:            sectionMCPProtection,
			Name:          "MCP Protection",
			Score:         0,
			MaxScore:      100,
			Grade:         assessGradeF,
			Detail:        fmt.Sprintf("%d client parse errors, no servers scored", parseErrors),
			Applicable:    0,
			Total:         parseErrors,
		}
	}

	// Score servers: protected = 100%, unknown = 50%, unprotected = 0%.
	// Client parse errors add to the denominator with 0% credit (failed evidence).
	var numerator int
	for _, s := range disc.Servers {
		switch s.Protection {
		case discover.ProtectedPipelock, discover.ProtectedOther:
			numerator += 100
		case discover.Unknown:
			// 50% credit for unknown servers.
			numerator += 50
		}
		// unprotected = 0
	}

	// Each client with a parse error contributes an estimated server that
	// scores 0%. This prevents a partially unreadable discovery run from
	// reporting full protection.
	denominator := totalServers + parseErrors

	pct := numerator / denominator
	return AssessmentSection{
		SchemaVersion: assessSchemaVersion,
		ID:            sectionMCPProtection,
		Name:          "MCP Protection",
		Score:         pct,
		MaxScore:      100,
		Grade:         gradeFromPercentage(pct),
		Detail:        fmt.Sprintf("%d servers scored, %d client parse errors", totalServers, parseErrors),
		Applicable:    totalServers,
		Total:         totalServers + parseErrors,
	}
}

// computeGradeCaps evaluates raw evidence and returns applicable caps.
func computeGradeCaps(sources AssessSources, allowPartial bool) []CapReason {
	var caps []CapReason

	// Cap: verify-install containment check failed (not N/A) -> C
	if sources.VerifyInstall != nil {
		for _, c := range sources.VerifyInstall.Checks {
			if c.Category == verifyCatContainment && c.Status == verifyStatusFail {
				caps = append(caps, CapReason{
					Cap:        assessGradeC,
					Reason:     fmt.Sprintf("containment check %q failed", c.Name),
					Source:     sourceVerifyInstall,
					EvidenceID: c.Name,
				})
			}
		}
	}

	// Cap: discover server with Risk=="high" and Protection=="unprotected" -> C
	if sources.Discover != nil {
		for _, s := range sources.Discover.Servers {
			if s.Risk == discover.RiskHigh && s.Protection == discover.Unprotected {
				caps = append(caps, CapReason{
					Cap:        assessGradeC,
					Reason:     fmt.Sprintf("high-risk MCP server %q (%s) is unprotected", s.ServerName, s.Client),
					Source:     sourceDiscover,
					EvidenceID: slugify(s.Client + "-" + s.ServerName),
				})
			}
		}
	}

	// Cap: simulate category with 0% detection -> D
	// Group ScenarioResults by Category, find any where all Detected==false.
	// Absent/empty categories = N/A, NOT 0%.
	if sources.Simulate != nil && len(sources.Simulate.Scenarios) > 0 {
		type catStats struct {
			total    int
			detected int
		}
		categories := make(map[string]*catStats)
		for _, s := range sources.Simulate.Scenarios {
			if s.Limitation {
				continue // skip known limitations
			}
			cs, ok := categories[s.Category]
			if !ok {
				cs = &catStats{}
				categories[s.Category] = cs
			}
			cs.total++
			if s.Detected {
				cs.detected++
			}
		}
		for cat, cs := range categories {
			if cs.total > 0 && cs.detected == 0 {
				caps = append(caps, CapReason{
					Cap:        assessGradeD,
					Reason:     fmt.Sprintf("simulate category %q has 0%% detection (%d scenarios)", cat, cs.total),
					Source:     sourceSimulate,
					EvidenceID: slugify(cat),
				})
			}
		}
	}

	// Cap: verify-install summary containment=="exposed" -> D
	if sources.VerifyInstall != nil && sources.VerifyInstall.Summary.Containment == verifyContainmentExposed {
		caps = append(caps, CapReason{
			Cap:        assessGradeD,
			Reason:     "deployment containment is exposed",
			Source:     sourceVerifyInstall,
			EvidenceID: "containment-exposed",
		})
	}

	// Cap: allowPartial is true -> B
	if allowPartial {
		caps = append(caps, CapReason{
			Cap:        assessGradeB,
			Reason:     "partial assessment (some primitives skipped)",
			Source:     sourceManifest,
			EvidenceID: "allow-partial",
		})
	}

	return caps
}

// mapScoreFindingSeverity maps audit score severity to assess finding severity.
func mapScoreFindingSeverity(sev string) string {
	switch sev {
	case scoreSevCritical:
		return assessSevCritical
	case scoreSevWarning:
		return assessSevMedium
	case scoreSevInfo:
		return assessSevInfo
	default:
		return assessSevInfo
	}
}

// auditRemediation returns category-specific remediation text for
// audit-score findings. Category names are matched against the
// audit.Category* constants — keep this switch in sync with the
// scoring functions in internal/cli/audit/.
func auditRemediation(category string) string {
	switch category {
	// Schema-v1 categories (original audit set).
	case "Sandbox":
		return "Enable sandbox mode with `sandbox: {enabled: true}` in your pipelock config."
	case "DLP":
		return "Add DLP patterns or enable env leak scanning with `dlp: {scan_env: true}`."
	case "Response Scanning":
		return "Enable response scanning with `response_scanning: {enabled: true, action: block}`."
	case "MCP Tool Scanning":
		return "Enable MCP tool scanning with `mcp_tool_scanning: {enabled: true, action: block}`."
	case "MCP Tool Policy":
		return "Add tool policy rules to restrict dangerous tool calls. See docs/configuration.md."
	case "MCP Input Scanning":
		return "Enable MCP input scanning with `mcp_input_scanning: {enabled: true}`."
	case "MCP Session Binding":
		return "Enable session binding with `mcp_session_binding: {enabled: true}`."
	case "Kill Switch":
		return "Configure kill switch with multiple sources (config, API, sentinel file)."
	case "Enforcement":
		return "Switch to strict mode with `mode: strict` for maximum protection."
	case "Domain Blocklist":
		return "Add known exfiltration domains to `fetch_proxy.monitoring.blocklist`."
	case "Adaptive Enforcement":
		return "Enable adaptive enforcement with `adaptive_enforcement: {enabled: true}`."
	case "Tool Chain Detection":
		return "Enable chain detection with `tool_chain_detection: {enabled: true}`."

	// Schema-v2 categories (added 2026-05 for pipelock v2.1-v2.5 features).
	case audit.CategoryLiveLockContracts:
		return "Enable the live-lock contract gate with `learn_lock: {enabled: true, mode: live}`. Use `mode: shadow` first to observe drift before flipping to enforcement."
	case audit.CategoryRedaction:
		return "Enable class-preserving redaction with `redaction: {enabled: true, default_profile: <profile>}`. Configure a default profile and dictionaries, then set `strict_reload: true` for fail-closed dictionary failures."
	case audit.CategoryBrowserShield:
		return "Enable browser shield with `browser_shield: {enabled: true, strictness: standard}`. Use `aggressive` for sensitive fetch destinations."
	case audit.CategoryMediationEnvelope:
		return "Enable mediation envelope with `mediation_envelope: {enabled: true, sign: true, signing_key_path: <ed25519-key>}` to produce signed receipts that downstream verifiers can attest."
	case audit.CategoryFlightRecorder:
		return "Enable tamper-evident decision recording with `flight_recorder: {enabled: true, sign_checkpoints: true, redact: true}`."
	case audit.CategoryRequestBody:
		return "Enable request body scanning with `request_body_scanning: {enabled: true, action: block, scan_headers: true}` to catch secrets in POST/PUT bodies and authorization headers."
	case audit.CategoryCrossRequest:
		return "Enable cross-request detection with `cross_request_detection: {enabled: true, entropy_budget: {enabled: true}, fragment_reassembly: {enabled: true}}` to catch secrets split across requests."
	case audit.CategoryAddressProtect:
		return "Enable blockchain address protection with `address_protection: {enabled: true, action: block, unknown_action: block, allowed_addresses: [<your-addresses>]}`."
	case audit.CategorySeedPhrase:
		return "Seed-phrase detection is on by default. To restore defaults, remove the `seed_phrase_detection.enabled` field or set it to `null`."
	case audit.CategoryGitProtection:
		return "Enable git-aware protection with `git_protection: {enabled: true, pre_push_scan: true, blocked_commands: [\"force-push\"]}`."
	case audit.CategoryFileSentry:
		return "Enable filesystem-watch DLP with `file_sentry: {enabled: true, watch_paths: [<sensitive-paths>]}`."

	default:
		return "Review the configuration section and enable recommended protections."
	}
}

// generateFindings extracts findings from all source outputs.
func generateFindings(sources AssessSources) []Finding {
	var findings []Finding

	// From simulate: each scenario where Detected==false && Limitation==false.
	if sources.Simulate != nil {
		for _, s := range sources.Simulate.Scenarios {
			if !s.Detected && !s.Limitation {
				evidence, _ := json.Marshal(map[string]any{
					"scenario": s.Name,
					"category": s.Category,
					"detected": false,
				})
				findings = append(findings, Finding{
					SchemaVersion: assessSchemaVersion,
					ID:            "find-sim-" + slugify(s.Name),
					Severity:      assessSevHigh,
					Category:      s.Category,
					Source:        sourceSimulate,
					Title:         fmt.Sprintf("Attack scenario %q not detected", s.Name),
					Remediation:   fmt.Sprintf("Enable or strengthen the %s scanner configuration. See pipelock documentation for recommended settings.", s.Category),
					Evidence:      evidence,
				})
			}
		}
	}

	// From audit score: each ScoreFinding.
	if sources.AuditScore != nil {
		for i, f := range sources.AuditScore.Findings {
			evidence, _ := json.Marshal(map[string]string{
				"category": f.Category,
				"message":  f.Message,
			})
			findings = append(findings, Finding{
				SchemaVersion: assessSchemaVersion,
				ID:            fmt.Sprintf("find-audit-%s-%d", slugify(f.Category), i),
				Severity:      mapScoreFindingSeverity(f.Severity),
				Category:      f.Category,
				Source:        sourceAuditScore,
				Title:         f.Message,
				Remediation:   auditRemediation(f.Category),
				Evidence:      evidence,
			})
		}
	}

	// From verify-install: each check with Status=="fail".
	if sources.VerifyInstall != nil {
		for _, c := range sources.VerifyInstall.Checks {
			if c.Status != verifyStatusFail {
				continue
			}
			sev := assessSevHigh
			if c.Category == verifyCatContainment {
				sev = assessSevCritical
			}
			evidence, _ := json.Marshal(map[string]string{
				"check":  c.Name,
				"status": verifyStatusFail,
				"detail": c.Detail,
			})
			findings = append(findings, Finding{
				SchemaVersion: assessSchemaVersion,
				ID:            "find-verify-" + c.Name,
				Severity:      sev,
				Category:      c.Category,
				Source:        sourceVerifyInstall,
				Title:         fmt.Sprintf("Verification check %q failed: %s", c.Name, c.Detail),
				Remediation:   fmt.Sprintf("Investigate why the %s check failed. Run `pipelock diagnose` for detailed diagnostics.", c.Name),
				Evidence:      evidence,
			})
		}
	}

	// From discover: each server with Protection=="unprotected".
	if sources.Discover != nil {
		for _, s := range sources.Discover.Servers {
			if s.Protection != discover.Unprotected {
				continue
			}
			sev := assessSevMedium
			remediation := "Wrap this MCP server with pipelock: `pipelock mcp proxy --config pipelock.yaml -- <original-command>`."
			if s.Risk == discover.RiskHigh {
				sev = assessSevHigh
				remediation = "Wrap this MCP server with pipelock: `pipelock mcp proxy --config pipelock.yaml -- <original-command>`. High-risk servers with database or shell access should be prioritized."
			}
			evidence, _ := json.Marshal(map[string]string{
				"client": s.Client,
				"server": s.ServerName,
				"risk":   string(s.Risk),
			})
			findings = append(findings, Finding{
				SchemaVersion: assessSchemaVersion,
				ID:            "find-discover-" + slugify(s.Client+"-"+s.ServerName),
				Severity:      sev,
				Category:      sectionMCPProtection,
				Source:        sourceDiscover,
				Title:         fmt.Sprintf("MCP server %q (%s) is unprotected", s.ServerName, s.Client),
				Remediation:   remediation,
				Evidence:      evidence,
			})
		}
	}

	sortFindings(findings)
	return findings
}

// slugifyPattern matches characters that are not alphanumeric or hyphens.
var slugifyPattern = regexp.MustCompile(`[^a-z0-9-]+`)

// slugify converts a name to a lowercase hyphen-separated slug.
func slugify(s string) string {
	lower := strings.ToLower(s)
	slug := slugifyPattern.ReplaceAllString(lower, "-")
	slug = strings.Trim(slug, "-")
	return slug
}
