// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/discover"
)

// Finding and cap source constants identify which primitive produced an entry.
const (
	sourceSimulate      = "simulate"
	sourceAuditScore    = "audit_score"
	sourceVerifyInstall = "verify_install"
	sourceDiscover      = "discover"
	sourceManifest      = "manifest"
)

// synthesizeAssessment combines all source outputs into a scored Assessment.
func synthesizeAssessment(manifest AssessManifest, sources AssessSources) Assessment {
	// 1. Compute sections.
	sections := []AssessmentSection{
		scoreDetectionCoverage(sources.Simulate),
		scoreConfigPosture(sources.AuditScore),
		scoreDeploymentVerification(sources.VerifyInstall),
		scoreMCPProtection(sources.Discover),
	}
	sortAssessmentSections(sections)

	// 2. Weighted average (only sections with MaxScore > 0).
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

	// 3. Grade caps.
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

	// 4. Generate findings.
	findings := generateFindings(sources)

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
func scoreDetectionCoverage(sim *SimulateResult) AssessmentSection {
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
func scoreConfigPosture(audit *ScoreResult) AssessmentSection {
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
func scoreDeploymentVerification(verify *VerifyReport) AssessmentSection {
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

	// If all checks are N/A (e.g., host run with no containment): perfect score.
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
			if s.Risk == discover.RiskHigh {
				sev = assessSevHigh
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
