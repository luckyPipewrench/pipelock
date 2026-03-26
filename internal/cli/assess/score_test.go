// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package assess

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/cli/audit"
	"github.com/luckyPipewrench/pipelock/internal/cli/diag"
	"github.com/luckyPipewrench/pipelock/internal/discover"
)

func TestScoreDetectionCoverage(t *testing.T) {
	t.Run("from simulate result", func(t *testing.T) {
		sim := &audit.SimulateResult{
			Total:       20,
			Passed:      18,
			Failed:      2,
			KnownLimits: 0,
			Percentage:  90,
			Scenarios:   nil,
		}
		s := scoreDetectionCoverage(sim)
		if s.ID != sectionDetectionCoverage {
			t.Errorf("ID = %q, want %q", s.ID, sectionDetectionCoverage)
		}
		if s.Score != 90 {
			t.Errorf("Score = %d, want 90", s.Score)
		}
		if s.MaxScore != 100 {
			t.Errorf("MaxScore = %d, want 100", s.MaxScore)
		}
		if s.Grade != assessGradeA {
			t.Errorf("Grade = %q, want %q", s.Grade, assessGradeA)
		}
		if s.Applicable != 20 {
			t.Errorf("Applicable = %d, want 20", s.Applicable)
		}
	})

	t.Run("nil returns zero section", func(t *testing.T) {
		s := scoreDetectionCoverage(nil)
		if s.Score != 0 || s.MaxScore != 0 || s.Applicable != 0 {
			t.Errorf("nil sim: Score=%d MaxScore=%d Applicable=%d, want all 0", s.Score, s.MaxScore, s.Applicable)
		}
	})

	t.Run("with known limitations", func(t *testing.T) {
		sim := &audit.SimulateResult{
			Total:       10,
			Passed:      6,
			Failed:      2,
			KnownLimits: 2,
			Percentage:  75,
		}
		s := scoreDetectionCoverage(sim)
		// Applicable should be total - known limits = 8
		if s.Applicable != 8 {
			t.Errorf("Applicable = %d, want 8", s.Applicable)
		}
		if s.Total != 10 {
			t.Errorf("Total = %d, want 10", s.Total)
		}
	})
}

func TestScoreConfigPosture(t *testing.T) {
	t.Run("from audit result", func(t *testing.T) {
		audit := &audit.ScoreResult{
			TotalScore: 80,
			MaxScore:   100,
			Percentage: 80,
			Grade:      "B",
			Categories: []audit.ScoreCategory{
				{Name: "DLP", Score: 15, MaxScore: 15},
				{Name: "Response Scanning", Score: 10, MaxScore: 10},
			},
		}
		s := scoreConfigPosture(audit)
		if s.ID != sectionConfigPosture {
			t.Errorf("ID = %q, want %q", s.ID, sectionConfigPosture)
		}
		if s.Score != 80 {
			t.Errorf("Score = %d, want 80", s.Score)
		}
		if s.MaxScore != 100 {
			t.Errorf("MaxScore = %d, want 100", s.MaxScore)
		}
		if s.Grade != assessGradeB {
			t.Errorf("Grade = %q, want %q", s.Grade, assessGradeB)
		}
		if s.Applicable != 2 {
			t.Errorf("Applicable = %d, want 2", s.Applicable)
		}
	})

	t.Run("nil returns zero section", func(t *testing.T) {
		s := scoreConfigPosture(nil)
		if s.Score != 0 || s.MaxScore != 0 || s.Applicable != 0 {
			t.Errorf("nil audit: Score=%d MaxScore=%d Applicable=%d, want all 0", s.Score, s.MaxScore, s.Applicable)
		}
	})
}

func TestScoreDeploymentVerification(t *testing.T) {
	t.Run("applicability-aware scoring", func(t *testing.T) {
		report := &diag.VerifyReport{
			Checks: []diag.VerifyReportCheck{
				{Name: "config_valid", Category: verifyCatScanning, Status: verifyStatusPass},
				{Name: "proxy_health", Category: verifyCatScanning, Status: verifyStatusPass},
				{Name: "fetch_dlp", Category: verifyCatScanning, Status: verifyStatusFail},
				{Name: "no_direct_http", Category: verifyCatContainment, Status: verifyStatusNA},
				{Name: "no_direct_dns", Category: verifyCatContainment, Status: verifyStatusNA},
			},
		}
		s := scoreDeploymentVerification(report)
		// 3 applicable (2 pass, 1 fail), 2 N/A
		if s.Applicable != 3 {
			t.Errorf("Applicable = %d, want 3", s.Applicable)
		}
		// score = (2/3)*100 = 66
		wantScore := (2 * 100) / 3
		if s.Score != wantScore {
			t.Errorf("Score = %d, want %d", s.Score, wantScore)
		}
		if s.Total != 5 {
			t.Errorf("Total = %d, want 5", s.Total)
		}
	})

	t.Run("nil returns zero section", func(t *testing.T) {
		s := scoreDeploymentVerification(nil)
		if s.Score != 0 || s.MaxScore != 0 || s.Applicable != 0 {
			t.Errorf("nil verify: Score=%d MaxScore=%d Applicable=%d, want all 0", s.Score, s.MaxScore, s.Applicable)
		}
	})

	t.Run("mixed pass and fail", func(t *testing.T) {
		report := &diag.VerifyReport{
			Checks: []diag.VerifyReportCheck{
				{Name: "a", Category: verifyCatScanning, Status: verifyStatusPass},
				{Name: "b", Category: verifyCatScanning, Status: verifyStatusPass},
				{Name: "c", Category: verifyCatScanning, Status: verifyStatusPass},
				{Name: "d", Category: verifyCatScanning, Status: verifyStatusFail},
			},
		}
		s := scoreDeploymentVerification(report)
		if s.Score != 75 {
			t.Errorf("Score = %d, want 75", s.Score)
		}
	})
}

func TestScoreDeploymentVerification_AllNA(t *testing.T) {
	report := &diag.VerifyReport{
		Checks: []diag.VerifyReportCheck{
			{Name: "no_direct_http", Category: verifyCatContainment, Status: verifyStatusNA},
			{Name: "no_direct_dns", Category: verifyCatContainment, Status: verifyStatusNA},
			{Name: "no_direct_https", Category: verifyCatContainment, Status: verifyStatusNA},
		},
	}
	s := scoreDeploymentVerification(report)
	if s.Score != 100 {
		t.Errorf("all N/A: Score = %d, want 100", s.Score)
	}
	if s.MaxScore != 100 {
		t.Errorf("all N/A: MaxScore = %d, want 100", s.MaxScore)
	}
	if s.Grade != assessGradeA {
		t.Errorf("all N/A: Grade = %q, want %q", s.Grade, assessGradeA)
	}
	if s.Applicable != 0 {
		t.Errorf("all N/A: Applicable = %d, want 0", s.Applicable)
	}
}

func TestScoreMCPProtection(t *testing.T) {
	t.Run("unknown gets 50% credit", func(t *testing.T) {
		disc := &AssessDiscoverReport{
			Servers: []AssessDiscoverServer{
				{MCPServer: discover.MCPServer{Client: "cursor", ServerName: "a", Protection: discover.ProtectedPipelock, Risk: discover.RiskLow}},
				{MCPServer: discover.MCPServer{Client: "cursor", ServerName: "b", Protection: discover.Unknown, Risk: discover.RiskLow}},
			},
			Clients: []AssessDiscoverClient{},
		}
		s := scoreMCPProtection(disc)
		// (100 + 50) / 2 = 75
		if s.Score != 75 {
			t.Errorf("Score = %d, want 75", s.Score)
		}
		if s.Applicable != 2 {
			t.Errorf("Applicable = %d, want 2", s.Applicable)
		}
	})

	t.Run("unprotected gets 0%", func(t *testing.T) {
		disc := &AssessDiscoverReport{
			Servers: []AssessDiscoverServer{
				{MCPServer: discover.MCPServer{Client: "cc", ServerName: "a", Protection: discover.Unprotected, Risk: discover.RiskHigh}},
			},
			Clients: []AssessDiscoverClient{},
		}
		s := scoreMCPProtection(disc)
		if s.Score != 0 {
			t.Errorf("Score = %d, want 0", s.Score)
		}
	})

	t.Run("parse errors with no servers", func(t *testing.T) {
		disc := &AssessDiscoverReport{
			Servers: []AssessDiscoverServer{},
			Clients: []AssessDiscoverClient{
				{ClientConfig: discover.ClientConfig{Client: "cursor", ParseError: "bad json"}},
			},
		}
		s := scoreMCPProtection(disc)
		if s.Score != 0 {
			t.Errorf("Score = %d, want 0", s.Score)
		}
		if s.MaxScore != 100 {
			t.Errorf("MaxScore = %d, want 100", s.MaxScore)
		}
	})

	t.Run("nil returns zero section", func(t *testing.T) {
		s := scoreMCPProtection(nil)
		if s.Score != 0 || s.MaxScore != 0 || s.Applicable != 0 {
			t.Errorf("nil disc: Score=%d MaxScore=%d Applicable=%d, want all 0", s.Score, s.MaxScore, s.Applicable)
		}
	})

	t.Run("mixed protection states", func(t *testing.T) {
		disc := &AssessDiscoverReport{
			Servers: []AssessDiscoverServer{
				{MCPServer: discover.MCPServer{Client: "cc", ServerName: "a", Protection: discover.ProtectedPipelock, Risk: discover.RiskLow}},
				{MCPServer: discover.MCPServer{Client: "cc", ServerName: "b", Protection: discover.ProtectedOther, Risk: discover.RiskLow}},
				{MCPServer: discover.MCPServer{Client: "cc", ServerName: "c", Protection: discover.Unprotected, Risk: discover.RiskMedium}},
				{MCPServer: discover.MCPServer{Client: "cc", ServerName: "d", Protection: discover.Unknown, Risk: discover.RiskLow}},
			},
			Clients: []AssessDiscoverClient{},
		}
		s := scoreMCPProtection(disc)
		// (100 + 100 + 0 + 50) / 4 = 62
		if s.Score != 62 {
			t.Errorf("Score = %d, want 62", s.Score)
		}
	})

	t.Run("parse errors with servers present degrade score", func(t *testing.T) {
		disc := &AssessDiscoverReport{
			Servers: []AssessDiscoverServer{
				{MCPServer: discover.MCPServer{Client: "cc", ServerName: "a", Protection: discover.ProtectedPipelock, Risk: discover.RiskLow}},
				{MCPServer: discover.MCPServer{Client: "cc", ServerName: "b", Protection: discover.ProtectedPipelock, Risk: discover.RiskLow}},
			},
			Clients: []AssessDiscoverClient{
				{ClientConfig: discover.ClientConfig{Client: "cursor", ParseError: "bad json"}},
			},
		}
		s := scoreMCPProtection(disc)
		// 2 servers protected (100+100) / (2 servers + 1 parse error) = 200/3 = 66
		if s.Score != 66 {
			t.Errorf("Score = %d, want 66 (parse error penalizes)", s.Score)
		}
		if s.Total != 3 {
			t.Errorf("Total = %d, want 3 (2 servers + 1 parse error)", s.Total)
		}
	})
}

func TestScoreMCPProtection_ZeroServers(t *testing.T) {
	t.Run("clean zero = 100", func(t *testing.T) {
		disc := &AssessDiscoverReport{
			Servers: []AssessDiscoverServer{},
			Clients: []AssessDiscoverClient{},
		}
		s := scoreMCPProtection(disc)
		if s.Score != 100 {
			t.Errorf("clean zero: Score = %d, want 100", s.Score)
		}
		if s.Grade != assessGradeA {
			t.Errorf("clean zero: Grade = %q, want %q", s.Grade, assessGradeA)
		}
	})
}

func TestGradeCap_ContainmentFailed(t *testing.T) {
	sources := AssessSources{
		VerifyInstall: &diag.VerifyReport{
			Checks: []diag.VerifyReportCheck{
				{Name: "no_direct_http", Category: verifyCatContainment, Status: verifyStatusFail},
			},
			Summary: diag.VerifyReportSummary{Containment: verifyContainmentExposed},
		},
	}
	caps := computeGradeCaps(sources, false)
	found := false
	for _, c := range caps {
		if c.Cap == assessGradeC && c.Source == sourceVerifyInstall {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected C cap from containment failure, got none")
	}
}

func TestGradeCap_HighRiskUnprotected(t *testing.T) {
	sources := AssessSources{
		Discover: &AssessDiscoverReport{
			Servers: []AssessDiscoverServer{
				{MCPServer: discover.MCPServer{
					Client:     "cursor",
					ServerName: "shell",
					Risk:       discover.RiskHigh,
					Protection: discover.Unprotected,
				}},
			},
		},
	}
	caps := computeGradeCaps(sources, false)
	found := false
	for _, c := range caps {
		if c.Cap == assessGradeC && c.Source == sourceDiscover {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected C cap from high-risk unprotected server, got none")
	}
}

func TestGradeCap_ZeroDetectionCategory(t *testing.T) {
	sources := AssessSources{
		Simulate: &audit.SimulateResult{
			Scenarios: []audit.ScenarioResult{
				{Name: "test1", Category: "SSRF", Detected: false},
				{Name: "test2", Category: "SSRF", Detected: false},
				{Name: "test3", Category: "DLP Exfiltration", Detected: true},
			},
		},
	}
	caps := computeGradeCaps(sources, false)
	found := false
	for _, c := range caps {
		if c.Cap == assessGradeD && c.Source == sourceSimulate {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected D cap from 0% SSRF detection, got none")
	}
}

func TestGradeCap_Exposed(t *testing.T) {
	sources := AssessSources{
		VerifyInstall: &diag.VerifyReport{
			Checks:  []diag.VerifyReportCheck{},
			Summary: diag.VerifyReportSummary{Containment: verifyContainmentExposed},
		},
	}
	caps := computeGradeCaps(sources, false)
	found := false
	for _, c := range caps {
		if c.Cap == assessGradeD && c.EvidenceID == "containment-exposed" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected D cap from exposed containment, got none")
	}
}

func TestGradeCap_AllowPartial(t *testing.T) {
	sources := AssessSources{}
	caps := computeGradeCaps(sources, true)
	found := false
	for _, c := range caps {
		if c.Cap == assessGradeB && c.Source == sourceManifest {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected B cap from allowPartial, got none")
	}
}

func TestGradeCap_StackLowestWins(t *testing.T) {
	// Both containment fail (C cap) and exposed summary (D cap).
	// D is worse than C, so D should be the effective cap.
	sources := AssessSources{
		VerifyInstall: &diag.VerifyReport{
			Checks: []diag.VerifyReportCheck{
				{Name: "no_direct_http", Category: verifyCatContainment, Status: verifyStatusFail},
			},
			Summary: diag.VerifyReportSummary{Containment: verifyContainmentExposed},
		},
	}
	caps := computeGradeCaps(sources, true) // also adds B cap from allowPartial
	if len(caps) < 3 {
		t.Fatalf("expected at least 3 caps, got %d", len(caps))
	}

	// Find lowest cap.
	lowestCap := caps[0].Cap
	for _, cr := range caps[1:] {
		if gradeOrder(cr.Cap) > gradeOrder(lowestCap) {
			lowestCap = cr.Cap
		}
	}
	if lowestCap != assessGradeD {
		t.Errorf("lowest cap = %q, want %q", lowestCap, assessGradeD)
	}
}

func TestGradeCap_AbsentCategory(t *testing.T) {
	// Simulate result that has DLP scenarios but no SSRF scenarios.
	// Absent categories should NOT trigger a 0% detection cap.
	sources := AssessSources{
		Simulate: &audit.SimulateResult{
			Scenarios: []audit.ScenarioResult{
				{Name: "aws key", Category: "DLP Exfiltration", Detected: true},
				{Name: "github token", Category: "DLP Exfiltration", Detected: true},
			},
		},
	}
	caps := computeGradeCaps(sources, false)
	for _, c := range caps {
		if c.Cap == assessGradeD && c.Source == sourceSimulate {
			t.Error("absent SSRF category should not produce a D cap")
		}
	}
}

func TestGradeCap_LimitationsExcluded(t *testing.T) {
	// A category where all non-limitation scenarios pass, but has a limitation.
	// Should NOT trigger 0% cap.
	sources := AssessSources{
		Simulate: &audit.SimulateResult{
			Scenarios: []audit.ScenarioResult{
				{Name: "test1", Category: "Evasion", Detected: true},
				{Name: "test2", Category: "Evasion", Detected: false, Limitation: true},
			},
		},
	}
	caps := computeGradeCaps(sources, false)
	for _, c := range caps {
		if c.Cap == assessGradeD && c.Source == sourceSimulate {
			t.Error("category with only limitation failures should not produce a D cap")
		}
	}
}

func TestGenerateFindings(t *testing.T) {
	sources := AssessSources{
		Simulate: &audit.SimulateResult{
			Scenarios: []audit.ScenarioResult{
				{Name: "AWS key leak", Category: "DLP Exfiltration", Detected: false},
				{Name: "Injection test", Category: "Prompt Injection", Detected: true},
				{Name: "Known limit", Category: "Evasion", Detected: false, Limitation: true},
			},
		},
		AuditScore: &audit.ScoreResult{
			Findings: []audit.ScoreFinding{
				{Severity: scoreSevCritical, Category: "DLP", Message: "No DLP patterns"},
				{Severity: scoreSevWarning, Category: "Response Scanning", Message: "Action is warn"},
			},
		},
		VerifyInstall: &diag.VerifyReport{
			Checks: []diag.VerifyReportCheck{
				{Name: "config_valid", Category: verifyCatScanning, Status: verifyStatusPass},
				{Name: "fetch_dlp", Category: verifyCatScanning, Status: verifyStatusFail, Detail: "DLP not triggered"},
				{Name: "no_direct_http", Category: verifyCatContainment, Status: verifyStatusFail, Detail: "egress open"},
			},
		},
		Discover: &AssessDiscoverReport{
			Servers: []AssessDiscoverServer{
				{MCPServer: discover.MCPServer{Client: "cursor", ServerName: "shell", Protection: discover.Unprotected, Risk: discover.RiskHigh}},
				{MCPServer: discover.MCPServer{Client: "vscode", ServerName: "safe", Protection: discover.ProtectedPipelock, Risk: discover.RiskLow}},
			},
		},
	}

	findings := generateFindings(sources)

	// Expected findings:
	// 1. sim: AWS key leak (high) -- "Known limit" skipped, "Injection test" detected
	// 2. audit: No DLP patterns (critical)
	// 3. audit: Action is warn (medium)
	// 4. verify: fetch_dlp (high)
	// 5. verify: no_direct_http (critical)
	// 6. discover: shell unprotected (high)
	wantCount := 6
	if len(findings) != wantCount {
		t.Fatalf("findings count = %d, want %d", len(findings), wantCount)
	}

	// Verify sorted: critical first, then high, then medium.
	// The first findings should be critical severity.
	if findings[0].Severity != assessSevCritical {
		t.Errorf("first finding severity = %q, want critical", findings[0].Severity)
	}

	// Verify limitation scenario was excluded.
	for _, f := range findings {
		if f.ID == "find-sim-known-limit" {
			t.Error("limitation scenario should not generate a finding")
		}
	}

	// Verify detected scenario was excluded.
	for _, f := range findings {
		if f.ID == "find-sim-injection-test" {
			t.Error("detected scenario should not generate a finding")
		}
	}

	// Verify protected server was excluded from discover findings.
	for _, f := range findings {
		if f.ID == "find-discover-vscode-safe" {
			t.Error("protected server should not generate a finding")
		}
	}
}

func TestSeverityMapping(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{scoreSevCritical, assessSevCritical},
		{scoreSevWarning, assessSevMedium},
		{scoreSevInfo, assessSevInfo},
		{"unknown", assessSevInfo},
		{"", assessSevInfo},
	}
	for _, tc := range cases {
		got := mapScoreFindingSeverity(tc.input)
		if got != tc.want {
			t.Errorf("mapScoreFindingSeverity(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestSynthesizeAssessment_WeightedAverage(t *testing.T) {
	manifest := AssessManifest{
		SchemaVersion: assessSchemaVersion,
		Version:       "2.0.0",
		RunID:         "test-run",
		StartedAt:     time.Now().UTC(),
		Status:        assessStatusCompleted,
	}
	sources := AssessSources{
		Simulate: &audit.SimulateResult{
			Total:      10,
			Passed:     9,
			Failed:     1,
			Percentage: 90, // A
		},
		AuditScore: &audit.ScoreResult{
			TotalScore: 80,
			MaxScore:   100,
			Percentage: 80, // B
			Categories: []audit.ScoreCategory{{Name: "DLP", Score: 80, MaxScore: 100}},
		},
		VerifyInstall: &diag.VerifyReport{
			Checks: []diag.VerifyReportCheck{
				{Name: "a", Category: verifyCatScanning, Status: verifyStatusPass},
				{Name: "b", Category: verifyCatScanning, Status: verifyStatusPass},
			},
			Summary: diag.VerifyReportSummary{Containment: verifyContainmentContained},
		},
		Discover: &AssessDiscoverReport{
			Servers: []AssessDiscoverServer{
				{MCPServer: discover.MCPServer{Client: "cc", ServerName: "a", Protection: discover.ProtectedPipelock, Risk: discover.RiskLow}},
			},
			Clients: []AssessDiscoverClient{},
		},
	}

	a := synthesizeAssessment(manifest, sources)

	// Weighted: detection=90*25 + config=80*25 + deploy=100*30 + mcp=100*20
	// = 2250 + 2000 + 3000 + 2000 = 9250 / 100 = 92
	if a.OverallScore != 92 {
		t.Errorf("OverallScore = %d, want 92", a.OverallScore)
	}
	if a.OverallGrade != assessGradeA {
		t.Errorf("OverallGrade = %q, want %q", a.OverallGrade, assessGradeA)
	}
	if a.SchemaVersion != assessSchemaVersion {
		t.Errorf("SchemaVersion = %q, want %q", a.SchemaVersion, assessSchemaVersion)
	}
	if len(a.Sections) != 4 {
		t.Errorf("Sections count = %d, want 4", len(a.Sections))
	}
	// Verify sections are sorted by ID.
	for i := 1; i < len(a.Sections); i++ {
		if a.Sections[i].ID < a.Sections[i-1].ID {
			t.Errorf("sections not sorted: %q before %q", a.Sections[i-1].ID, a.Sections[i].ID)
		}
	}
}

func TestSynthesizeAssessment_CapApplied(t *testing.T) {
	manifest := AssessManifest{
		SchemaVersion: assessSchemaVersion,
		Version:       "2.0.0",
		RunID:         "test-run",
		StartedAt:     time.Now().UTC(),
		Status:        assessStatusCompleted,
	}
	// All sections score 100 (A), but containment is exposed -> D cap.
	sources := AssessSources{
		Simulate: &audit.SimulateResult{
			Total:      10,
			Passed:     10,
			Percentage: 100,
		},
		AuditScore: &audit.ScoreResult{
			TotalScore: 100,
			MaxScore:   100,
			Percentage: 100,
			Categories: []audit.ScoreCategory{{Name: "All", Score: 100, MaxScore: 100}},
		},
		VerifyInstall: &diag.VerifyReport{
			Checks: []diag.VerifyReportCheck{
				{Name: "a", Category: verifyCatScanning, Status: verifyStatusPass},
				{Name: "no_direct_http", Category: verifyCatContainment, Status: verifyStatusFail},
			},
			Summary: diag.VerifyReportSummary{Containment: verifyContainmentExposed},
		},
		Discover: &AssessDiscoverReport{
			Servers: []AssessDiscoverServer{},
			Clients: []AssessDiscoverClient{},
		},
	}

	a := synthesizeAssessment(manifest, sources)

	// Raw score should be high, but grade capped.
	if a.OverallGrade != assessGradeD {
		t.Errorf("OverallGrade = %q, want %q (D cap from exposed containment)", a.OverallGrade, assessGradeD)
	}
	if a.GradeCap != assessGradeD {
		t.Errorf("GradeCap = %q, want %q", a.GradeCap, assessGradeD)
	}
	if len(a.CapReasons) == 0 {
		t.Error("expected cap reasons, got none")
	}
}

func TestSynthesizeAssessment_SkippedSectionsExcludedFromWeight(t *testing.T) {
	manifest := AssessManifest{
		SchemaVersion: assessSchemaVersion,
		Version:       "2.0.0",
		RunID:         "test-run",
		StartedAt:     time.Now().UTC(),
		Status:        assessStatusCompleted,
	}
	// Only simulate and audit present. Verify and discover are nil.
	sources := AssessSources{
		Simulate: &audit.SimulateResult{
			Total:      10,
			Passed:     10,
			Percentage: 100,
		},
		AuditScore: &audit.ScoreResult{
			TotalScore: 100,
			MaxScore:   100,
			Percentage: 100,
			Categories: []audit.ScoreCategory{{Name: "All", Score: 100, MaxScore: 100}},
		},
	}

	a := synthesizeAssessment(manifest, sources)

	// Both present sections score 100. Nil sections have MaxScore=0,
	// so their weight is excluded. Result should be 100.
	if a.OverallScore != 100 {
		t.Errorf("OverallScore = %d, want 100 (nil sections excluded)", a.OverallScore)
	}
}

func TestSynthesizeAssessment_AllNilSources(t *testing.T) {
	manifest := AssessManifest{
		SchemaVersion: assessSchemaVersion,
		Version:       "2.0.0",
		RunID:         "test-run",
		StartedAt:     time.Now().UTC(),
		Status:        assessStatusCompleted,
	}
	sources := AssessSources{}

	a := synthesizeAssessment(manifest, sources)

	if a.OverallScore != 0 {
		t.Errorf("all-nil OverallScore = %d, want 0", a.OverallScore)
	}
	if a.OverallGrade != assessGradeF {
		t.Errorf("all-nil OverallGrade = %q, want %q", a.OverallGrade, assessGradeF)
	}
}

func TestSynthesizeAssessment_CapNotAppliedWhenGradeAlreadyLow(t *testing.T) {
	manifest := AssessManifest{
		SchemaVersion: assessSchemaVersion,
		Version:       "2.0.0",
		RunID:         "test-run",
		StartedAt:     time.Now().UTC(),
		Status:        assessStatusCompleted,
		AllowPartial:  true, // B cap
	}
	// All sections score poorly -> F grade. B cap is above F, so no cap applied.
	sources := AssessSources{
		Simulate: &audit.SimulateResult{
			Total:      10,
			Passed:     2,
			Failed:     8,
			Percentage: 20,
		},
		AuditScore: &audit.ScoreResult{
			TotalScore: 20,
			MaxScore:   100,
			Percentage: 20,
			Categories: []audit.ScoreCategory{{Name: "All", Score: 20, MaxScore: 100}},
		},
	}

	a := synthesizeAssessment(manifest, sources)

	if a.OverallGrade != assessGradeF {
		t.Errorf("OverallGrade = %q, want %q", a.OverallGrade, assessGradeF)
	}
	// GradeCap should be empty because the cap (B) is better than the raw grade (F).
	if a.GradeCap != "" {
		t.Errorf("GradeCap = %q, want empty (B cap above F grade)", a.GradeCap)
	}
}

func TestSlugify(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"Hello World", "hello-world"},
		{"DLP Exfiltration", "dlp-exfiltration"},
		{"cursor-shell", "cursor-shell"},
		{"SSRF", "ssrf"},
		{"a  b  c", "a-b-c"},
		{"already-clean", "already-clean"},
		{"Special!@#Chars", "special-chars"},
		{"  leading trailing  ", "leading-trailing"},
		{"MCP Tool Scanning", "mcp-tool-scanning"},
	}
	for _, tc := range cases {
		got := slugify(tc.input)
		if got != tc.want {
			t.Errorf("slugify(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestGradeOrder(t *testing.T) {
	cases := []struct {
		grade string
		want  int
	}{
		{assessGradeA, 0},
		{assessGradeB, 1},
		{assessGradeC, 2},
		{assessGradeD, 3},
		{assessGradeF, 4},
		{"unknown", 5},
	}
	for _, tc := range cases {
		got := gradeOrder(tc.grade)
		if got != tc.want {
			t.Errorf("gradeOrder(%q) = %d, want %d", tc.grade, got, tc.want)
		}
	}

	// Verify ordering: worse grades have higher order.
	if gradeOrder(assessGradeA) >= gradeOrder(assessGradeB) {
		t.Error("A should have lower order than B")
	}
	if gradeOrder(assessGradeD) >= gradeOrder(assessGradeF) {
		t.Error("D should have lower order than F")
	}
}

func TestGenerateFindings_EvidenceIsValidJSON(t *testing.T) {
	sources := AssessSources{
		Simulate: &audit.SimulateResult{
			Scenarios: []audit.ScenarioResult{
				{Name: "test", Category: "DLP", Detected: false},
			},
		},
	}
	findings := generateFindings(sources)
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	for _, f := range findings {
		if f.Evidence != nil {
			if !json.Valid(f.Evidence) {
				t.Errorf("finding %q has invalid JSON evidence: %s", f.ID, string(f.Evidence))
			}
		}
	}
}

func TestGenerateFindings_ContainmentSeverityIsCritical(t *testing.T) {
	sources := AssessSources{
		VerifyInstall: &diag.VerifyReport{
			Checks: []diag.VerifyReportCheck{
				{Name: "no_direct_http", Category: verifyCatContainment, Status: verifyStatusFail, Detail: "open"},
			},
		},
	}
	findings := generateFindings(sources)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != assessSevCritical {
		t.Errorf("containment failure severity = %q, want %q", findings[0].Severity, assessSevCritical)
	}
}

func TestGenerateFindings_ScanningFailSeverityIsHigh(t *testing.T) {
	sources := AssessSources{
		VerifyInstall: &diag.VerifyReport{
			Checks: []diag.VerifyReportCheck{
				{Name: "fetch_dlp", Category: verifyCatScanning, Status: verifyStatusFail, Detail: "not triggered"},
			},
		},
	}
	findings := generateFindings(sources)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != assessSevHigh {
		t.Errorf("scanning failure severity = %q, want %q", findings[0].Severity, assessSevHigh)
	}
}

func TestGenerateFindings_DiscoverHighRiskSeverity(t *testing.T) {
	sources := AssessSources{
		Discover: &AssessDiscoverReport{
			Servers: []AssessDiscoverServer{
				{MCPServer: discover.MCPServer{Client: "cc", ServerName: "exec", Protection: discover.Unprotected, Risk: discover.RiskHigh}},
				{MCPServer: discover.MCPServer{Client: "cc", ServerName: "safe", Protection: discover.Unprotected, Risk: discover.RiskLow}},
			},
		},
	}
	findings := generateFindings(sources)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	// First should be high (sorted by severity).
	if findings[0].Severity != assessSevHigh {
		t.Errorf("high-risk server severity = %q, want %q", findings[0].Severity, assessSevHigh)
	}
	if findings[1].Severity != assessSevMedium {
		t.Errorf("low-risk server severity = %q, want %q", findings[1].Severity, assessSevMedium)
	}
}
