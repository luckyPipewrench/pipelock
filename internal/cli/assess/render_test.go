// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package assess

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/cli/audit"
	"github.com/luckyPipewrench/pipelock/internal/discover"
)

const (
	testRunID      = "test-run-abc123"
	testVersion    = "2.0.0"
	testBuildSHA   = "deadbeef"
	testSectionDet = "Detection Coverage"
	testSectionCfg = "Config Posture"
)

func minimalAssessment(grade string, score int) *Assessment {
	now := time.Now().UTC()
	manifest := AssessManifest{
		RunID:           testRunID,
		Version:         testVersion,
		BuildSHA:        testBuildSHA,
		SchemaVersion:   assessSchemaVersion,
		ScoringVersion:  assessScoringVersion,
		RendererVersion: assessRendererVersion,
		Status:          assessStatusFinalized,
		FinalizedAt:     &now,
	}
	return &Assessment{
		SchemaVersion: assessSchemaVersion,
		Manifest:      manifest,
		OverallGrade:  grade,
		OverallScore:  score,
		Sections: []AssessmentSection{
			{ID: sectionDetectionCoverage, Name: testSectionDet, Score: 90, MaxScore: 100, Grade: assessGradeA, Detail: "18/20 detected"},
			{ID: sectionConfigPosture, Name: testSectionCfg, Score: 75, MaxScore: 100, Grade: assessGradeC, Detail: "Config detail"},
		},
		Findings: []Finding{
			{
				ID:          "find-001",
				Severity:    assessSevHigh,
				Category:    "DLP",
				Source:      "simulate",
				Title:       "Secret exfiltration not blocked",
				Detail:      "AWS key transmitted in plain text",
				Remediation: "Enable DLP pattern matching",
			},
		},
	}
}

func minimalSummary(grade string, score int) *Summary {
	now := time.Now().UTC()
	manifest := AssessManifest{
		RunID:           testRunID,
		Version:         testVersion,
		BuildSHA:        testBuildSHA,
		SchemaVersion:   assessSchemaVersion,
		ScoringVersion:  assessScoringVersion,
		RendererVersion: assessRendererVersion,
		Status:          assessStatusFinalized,
		FinalizedAt:     &now,
	}
	return &Summary{
		SchemaVersion: assessSchemaVersion,
		Manifest:      manifest,
		OverallGrade:  grade,
		OverallScore:  score,
		Sections: []AssessmentSection{
			{ID: sectionDetectionCoverage, Name: testSectionDet, Score: 85, MaxScore: 100, Grade: assessGradeB},
			{ID: sectionConfigPosture, Name: testSectionCfg, Score: 70, MaxScore: 100, Grade: assessGradeC},
		},
		TopFindings: []SummaryFinding{
			{ID: "find-001", Severity: assessSevHigh, Category: "DLP", Source: "simulate", Title: "Missed exfiltration"},
		},
		DetectionPct: 85,
		Signed:       false,
	}
}

func TestRenderAssessmentHTML(t *testing.T) {
	a := minimalAssessment(assessGradeA, 95)

	var buf bytes.Buffer
	if err := renderAssessmentHTML(&buf, a); err != nil {
		t.Fatalf("renderAssessmentHTML: %v", err)
	}

	html := buf.String()

	// Must be valid HTML.
	if !strings.Contains(html, "<html") {
		t.Error("output should contain <html")
	}
	if !strings.Contains(html, "</html>") {
		t.Error("output should contain </html>")
	}

	// Must contain report title.
	if !strings.Contains(html, "Pipelock Security Assessment") {
		t.Error("output should contain report title")
	}

	// Must contain grade badge (letter only) and score line.
	if !strings.Contains(html, ">A</div>") {
		t.Error("output should contain grade badge letter")
	}
	if !strings.Contains(html, "Scored 95/100") {
		t.Error("output should contain topline story with score")
	}

	// Must contain run ID.
	if !strings.Contains(html, testRunID) {
		t.Error("output should contain run ID")
	}

	// Must contain section names.
	if !strings.Contains(html, testSectionDet) {
		t.Errorf("output should contain section %q", testSectionDet)
	}
	if !strings.Contains(html, testSectionCfg) {
		t.Errorf("output should contain section %q", testSectionCfg)
	}

	// Must contain finding title.
	if !strings.Contains(html, "Secret exfiltration not blocked") {
		t.Error("output should contain finding title")
	}

	// Must NOT contain "Informational only" (that's summary-only).
	if strings.Contains(html, "Informational only") {
		t.Error("full assessment should not contain 'Informational only'")
	}
}

func TestRenderSummaryHTML(t *testing.T) {
	s := minimalSummary(assessGradeB, 82)

	var buf bytes.Buffer
	if err := renderSummaryHTML(&buf, s); err != nil {
		t.Fatalf("renderSummaryHTML: %v", err)
	}

	html := buf.String()

	// Must be valid HTML.
	if !strings.Contains(html, "<html") {
		t.Error("output should contain <html")
	}

	// Must contain summary title.
	if !strings.Contains(html, "Pipelock Security Summary") {
		t.Error("output should contain summary title")
	}

	// Must contain "Informational only".
	if !strings.Contains(html, "Informational only") {
		t.Error("summary should contain 'Informational only'")
	}

	// Must contain "Unsigned".
	if !strings.Contains(html, "Unsigned") {
		t.Error("summary should contain 'Unsigned'")
	}

	// Must contain "Not audit-grade".
	if !strings.Contains(html, "Not audit-grade") {
		t.Error("summary should contain 'Not audit-grade'")
	}

	// Must NOT contain remediation or evidence columns.
	if strings.Contains(html, "remediation") {
		t.Error("summary should not contain remediation field")
	}
	if strings.Contains(html, "evidence") {
		t.Error("summary should not contain evidence field")
	}

	// Must contain finding title.
	if !strings.Contains(html, "Missed exfiltration") {
		t.Error("summary should contain top finding title")
	}
}

func TestRenderAssessmentHTML_AllGrades(t *testing.T) {
	cases := []struct {
		grade     string
		wantColor string
	}{
		{assessGradeA, "#22c55e"},
		{assessGradeB, "#3b82f6"},
		{assessGradeC, "#eab308"},
		{assessGradeD, "#f97316"},
		{assessGradeF, "#ef4444"},
	}

	for _, tc := range cases {
		t.Run("grade_"+tc.grade, func(t *testing.T) {
			a := minimalAssessment(tc.grade, 50)
			var buf bytes.Buffer
			if err := renderAssessmentHTML(&buf, a); err != nil {
				t.Fatalf("renderAssessmentHTML grade %q: %v", tc.grade, err)
			}
			html := buf.String()
			if !strings.Contains(html, tc.wantColor) {
				t.Errorf("grade %q: expected color %q in output", tc.grade, tc.wantColor)
			}
		})
	}
}

func TestGradeColor(t *testing.T) {
	cases := []struct {
		grade string
		want  string
	}{
		{assessGradeA, "#22c55e"},
		{assessGradeB, "#3b82f6"},
		{assessGradeC, "#eab308"},
		{assessGradeD, "#f97316"},
		{assessGradeF, "#ef4444"},
		{"", "#ef4444"}, // unknown defaults to F color
	}

	for _, tc := range cases {
		t.Run("grade_"+tc.grade, func(t *testing.T) {
			got := gradeColor(tc.grade)
			if got != tc.want {
				t.Errorf("gradeColor(%q) = %q, want %q", tc.grade, got, tc.want)
			}
		})
	}
}

func TestSeverityColor(t *testing.T) {
	cases := []struct {
		sev  string
		want string
	}{
		{assessSevCritical, "#ef4444"},
		{assessSevHigh, "#f97316"},
		{assessSevMedium, "#eab308"},
		{assessSevLow, "#3b82f6"},
		{assessSevInfo, "#6b7280"},
		{"", "#6b7280"}, // unknown defaults to gray
	}

	for _, tc := range cases {
		t.Run("sev_"+tc.sev, func(t *testing.T) {
			got := severityColor(tc.sev)
			if got != tc.want {
				t.Errorf("severityColor(%q) = %q, want %q", tc.sev, got, tc.want)
			}
		})
	}
}

func TestRenderAssessmentHTML_WithCapWarning(t *testing.T) {
	a := minimalAssessment(assessGradeC, 72)
	a.GradeCap = assessGradeC
	a.CapReasons = []CapReason{
		{Cap: assessGradeC, Reason: "Unprotected servers found", Source: "discover"},
	}

	var buf bytes.Buffer
	if err := renderAssessmentHTML(&buf, a); err != nil {
		t.Fatalf("renderAssessmentHTML with cap: %v", err)
	}

	html := buf.String()
	// Cap info is now in the topline story, not a separate warning box.
	if !strings.Contains(html, "capped at") {
		t.Error("output should contain cap info in topline story")
	}
	if !strings.Contains(html, "Unprotected servers found") {
		t.Error("output should contain cap reason in topline story")
	}
}

func TestRenderAssessmentHTML_EmptyFindings(t *testing.T) {
	a := minimalAssessment(assessGradeA, 100)
	a.Findings = nil

	var buf bytes.Buffer
	if err := renderAssessmentHTML(&buf, a); err != nil {
		t.Fatalf("renderAssessmentHTML with no findings: %v", err)
	}

	html := buf.String()
	if !strings.Contains(html, "No findings recorded") {
		t.Error("output should indicate no findings when slice is empty")
	}
}

func TestRenderSummaryHTML_EmptyTopFindings(t *testing.T) {
	s := minimalSummary(assessGradeA, 100)
	s.TopFindings = nil

	var buf bytes.Buffer
	if err := renderSummaryHTML(&buf, s); err != nil {
		t.Fatalf("renderSummaryHTML with no findings: %v", err)
	}

	html := buf.String()
	if !strings.Contains(html, "No findings recorded") {
		t.Error("summary should indicate no findings when slice is empty")
	}
}

func TestSeverityBadge(t *testing.T) {
	cases := []struct {
		sev  string
		want string
	}{
		{assessSevCritical, "CRITICAL"},
		{assessSevHigh, "HIGH"},
		{assessSevMedium, "MEDIUM"},
		{assessSevLow, "LOW"},
		{assessSevInfo, "INFO"},
	}

	for _, tc := range cases {
		t.Run(tc.sev, func(t *testing.T) {
			got := severityBadge(tc.sev)
			if got != tc.want {
				t.Errorf("severityBadge(%q) = %q, want %q", tc.sev, got, tc.want)
			}
		})
	}
}

func TestExecSummary(t *testing.T) {
	const (
		testPlatform   = "linux/amd64"
		testCapGrade   = assessGradeC
		testNoCapGrade = assessGradeA
		testNoCapScore = 95
		testCapScore   = 72
		testSimPassed  = 18
		testSimTotal   = 20
		testSimLimits  = 0
		testSimPct     = 90
		testDiscTotal  = 3
		testDiscProt   = 2
		testDiscUnprot = 1
	)

	baseAssessment := func() *Assessment {
		a := minimalAssessment(testNoCapGrade, testNoCapScore)
		a.Manifest.Platform = testPlatform
		return a
	}

	t.Run("nil sources", func(t *testing.T) {
		a := baseAssessment()
		a.Sources = AssessSources{}
		got := execSummary(a)
		if !strings.Contains(got, "Overall security posture") {
			t.Errorf("execSummary with nil sources: missing posture line, got %q", got)
		}
		if strings.Contains(got, "scenarios") {
			t.Errorf("execSummary with nil sources: should not mention scenarios, got %q", got)
		}
		if strings.Contains(got, "MCP servers") {
			t.Errorf("execSummary with nil sources: should not mention MCP servers, got %q", got)
		}
	})

	t.Run("simulate only", func(t *testing.T) {
		a := baseAssessment()
		a.Sources = AssessSources{
			Simulate: &audit.SimulateResult{
				Total:       testSimTotal,
				Passed:      testSimPassed,
				KnownLimits: testSimLimits,
				Percentage:  testSimPct,
			},
		}
		got := execSummary(a)
		if !strings.Contains(got, "scenarios") {
			t.Errorf("execSummary simulate only: missing scenarios, got %q", got)
		}
		if strings.Contains(got, "MCP servers") {
			t.Errorf("execSummary simulate only: should not mention MCP servers, got %q", got)
		}
	})

	t.Run("discover only", func(t *testing.T) {
		a := baseAssessment()
		a.Sources = AssessSources{
			Discover: &AssessDiscoverReport{
				Summary: AssessDiscoverSummary{
					Summary: discoverSummary(testDiscTotal, testDiscProt, 0, testDiscUnprot),
				},
			},
		}
		got := execSummary(a)
		if !strings.Contains(got, "MCP servers are protected") {
			t.Errorf("execSummary discover only: missing MCP protection line, got %q", got)
		}
		if strings.Contains(got, "scenarios") {
			t.Errorf("execSummary discover only: should not mention scenarios, got %q", got)
		}
	})

	t.Run("with grade cap", func(t *testing.T) {
		a := baseAssessment()
		a.OverallGrade = testCapGrade
		a.OverallScore = testCapScore
		a.GradeCap = testCapGrade
		got := execSummary(a)
		if !strings.Contains(got, "capped at grade") {
			t.Errorf("execSummary with cap: missing cap phrase, got %q", got)
		}
		if strings.Contains(got, "Overall security posture") {
			t.Errorf("execSummary with cap: should not show posture line, got %q", got)
		}
	})

	t.Run("without grade cap", func(t *testing.T) {
		a := baseAssessment()
		got := execSummary(a)
		if !strings.Contains(got, "Overall security posture") {
			t.Errorf("execSummary without cap: missing posture line, got %q", got)
		}
		if strings.Contains(got, "capped") {
			t.Errorf("execSummary without cap: should not mention cap, got %q", got)
		}
	})
}

// discoverSummary is a helper to build discover.Summary values inline.
func discoverSummary(total, pipelock, other, unprotected int) discover.Summary {
	return discover.Summary{
		TotalServers:      total,
		ProtectedPipelock: pipelock,
		ProtectedOther:    other,
		Unprotected:       unprotected,
	}
}

func TestSummaryTopline(t *testing.T) {
	t.Run("capped grade", func(t *testing.T) {
		s := minimalSummary(assessGradeC, 72)
		s.GradeCap = assessGradeC
		got := summaryTopline(s)
		if !strings.Contains(got, "capped at") {
			t.Errorf("summaryTopline capped: missing 'capped at', got %q", got)
		}
		if !strings.Contains(got, "critical exposure") {
			t.Errorf("summaryTopline capped: missing 'critical exposure', got %q", got)
		}
	})

	t.Run("uncapped grade", func(t *testing.T) {
		s := minimalSummary(assessGradeA, 95)
		got := summaryTopline(s)
		if !strings.Contains(got, "Overall security posture") {
			t.Errorf("summaryTopline uncapped: missing posture line, got %q", got)
		}
		if strings.Contains(got, "capped") {
			t.Errorf("summaryTopline uncapped: should not mention cap, got %q", got)
		}
	})
}

func TestServerStatColor(t *testing.T) {
	cases := []struct {
		name      string
		protected int
		total     int
		want      string
	}{
		{"all protected", 5, 5, colorGreen},
		{"zero of zero", 0, 0, colorGreen}, // protected == total (both 0)
		{"some unprotected", 3, 5, colorRed},
		{"none protected", 0, 5, colorRed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := serverStatColor(tc.protected, tc.total)
			if got != tc.want {
				t.Errorf("serverStatColor(%d, %d) = %q, want %q", tc.protected, tc.total, got, tc.want)
			}
		})
	}
}

func TestFormatEvidence(t *testing.T) {
	t.Run("nil returns empty", func(t *testing.T) {
		got := formatEvidence(nil)
		if got != "" {
			t.Errorf("formatEvidence(nil) = %q, want empty", got)
		}
	})

	t.Run("valid JSON is indented", func(t *testing.T) {
		raw := json.RawMessage(`{"key":"value","n":1}`)
		got := formatEvidence(raw)
		if !strings.Contains(got, "\n") {
			t.Errorf("formatEvidence(valid JSON): expected indented output with newlines, got %q", got)
		}
		if !strings.Contains(got, `"key"`) {
			t.Errorf("formatEvidence(valid JSON): expected key in output, got %q", got)
		}
	})

	t.Run("invalid JSON shows placeholder", func(t *testing.T) {
		raw := json.RawMessage(`not-json{`)
		got := formatEvidence(raw)
		if got != "[invalid evidence payload]" {
			t.Errorf("formatEvidence(invalid JSON) = %q, want placeholder", got)
		}
	})
}

func TestProtectionColor(t *testing.T) {
	cases := []struct {
		status string
		want   string
	}{
		{"protected_pipelock", colorGreen},
		{"protected_other", colorBlue},
		{"unprotected", colorRed},
		{"unknown", colorGray},
		{"", colorGray},
	}
	for _, tc := range cases {
		t.Run(tc.status, func(t *testing.T) {
			got := protectionColor(tc.status)
			if got != tc.want {
				t.Errorf("protectionColor(%q) = %q, want %q", tc.status, got, tc.want)
			}
		})
	}
}

func TestProtectionLabel(t *testing.T) {
	cases := []struct {
		status string
		want   string
	}{
		{"protected_pipelock", "PIPELOCK"},
		{"protected_other", "OTHER"},
		{"unprotected", "UNPROTECTED"},
		{"unknown_status", "UNKNOWN"},
		{"", "UNKNOWN"},
	}
	for _, tc := range cases {
		t.Run(tc.status, func(t *testing.T) {
			got := protectionLabel(tc.status)
			if got != tc.want {
				t.Errorf("protectionLabel(%q) = %q, want %q", tc.status, got, tc.want)
			}
		})
	}
}

func TestScenarioResult(t *testing.T) {
	cases := []struct {
		name       string
		detected   bool
		limitation bool
		want       string
	}{
		{"limitation overrides detected=true", true, true, "KNOWN LIMITATION"},
		{"limitation overrides detected=false", false, true, "KNOWN LIMITATION"},
		{"detected=true no limitation", true, false, "DETECTED"},
		{"detected=false no limitation", false, false, "MISSED"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := scenarioResult(tc.detected, tc.limitation)
			if got != tc.want {
				t.Errorf("scenarioResult(%v, %v) = %q, want %q", tc.detected, tc.limitation, got, tc.want)
			}
		})
	}
}

func TestScenarioColor(t *testing.T) {
	cases := []struct {
		name       string
		detected   bool
		limitation bool
		want       string
	}{
		{"limitation", false, true, colorGray},
		{"detected", true, false, colorGreen},
		{"missed", false, false, colorRed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := scenarioColor(tc.detected, tc.limitation)
			if got != tc.want {
				t.Errorf("scenarioColor(%v, %v) = %q, want %q", tc.detected, tc.limitation, got, tc.want)
			}
		})
	}
}

func TestScorePercent(t *testing.T) {
	cases := []struct {
		name     string
		score    int
		maxScore int
		want     int
	}{
		{"normal 90/100", 90, 100, 90},
		{"partial 3/4", 3, 4, 75},
		{"zero maxScore returns 0", 50, 0, 0},
		{"zero score", 0, 100, 0},
		{"perfect", 100, 100, 100},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := scorePercent(tc.score, tc.maxScore)
			if got != tc.want {
				t.Errorf("scorePercent(%d, %d) = %d, want %d", tc.score, tc.maxScore, got, tc.want)
			}
		})
	}
}

func TestAuditBarColor(t *testing.T) {
	cases := []struct {
		name     string
		score    int
		maxScore int
		want     string
	}{
		{"100% green", 100, 100, colorGreen},
		{"90% green", 90, 100, colorGreen},
		{"80% yellow", 80, 100, colorYellow},
		{"70% yellow", 70, 100, colorYellow},
		{"50% orange", 50, 100, colorOrange},
		{"49% red", 49, 100, colorRed},
		{"0% red", 0, 100, colorRed},
		{"zero maxScore gray", 0, 0, colorGray},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := auditBarColor(tc.score, tc.maxScore)
			if got != tc.want {
				t.Errorf("auditBarColor(%d, %d) = %q, want %q", tc.score, tc.maxScore, got, tc.want)
			}
		})
	}
}

func TestFormatEvidence_JSONNull(t *testing.T) {
	// json.RawMessage("null") is non-nil in Go but should be treated as empty.
	raw := json.RawMessage("null")
	got := formatEvidence(raw)
	if got != "" {
		t.Errorf("formatEvidence(json null) = %q, want empty", got)
	}
}

func TestEffectiveCapReason(t *testing.T) {
	t.Run("matches effective cap", func(t *testing.T) {
		reasons := []CapReason{
			{Cap: assessGradeC, Reason: "containment failed", Source: sourceVerifyInstall},
			{Cap: assessGradeD, Reason: "0% detection in DLP", Source: sourceSimulate},
		}
		// GradeCap is D (the worst), so effectiveCapReason should return the D reason.
		got := effectiveCapReason(assessGradeD, reasons)
		if got != "0% detection in DLP" {
			t.Errorf("effectiveCapReason(D) = %q, want '0%% detection in DLP'", got)
		}
	})

	t.Run("falls back to first when no match", func(t *testing.T) {
		reasons := []CapReason{
			{Cap: assessGradeC, Reason: "containment failed", Source: sourceVerifyInstall},
		}
		got := effectiveCapReason(assessGradeB, reasons)
		if got != "containment failed" {
			t.Errorf("effectiveCapReason(B, no match) = %q, want fallback 'containment failed'", got)
		}
	})
}

func TestToplineStory_EffectiveCapReason(t *testing.T) {
	a := minimalAssessment(assessGradeD, 85)
	a.GradeCap = assessGradeD
	a.CapReasons = []CapReason{
		{Cap: assessGradeC, Reason: "containment failed", Source: sourceVerifyInstall},
		{Cap: assessGradeD, Reason: "DLP Exfiltration has 0% detection", Source: sourceSimulate},
	}

	got := toplineStory(a)
	if !strings.Contains(got, "DLP Exfiltration has 0% detection") {
		t.Errorf("toplineStory should use effective cap D reason, got %q", got)
	}
	if strings.Contains(got, "containment failed") {
		t.Error("toplineStory should not use non-effective cap C reason")
	}
}

func TestDiscoverCausedCap(t *testing.T) {
	fn := assessFuncMap()["discoverCausedCap"].(func(*Assessment) bool)

	t.Run("discover is effective cap", func(t *testing.T) {
		a := minimalAssessment(assessGradeC, 85)
		a.GradeCap = assessGradeC
		a.CapReasons = []CapReason{
			{Cap: assessGradeC, Reason: "unprotected server", Source: sourceDiscover},
		}
		if !fn(a) {
			t.Error("discoverCausedCap should return true when discover matches effective cap")
		}
	})

	t.Run("discover not effective cap", func(t *testing.T) {
		a := minimalAssessment(assessGradeD, 85)
		a.GradeCap = assessGradeD
		a.CapReasons = []CapReason{
			{Cap: assessGradeC, Reason: "unprotected server", Source: sourceDiscover},
			{Cap: assessGradeD, Reason: "0% detection", Source: sourceSimulate},
		}
		if fn(a) {
			t.Error("discoverCausedCap should return false when simulate caused the effective cap")
		}
	})

	t.Run("no cap", func(t *testing.T) {
		a := minimalAssessment(assessGradeA, 95)
		if fn(a) {
			t.Error("discoverCausedCap should return false when no cap")
		}
	})
}

func TestCheckStatusColor(t *testing.T) {
	cases := []struct {
		status string
		want   string
	}{
		{"pass", colorGreen},
		{"fail", colorRed},
		{"warn", colorGray},
		{"", colorGray},
	}
	for _, tc := range cases {
		t.Run(tc.status, func(t *testing.T) {
			got := checkStatusColor(tc.status)
			if got != tc.want {
				t.Errorf("checkStatusColor(%q) = %q, want %q", tc.status, got, tc.want)
			}
		})
	}
}
