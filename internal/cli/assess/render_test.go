// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package assess

import (
	"bytes"
	"strings"
	"testing"
	"time"
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
