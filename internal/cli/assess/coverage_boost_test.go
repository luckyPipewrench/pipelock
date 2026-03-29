// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package assess

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cli/audit"
	"github.com/luckyPipewrench/pipelock/internal/discover"
	"github.com/luckyPipewrench/pipelock/internal/report/attestation"
	"github.com/luckyPipewrench/pipelock/internal/report/compliance"
)

// ---------- writeManifest ----------

func TestWriteManifest_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")

	m := &AssessManifest{
		SchemaVersion: assessSchemaVersion,
		RunID:         "test-manifest-roundtrip",
		Status:        assessStatusInitialized,
		Version:       testVersion,
	}

	if err := writeManifest(path, m); err != nil {
		t.Fatalf("writeManifest: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("reading manifest: %v", err)
	}

	var got AssessManifest
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("parsing manifest: %v", err)
	}

	if got.RunID != "test-manifest-roundtrip" {
		t.Errorf("RunID = %q, want %q", got.RunID, "test-manifest-roundtrip")
	}
	if got.Status != assessStatusInitialized {
		t.Errorf("Status = %q, want %q", got.Status, assessStatusInitialized)
	}
}

func TestWriteManifest_BadPath(t *testing.T) {
	err := writeManifest("/nonexistent/dir/manifest.json", &AssessManifest{})
	if err == nil {
		t.Error("expected error writing to bad path")
	}
}

// ---------- writeSummaryJSON / writeSummaryHTML ----------

func TestWriteSummaryJSON_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "summary.json")

	s := minimalSummary(assessGradeA, 95)
	if err := writeSummaryJSON(path, s); err != nil {
		t.Fatalf("writeSummaryJSON: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("reading: %v", err)
	}

	var got Summary
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("parsing: %v", err)
	}

	if got.OverallGrade != assessGradeA {
		t.Errorf("OverallGrade = %q, want A", got.OverallGrade)
	}
}

func TestWriteSummaryJSON_BadPath(t *testing.T) {
	s := minimalSummary(assessGradeA, 95)
	err := writeSummaryJSON("/nonexistent/dir/summary.json", s)
	if err == nil {
		t.Error("expected error writing to bad path")
	}
}

func TestWriteSummaryHTML_Produces_HTML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "summary.html")

	s := minimalSummary(assessGradeB, 85)
	if err := writeSummaryHTML(path, s); err != nil {
		t.Fatalf("writeSummaryHTML: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("reading: %v", err)
	}

	if !strings.Contains(string(data), "<html") {
		t.Error("expected HTML content")
	}
}

func TestWriteSummaryHTML_BadPath(t *testing.T) {
	s := minimalSummary(assessGradeA, 95)
	err := writeSummaryHTML("/nonexistent/dir/summary.html", s)
	if err == nil {
		t.Error("expected error writing to bad path")
	}
}

// ---------- writeAssessmentJSON / writeAssessmentHTML ----------

func TestWriteAssessmentJSON_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "assessment.json")

	a := minimalAssessment(assessGradeB, 85)
	if err := writeAssessmentJSON(path, a); err != nil {
		t.Fatalf("writeAssessmentJSON: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("reading: %v", err)
	}

	var got Assessment
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("parsing: %v", err)
	}

	if got.OverallGrade != assessGradeB {
		t.Errorf("OverallGrade = %q, want B", got.OverallGrade)
	}
}

func TestWriteAssessmentJSON_BadPath(t *testing.T) {
	a := minimalAssessment(assessGradeA, 95)
	err := writeAssessmentJSON("/nonexistent/dir/assessment.json", a)
	if err == nil {
		t.Error("expected error writing to bad path")
	}
}

func TestWriteAssessmentHTML_Produces_HTML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "assessment.html")

	a := minimalAssessment(assessGradeA, 95)
	if err := writeAssessmentHTML(path, a); err != nil {
		t.Fatalf("writeAssessmentHTML: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("reading: %v", err)
	}

	if !strings.Contains(string(data), "<html") {
		t.Error("expected HTML content")
	}
}

func TestWriteAssessmentHTML_BadPath(t *testing.T) {
	a := minimalAssessment(assessGradeA, 95)
	err := writeAssessmentHTML("/nonexistent/dir/assessment.html", a)
	if err == nil {
		t.Error("expected error writing to bad path")
	}
}

// ---------- hashFile ----------

func TestHashFile_ValidFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	if err := os.WriteFile(path, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := hashFile(path)
	if err != nil {
		t.Fatalf("hashFile: %v", err)
	}

	// SHA-256 of "hello" is well-known.
	want := "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if got != want {
		t.Errorf("hashFile = %q, want %q", got, want)
	}
}

func TestHashFile_MissingFile(t *testing.T) {
	_, err := hashFile("/nonexistent/file.txt")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

// ---------- createTarGz ----------

func TestCreateTarGz_RoundTrip(t *testing.T) {
	// Create source directory with files.
	srcDir := filepath.Join(t.TempDir(), "source")
	if err := os.MkdirAll(srcDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "file1.txt"), []byte("content1"), 0o600); err != nil {
		t.Fatal(err)
	}

	subDir := filepath.Join(srcDir, "sub")
	if err := os.MkdirAll(subDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subDir, "file2.txt"), []byte("content2"), 0o600); err != nil {
		t.Fatal(err)
	}

	archivePath := filepath.Join(t.TempDir(), "archive.tar.gz")
	if err := createTarGz(archivePath, srcDir); err != nil {
		t.Fatalf("createTarGz: %v", err)
	}

	// Verify archive exists and is not empty.
	info, err := os.Stat(archivePath)
	if err != nil {
		t.Fatalf("stat archive: %v", err)
	}
	if info.Size() == 0 {
		t.Error("archive is empty")
	}
}

func TestCreateTarGz_BadArchivePath(t *testing.T) {
	srcDir := t.TempDir()
	err := createTarGz("/nonexistent/dir/archive.tar.gz", srcDir)
	if err == nil {
		t.Error("expected error for bad archive path")
	}
}

// ---------- sortedArtifactKeys ----------

func TestSortedArtifactKeys(t *testing.T) {
	m := map[string]string{
		"c.json": "hash3",
		"a.json": "hash1",
		"b.json": "hash2",
	}
	keys := sortedArtifactKeys(m)
	if len(keys) != 3 {
		t.Fatalf("expected 3 keys, got %d", len(keys))
	}
	if keys[0] != "a.json" || keys[1] != "b.json" || keys[2] != "c.json" {
		t.Errorf("expected [a.json b.json c.json], got %v", keys)
	}
}

func TestSortedArtifactKeys_Empty(t *testing.T) {
	keys := sortedArtifactKeys(nil)
	if len(keys) != 0 {
		t.Errorf("expected 0 keys, got %d", len(keys))
	}
}

// ---------- splitJSONLines ----------

func TestSplitJSONLines(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  int
	}{
		{"empty", "", 0},
		{"single line no newline", `{"a":1}`, 1},
		{"single line with newline", "{\"a\":1}\n", 1},
		{"two lines", "{\"a\":1}\n{\"b\":2}\n", 2},
		{"trailing empty lines", "{\"a\":1}\n\n\n", 1},
		{"mixed empty lines", "{\"a\":1}\n\n{\"b\":2}\n", 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lines := splitJSONLines([]byte(tc.input))
			if len(lines) != tc.want {
				t.Errorf("splitJSONLines(%q) = %d lines, want %d", tc.input, len(lines), tc.want)
			}
		})
	}
}

// ---------- reconstructSimulateResult ----------

func TestReconstructSimulateResult_Empty(t *testing.T) {
	result := reconstructSimulateResult(nil)
	if result != nil {
		t.Error("expected nil for empty scenarios")
	}
}

func TestReconstructSimulateResult_MixedScenarios(t *testing.T) {
	scenarios := []audit.ScenarioResult{
		{Name: "DLP Basic", Category: "DLP", Detected: true},
		{Name: "DLP Advanced", Category: "DLP", Detected: false},
		{Name: "Known Limit", Category: "Injection", Detected: false, Limitation: true},
		{Name: "Injection Basic", Category: "Injection", Detected: true},
	}

	result := reconstructSimulateResult(scenarios)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Total != 4 {
		t.Errorf("Total = %d, want 4", result.Total)
	}
	if result.Passed != 2 {
		t.Errorf("Passed = %d, want 2", result.Passed)
	}
	if result.Failed != 1 {
		t.Errorf("Failed = %d, want 1", result.Failed)
	}
	if result.KnownLimits != 1 {
		t.Errorf("KnownLimits = %d, want 1", result.KnownLimits)
	}
	// Applicable = 4 - 1 = 3. Passed = 2. Pct = (2*100)/3 = 66.
	if result.Percentage != 66 {
		t.Errorf("Percentage = %d, want 66", result.Percentage)
	}
	if result.Grade != assessGradeD {
		t.Errorf("Grade = %q, want D", result.Grade)
	}
}

func TestReconstructSimulateResult_AllLimitations(t *testing.T) {
	scenarios := []audit.ScenarioResult{
		{Name: "S1", Limitation: true},
		{Name: "S2", Limitation: true},
	}
	result := reconstructSimulateResult(scenarios)
	if result == nil {
		t.Fatal("expected non-nil")
	}
	// All limitations: applicable = 0, pct = 0.
	if result.Percentage != 0 {
		t.Errorf("Percentage = %d, want 0", result.Percentage)
	}
	if result.Grade != assessGradeF {
		t.Errorf("Grade = %q, want F", result.Grade)
	}
}

// ---------- projectToSummary ----------

func TestProjectToSummary_StripsDetail(t *testing.T) {
	a := *minimalAssessment(assessGradeB, 85)
	a.Sections[0].Detail = "should be stripped"

	summary := projectToSummary(a)

	for _, s := range summary.Sections {
		if s.Detail != "" {
			t.Errorf("section %q Detail should be empty, got %q", s.ID, s.Detail)
		}
	}
}

func TestProjectToSummary_LimitsFindings(t *testing.T) {
	a := *minimalAssessment(assessGradeB, 85)
	a.Findings = []Finding{
		{ID: "f1", Severity: assessSevCritical, Source: sourceSimulate, Title: "t1"},
		{ID: "f2", Severity: assessSevHigh, Source: sourceSimulate, Title: "t2"},
		{ID: "f3", Severity: assessSevMedium, Source: sourceSimulate, Title: "t3"},
		{ID: "f4", Severity: assessSevLow, Source: sourceSimulate, Title: "t4"},
		{ID: "f5", Severity: assessSevInfo, Source: sourceSimulate, Title: "t5"},
	}

	summary := projectToSummary(a)

	if len(summary.TopFindings) != 3 {
		t.Errorf("TopFindings count = %d, want 3", len(summary.TopFindings))
	}
}

func TestProjectToSummary_FewerThanThreeFindings(t *testing.T) {
	a := *minimalAssessment(assessGradeA, 95)
	a.Findings = []Finding{
		{ID: "f1", Severity: assessSevLow, Source: sourceSimulate, Title: "t1"},
	}

	summary := projectToSummary(a)

	if len(summary.TopFindings) != 1 {
		t.Errorf("TopFindings count = %d, want 1", len(summary.TopFindings))
	}
}

func TestProjectToSummary_RedactsDiscoverTitles(t *testing.T) {
	a := *minimalAssessment(assessGradeC, 70)
	a.Findings = []Finding{
		{ID: "f1", Severity: assessSevHigh, Source: sourceDiscover, Title: "MCP server \"secret-db\" is unprotected"},
		{ID: "f2", Severity: assessSevMedium, Source: sourceDiscover, Title: "MCP server \"dev-tools\" is unprotected"},
		{ID: "f3", Severity: assessSevLow, Source: sourceSimulate, Title: "normal finding"},
	}

	summary := projectToSummary(a)

	for _, f := range summary.TopFindings {
		if f.Source == sourceDiscover {
			if strings.Contains(f.Title, "secret-db") || strings.Contains(f.Title, "dev-tools") {
				t.Errorf("discover finding title should be redacted, got %q", f.Title)
			}
		}
	}
}

func TestProjectToSummary_AlwaysUnsigned(t *testing.T) {
	a := *minimalAssessment(assessGradeA, 95)
	a.Signed = true // even if assessment claims signed

	summary := projectToSummary(a)

	if summary.Signed {
		t.Error("summary Signed should always be false")
	}
}

func TestProjectToSummary_WithCapReason(t *testing.T) {
	a := *minimalAssessment(assessGradeC, 85)
	a.GradeCap = assessGradeC
	a.CapReasons = []CapReason{
		{Cap: assessGradeC, Reason: "unprotected servers", Source: sourceDiscover},
	}

	summary := projectToSummary(a)

	if summary.GradeCap != assessGradeC {
		t.Errorf("GradeCap = %q, want C", summary.GradeCap)
	}
	if summary.CapReason != "unprotected servers" {
		t.Errorf("CapReason = %q, want 'unprotected servers'", summary.CapReason)
	}
}

func TestProjectToSummary_UncappedGrade(t *testing.T) {
	a := *minimalAssessment(assessGradeA, 95)

	summary := projectToSummary(a)

	if summary.GradeCap != "" {
		t.Errorf("GradeCap should be empty, got %q", summary.GradeCap)
	}
	if summary.CapReason != "" {
		t.Errorf("CapReason should be empty, got %q", summary.CapReason)
	}
}

func TestProjectToSummary_DetectionPct(t *testing.T) {
	a := *minimalAssessment(assessGradeB, 85)
	a.Sources.Simulate = &audit.SimulateResult{Percentage: 88}

	summary := projectToSummary(a)

	if summary.DetectionPct != 88 {
		t.Errorf("DetectionPct = %d, want 88", summary.DetectionPct)
	}
}

func TestProjectToSummary_ServerCounts(t *testing.T) {
	a := *minimalAssessment(assessGradeB, 85)
	a.Sources.Discover = &AssessDiscoverReport{
		Summary: AssessDiscoverSummary{
			Summary: discover.Summary{
				TotalServers:      5,
				ProtectedPipelock: 3,
				ProtectedOther:    1,
				Unprotected:       1,
			},
		},
	}

	summary := projectToSummary(a)

	if summary.ServerCounts.TotalServers != 5 {
		t.Errorf("TotalServers = %d, want 5", summary.ServerCounts.TotalServers)
	}
}

func TestProjectToSummary_Compliance(t *testing.T) {
	a := *minimalAssessment(assessGradeA, 95)
	a.Compliance = compliance.Catalog()

	summary := projectToSummary(a)

	if len(summary.Compliance) != len(a.Compliance) {
		t.Errorf("Compliance count = %d, want %d", len(summary.Compliance), len(a.Compliance))
	}
}

// ---------- redactDiscoverTitle ----------

func TestRedactDiscoverTitle_AllSeverities(t *testing.T) {
	cases := []struct {
		severity string
		want     string
	}{
		{assessSevHigh, "A high-risk MCP server is unprotected"},
		{assessSevMedium, "An MCP server is unprotected"},
		{assessSevLow, "An MCP server is unprotected"},
		{"", "An MCP server is unprotected"},
	}
	for _, tc := range cases {
		t.Run(tc.severity, func(t *testing.T) {
			got := redactDiscoverTitle(tc.severity)
			if got != tc.want {
				t.Errorf("redactDiscoverTitle(%q) = %q, want %q", tc.severity, got, tc.want)
			}
		})
	}
}

// ---------- render helper functions ----------

func TestRiskColor(t *testing.T) {
	cases := []struct {
		risk string
		want string
	}{
		{"high", colorRed},
		{"medium", colorYellow},
		{"low", colorGray},
		{"", colorGray},
	}
	for _, tc := range cases {
		t.Run(tc.risk, func(t *testing.T) {
			got := riskColor(tc.risk)
			if got != tc.want {
				t.Errorf("riskColor(%q) = %q, want %q", tc.risk, got, tc.want)
			}
		})
	}
}

func TestCoverageColor(t *testing.T) {
	cases := []struct {
		status string
		want   string
	}{
		{compliance.StatusCovered, colorGreen},
		{compliance.StatusPartial, colorYellow},
		{compliance.StatusNotCovered, colorRed},
		{"", colorRed},
	}
	for _, tc := range cases {
		t.Run(tc.status, func(t *testing.T) {
			got := coverageColor(tc.status)
			if got != tc.want {
				t.Errorf("coverageColor(%q) = %q, want %q", tc.status, got, tc.want)
			}
		})
	}
}

func TestCoverageLabel(t *testing.T) {
	cases := []struct {
		status string
		want   string
	}{
		{compliance.StatusCovered, "COVERED"},
		{compliance.StatusPartial, "PARTIAL"},
		{compliance.StatusNotCovered, "NOT COVERED"},
		{"", "NOT COVERED"},
	}
	for _, tc := range cases {
		t.Run(tc.status, func(t *testing.T) {
			got := coverageLabel(tc.status)
			if got != tc.want {
				t.Errorf("coverageLabel(%q) = %q, want %q", tc.status, got, tc.want)
			}
		})
	}
}

func TestAddInts(t *testing.T) {
	cases := []struct {
		a, b, want int
	}{
		{0, 0, 0},
		{1, 2, 3},
		{-1, 1, 0},
		{100, 200, 300},
	}
	for _, tc := range cases {
		got := addInts(tc.a, tc.b)
		if got != tc.want {
			t.Errorf("addInts(%d, %d) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestTruncHash(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"abcdef1234567890", "abcdef123456..."},
		{"short", "short"},
		{"exactly12ch", "exactly12ch"},
		{"exactly12chr", "exactly12chr"},
		{"exactly12chrs", "exactly12chr..."},
		{"", ""},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got := truncHash(tc.input)
			if got != tc.want {
				t.Errorf("truncHash(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestPriorityActions_Empty(t *testing.T) {
	actions := priorityActions(nil)
	if len(actions) != 0 {
		t.Errorf("expected 0 actions, got %d", len(actions))
	}
}

func TestPriorityActions_CombinesDiscover(t *testing.T) {
	findings := []Finding{
		{Source: sourceDiscover, Severity: assessSevHigh, Category: sectionMCPProtection, Remediation: "wrap it"},
		{Source: sourceDiscover, Severity: assessSevMedium, Category: sectionMCPProtection, Remediation: "wrap it"},
		{Source: sourceSimulate, Severity: assessSevHigh, Category: "DLP", Remediation: "enable DLP"},
	}

	actions := priorityActions(findings)

	// Should be: 1 combined discover action + 1 simulate action = 2.
	if len(actions) != 2 {
		t.Fatalf("expected 2 actions, got %d: %v", len(actions), actions)
	}

	// First action should mention "2 unprotected".
	if !strings.Contains(actions[0], "2 unprotected") {
		t.Errorf("first action should combine discover findings, got %q", actions[0])
	}
	// Should mention high-risk count.
	if !strings.Contains(actions[0], "1 high-risk") {
		t.Errorf("first action should mention high-risk count, got %q", actions[0])
	}
}

func TestPriorityActions_MaxFive(t *testing.T) {
	var findings []Finding
	for i := 0; i < 10; i++ {
		findings = append(findings, Finding{
			Source:      sourceSimulate,
			Category:    "cat-" + string(rune('A'+i)),
			Remediation: "fix it",
		})
	}

	actions := priorityActions(findings)

	if len(actions) > maxPriorityActions {
		t.Errorf("expected at most %d actions, got %d", maxPriorityActions, len(actions))
	}
}

func TestPriorityActions_SkipsEmptyRemediation(t *testing.T) {
	findings := []Finding{
		{Source: sourceSimulate, Category: "DLP", Remediation: ""},
		{Source: sourceSimulate, Category: "Injection", Remediation: "fix injection"},
	}

	actions := priorityActions(findings)

	if len(actions) != 1 {
		t.Errorf("expected 1 action (empty remediation skipped), got %d", len(actions))
	}
}

func TestPriorityActions_DeduplicatesBySourceCategory(t *testing.T) {
	findings := []Finding{
		{Source: sourceSimulate, Category: "DLP", Remediation: "fix DLP"},
		{Source: sourceSimulate, Category: "DLP", Remediation: "fix DLP again"},
	}

	actions := priorityActions(findings)

	if len(actions) != 1 {
		t.Errorf("expected 1 deduplicated action, got %d", len(actions))
	}
}

// ---------- writeAttestationJSON ----------

func TestWriteAttestationJSON_BadPath(t *testing.T) {
	att := &attestation.Attestation{}
	err := writeAttestationJSON("/nonexistent/dir/attestation.json", att)
	if err == nil {
		t.Error("expected error writing to bad path")
	}
}

func TestWriteAttestationJSON_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "attestation.json")

	att := &attestation.Attestation{}
	if err := writeAttestationJSON(path, att); err != nil {
		t.Fatalf("writeAttestationJSON: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("reading: %v", err)
	}
	if len(data) == 0 {
		t.Error("empty output")
	}
}
