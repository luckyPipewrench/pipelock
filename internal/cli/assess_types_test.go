// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"testing"
	"time"
)

// TestAssessManifest_JSONRoundTrip verifies that all fields survive a
// marshal/unmarshal cycle without corruption or loss.
func TestAssessManifest_JSONRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	completed := now.Add(time.Minute)
	finalized := now.Add(2 * time.Minute)

	original := AssessManifest{
		SchemaVersion:     assessSchemaVersion,
		Version:           "2.0.0",
		BuildSHA:          "abc123",
		RunID:             "run-001",
		ConfigFile:        "/etc/pipelock.yaml",
		ConfigHash:        "deadbeef",
		ConfigDrifted:     true,
		LicenseTier:       assessTierAssess,
		StartedAt:         now,
		CompletedAt:       &completed,
		FinalizedAt:       &finalized,
		FailedAt:          nil,
		FailureReason:     "",
		GitCommit:         "sha256abc",
		Platform:          "linux/amd64",
		Status:            assessStatusFinalized,
		SkippedPrimitives: []string{"simulate"},
		AllowPartial:      true,
		RendererVersion:   assessRendererVersion,
		ScoringVersion:    assessScoringVersion,
		Artifacts:         map[string]string{"report": "/tmp/report.html"},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var got AssessManifest
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if got.SchemaVersion != original.SchemaVersion {
		t.Errorf("SchemaVersion: got %q want %q", got.SchemaVersion, original.SchemaVersion)
	}
	if got.Version != original.Version {
		t.Errorf("Version: got %q want %q", got.Version, original.Version)
	}
	if got.RunID != original.RunID {
		t.Errorf("RunID: got %q want %q", got.RunID, original.RunID)
	}
	if got.LicenseTier != original.LicenseTier {
		t.Errorf("LicenseTier: got %q want %q", got.LicenseTier, original.LicenseTier)
	}
	if !got.StartedAt.Equal(original.StartedAt) {
		t.Errorf("StartedAt: got %v want %v", got.StartedAt, original.StartedAt)
	}
	if got.CompletedAt == nil || !got.CompletedAt.Equal(*original.CompletedAt) {
		t.Errorf("CompletedAt: got %v want %v", got.CompletedAt, original.CompletedAt)
	}
	if got.FinalizedAt == nil || !got.FinalizedAt.Equal(*original.FinalizedAt) {
		t.Errorf("FinalizedAt: got %v want %v", got.FinalizedAt, original.FinalizedAt)
	}
	if got.FailedAt != nil {
		t.Errorf("FailedAt: expected nil, got %v", got.FailedAt)
	}
	if got.ConfigDrifted != original.ConfigDrifted {
		t.Errorf("ConfigDrifted: got %v want %v", got.ConfigDrifted, original.ConfigDrifted)
	}
	if got.Platform != original.Platform {
		t.Errorf("Platform: got %q want %q", got.Platform, original.Platform)
	}
	if got.Status != original.Status {
		t.Errorf("Status: got %q want %q", got.Status, original.Status)
	}
	if len(got.SkippedPrimitives) != len(original.SkippedPrimitives) {
		t.Errorf("SkippedPrimitives: got %v want %v", got.SkippedPrimitives, original.SkippedPrimitives)
	}
	if got.Artifacts["report"] != original.Artifacts["report"] {
		t.Errorf("Artifacts[report]: got %q want %q", got.Artifacts["report"], original.Artifacts["report"])
	}
}

// TestSummaryProjection_NoLeakedFields ensures SummaryFinding omits the verbose
// fields present on Finding (detail, remediation, evidence).
func TestSummaryProjection_NoLeakedFields(t *testing.T) {
	sf := SummaryFinding{
		SchemaVersion: assessSchemaVersion,
		ID:            "F-001",
		Severity:      assessSevHigh,
		Category:      "dlp",
		Source:        "simulate",
		Title:         "Secret exposed in URL",
	}

	data, err := json.Marshal(sf)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal to map failed: %v", err)
	}

	for _, forbidden := range []string{"detail", "remediation", "evidence"} {
		if _, ok := m[forbidden]; ok {
			t.Errorf("SummaryFinding JSON must not contain key %q", forbidden)
		}
	}
}

// TestAssessmentSection_DeterministicOrder verifies that sortAssessmentSections
// produces alphabetical order by section ID.
func TestAssessmentSection_DeterministicOrder(t *testing.T) {
	sections := []AssessmentSection{
		{ID: sectionMCPProtection, Name: "MCP Protection"},
		{ID: sectionDetectionCoverage, Name: "Detection Coverage"},
		{ID: sectionDeploymentVerification, Name: "Deployment Verification"},
		{ID: sectionConfigPosture, Name: "Config Posture"},
	}

	sortAssessmentSections(sections)

	want := []string{
		sectionConfigPosture,
		sectionDeploymentVerification,
		sectionDetectionCoverage,
		sectionMCPProtection,
	}

	for i, s := range sections {
		if s.ID != want[i] {
			t.Errorf("position %d: got %q want %q", i, s.ID, want[i])
		}
	}
}

// TestFinding_DeterministicOrder verifies that sortFindings orders by severity
// descending (critical first) and breaks ties by ID ascending.
func TestFinding_DeterministicOrder(t *testing.T) {
	findings := []Finding{
		{ID: "F-003", Severity: assessSevLow},
		{ID: "F-001", Severity: assessSevCritical},
		{ID: "F-005", Severity: assessSevInfo},
		{ID: "F-002", Severity: assessSevHigh},
		{ID: "F-004", Severity: assessSevMedium},
		{ID: "F-006", Severity: assessSevCritical}, // tie-break by ID
	}

	sortFindings(findings)

	wantOrder := []struct {
		id  string
		sev string
	}{
		{"F-001", assessSevCritical},
		{"F-006", assessSevCritical},
		{"F-002", assessSevHigh},
		{"F-004", assessSevMedium},
		{"F-003", assessSevLow},
		{"F-005", assessSevInfo},
	}

	for i, w := range wantOrder {
		if findings[i].ID != w.id || findings[i].Severity != w.sev {
			t.Errorf("position %d: got {%s,%s} want {%s,%s}",
				i, findings[i].ID, findings[i].Severity, w.id, w.sev)
		}
	}
}

// TestDefaultScoringWeights verifies that defaultScoringWeights returns the
// canonical section weights and that they sum to 100.
func TestDefaultScoringWeights(t *testing.T) {
	w := defaultScoringWeights()

	if w.DetectionCoverage != weightDetectionCoverage {
		t.Errorf("DetectionCoverage: got %d want %d", w.DetectionCoverage, weightDetectionCoverage)
	}
	if w.ConfigPosture != weightConfigPosture {
		t.Errorf("ConfigPosture: got %d want %d", w.ConfigPosture, weightConfigPosture)
	}
	if w.DeploymentVerification != weightDeploymentVerification {
		t.Errorf("DeploymentVerification: got %d want %d", w.DeploymentVerification, weightDeploymentVerification)
	}
	if w.MCPProtection != weightMCPProtection {
		t.Errorf("MCPProtection: got %d want %d", w.MCPProtection, weightMCPProtection)
	}

	total := w.DetectionCoverage + w.ConfigPosture + w.DeploymentVerification + w.MCPProtection
	if total != 100 {
		t.Errorf("weights must sum to 100, got %d", total)
	}
}

// TestGradeFromPercentage verifies boundary conditions for all grade bands.
func TestGradeFromPercentage(t *testing.T) {
	cases := []struct {
		pct  int
		want string
	}{
		{100, assessGradeA},
		{90, assessGradeA},
		{89, assessGradeB},
		{80, assessGradeB},
		{79, assessGradeC},
		{70, assessGradeC},
		{69, assessGradeD},
		{60, assessGradeD},
		{59, assessGradeF},
		{0, assessGradeF},
	}

	for _, tc := range cases {
		got := gradeFromPercentage(tc.pct)
		if got != tc.want {
			t.Errorf("gradeFromPercentage(%d) = %q, want %q", tc.pct, got, tc.want)
		}
	}
}
