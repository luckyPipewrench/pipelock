// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// setupCompletedRun creates a completed assessment run directory with evidence.
// Returns runDir for finalize testing.
func setupCompletedRun(t *testing.T) string {
	t.Helper()

	runDir, _ := initTestRun(t)

	if err := runAssessRun(runDir, false, nil); err != nil {
		t.Fatalf("runAssessRun: %v", err)
	}

	// Verify status is completed before continuing.
	m := readTestManifest(t, runDir)
	if m.Status != assessStatusCompleted {
		t.Fatalf("expected completed status, got %q", m.Status)
	}
	return runDir
}

// setupCompletedRunWithSkip creates a completed run with a skipped primitive.
func setupCompletedRunWithSkip(t *testing.T) string {
	t.Helper()

	runDir, _ := initTestRun(t)

	if err := runAssessRun(runDir, false, []string{primitiveVerifyInstall}); err != nil {
		t.Fatalf("runAssessRun: %v", err)
	}

	return runDir
}

// generateTestKeys creates a temporary keystore with a test agent key pair.
// Returns the keystore directory and agent name.
func generateTestKeys(t *testing.T) (keystoreDir, agentName string) {
	t.Helper()

	keystoreDir = filepath.Join(t.TempDir(), "keystore")
	agentName = "test-agent"

	ks := signing.NewKeystore(keystoreDir)
	if _, err := ks.GenerateAgent(agentName); err != nil {
		t.Fatalf("generating test keys: %v", err)
	}

	return keystoreDir, agentName
}

func TestAssessFinalize_Licensed_AutoSigns(t *testing.T) {
	runDir := setupCompletedRun(t)
	keystoreDir, agentName := generateTestKeys(t)

	opts := assessFinalizeOpts{
		HasAssess:   true,
		Agent:       agentName,
		KeystoreDir: keystoreDir,
	}

	if err := runAssessFinalize(runDir, opts); err != nil {
		t.Fatalf("runAssessFinalize: %v", err)
	}

	// Assert: assessment.json exists.
	if _, err := os.Stat(filepath.Join(runDir, "assessment.json")); err != nil {
		t.Error("assessment.json not found after licensed finalize")
	}

	// Assert: assessment.html exists.
	if _, err := os.Stat(filepath.Join(runDir, "assessment.html")); err != nil {
		t.Error("assessment.html not found after licensed finalize")
	}

	// Assert: manifest.json.sig exists.
	if _, err := os.Stat(filepath.Join(runDir, "manifest.json.sig")); err != nil {
		t.Error("manifest.json.sig not found after licensed finalize")
	}

	// Assert: verify.txt exists.
	if _, err := os.Stat(filepath.Join(runDir, "verify.txt")); err != nil {
		t.Error("verify.txt not found")
	}

	// Verify the signature is actually valid.
	ks := signing.NewKeystore(keystoreDir)
	pubKey, err := ks.LoadPublicKey(agentName)
	if err != nil {
		t.Fatalf("loading public key: %v", err)
	}
	if err := signing.VerifyFile(filepath.Join(runDir, "manifest.json"), "", pubKey); err != nil {
		t.Errorf("manifest signature verification failed: %v", err)
	}

	// Verify manifest status.
	m := readTestManifest(t, runDir)
	if m.Status != assessStatusFinalized {
		t.Errorf("Status = %q, want %q", m.Status, assessStatusFinalized)
	}
	if m.LicenseTier != assessTierAssess {
		t.Errorf("LicenseTier = %q, want %q", m.LicenseTier, assessTierAssess)
	}
	if m.FinalizedAt == nil {
		t.Error("FinalizedAt must not be nil after finalize")
	}

	// Assert: NO summary files.
	if _, err := os.Stat(filepath.Join(runDir, "summary.json")); err == nil {
		t.Error("summary.json should not exist on licensed finalize")
	}
}

func TestAssessFinalize_Licensed_Unsigned(t *testing.T) {
	runDir := setupCompletedRun(t)

	opts := assessFinalizeOpts{
		HasAssess: true,
		Unsigned:  true,
	}

	if err := runAssessFinalize(runDir, opts); err != nil {
		t.Fatalf("runAssessFinalize: %v", err)
	}

	// Assert: assessment.json exists.
	if _, err := os.Stat(filepath.Join(runDir, "assessment.json")); err != nil {
		t.Error("assessment.json not found")
	}

	// Assert: NO manifest.json.sig.
	if _, err := os.Stat(filepath.Join(runDir, "manifest.json.sig")); err == nil {
		t.Error("manifest.json.sig should not exist when --unsigned")
	}

	m := readTestManifest(t, runDir)
	if m.Status != assessStatusFinalized {
		t.Errorf("Status = %q, want %q", m.Status, assessStatusFinalized)
	}
}

func TestAssessFinalize_Unlicensed_Summary(t *testing.T) {
	runDir := setupCompletedRun(t)

	opts := assessFinalizeOpts{
		HasAssess: false,
	}

	if err := runAssessFinalize(runDir, opts); err != nil {
		t.Fatalf("runAssessFinalize: %v", err)
	}

	// Assert: summary.json exists.
	if _, err := os.Stat(filepath.Join(runDir, "summary.json")); err != nil {
		t.Error("summary.json not found after unlicensed finalize")
	}

	// Assert: summary.html exists.
	if _, err := os.Stat(filepath.Join(runDir, "summary.html")); err != nil {
		t.Error("summary.html not found after unlicensed finalize")
	}

	// Assert: NO assessment.json.
	if _, err := os.Stat(filepath.Join(runDir, "assessment.json")); err == nil {
		t.Error("assessment.json should not exist on unlicensed finalize")
	}

	// Assert: NO signature.
	if _, err := os.Stat(filepath.Join(runDir, "manifest.json.sig")); err == nil {
		t.Error("manifest.json.sig should not exist on unlicensed finalize")
	}

	m := readTestManifest(t, runDir)
	if m.LicenseTier != assessTierFree {
		t.Errorf("LicenseTier = %q, want %q", m.LicenseTier, assessTierFree)
	}
}

func TestAssessFinalize_SummaryNoLeakedFields(t *testing.T) {
	runDir := setupCompletedRun(t)

	opts := assessFinalizeOpts{
		HasAssess: false,
	}

	if err := runAssessFinalize(runDir, opts); err != nil {
		t.Fatalf("runAssessFinalize: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(filepath.Join(runDir, "summary.json")))
	if err != nil {
		t.Fatalf("reading summary.json: %v", err)
	}

	// Unmarshal as generic map to check for leaked fields.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("parsing summary.json: %v", err)
	}

	// Summary should NOT have "findings" (full findings), "sources", or "annexes".
	for _, forbidden := range []string{"findings", "sources", "annexes", "cap_reasons", "weights"} {
		if _, ok := raw[forbidden]; ok {
			t.Errorf("summary.json contains forbidden field %q", forbidden)
		}
	}

	// Check top_findings have no remediation or evidence fields.
	if tfRaw, ok := raw["top_findings"]; ok {
		var topFindings []map[string]json.RawMessage
		if err := json.Unmarshal(tfRaw, &topFindings); err != nil {
			t.Fatalf("parsing top_findings: %v", err)
		}
		for i, tf := range topFindings {
			for _, leaked := range []string{"remediation", "evidence", "detail"} {
				if _, ok := tf[leaked]; ok {
					t.Errorf("top_findings[%d] contains leaked field %q", i, leaked)
				}
			}
		}
	}

	// Check discover finding IDs don't leak server/client names.
	if tfRaw2, ok := raw["top_findings"]; ok {
		var findings []map[string]json.RawMessage
		if err := json.Unmarshal(tfRaw2, &findings); err == nil {
			for i, tf := range findings {
				var id string
				if idRaw, ok := tf["id"]; ok {
					_ = json.Unmarshal(idRaw, &id)
				}
				var source string
				if srcRaw, ok := tf["source"]; ok {
					_ = json.Unmarshal(srcRaw, &source)
				}
				if source == sourceDiscover && !strings.HasPrefix(id, "find-discover-redacted-") {
					t.Errorf("top_findings[%d] discover ID %q leaks server name (expected find-discover-redacted-*)", i, id)
				}
			}
		}
	}

	// Check sections have no detail field.
	if secRaw, ok := raw["sections"]; ok {
		var sections []map[string]json.RawMessage
		if err := json.Unmarshal(secRaw, &sections); err != nil {
			t.Fatalf("parsing sections: %v", err)
		}
		for i, sec := range sections {
			if detailRaw, ok := sec["detail"]; ok {
				// detail may be present as empty string (omitempty drops it) or absent.
				var detail string
				if err := json.Unmarshal(detailRaw, &detail); err == nil && detail != "" {
					t.Errorf("sections[%d] has non-empty detail %q", i, detail)
				}
			}
		}
	}
}

func TestRedactDiscoverTitle(t *testing.T) {
	tests := []struct {
		severity string
		want     string
	}{
		{assessSevHigh, "A high-risk MCP server is unprotected"},
		{assessSevMedium, "An MCP server is unprotected"},
		{assessSevLow, "An MCP server is unprotected"},
		{assessSevCritical, "An MCP server is unprotected"},
		{assessSevInfo, "An MCP server is unprotected"},
	}
	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			got := redactDiscoverTitle(tt.severity)
			if got != tt.want {
				t.Errorf("redactDiscoverTitle(%q) = %q, want %q", tt.severity, got, tt.want)
			}
		})
	}
}

func TestAssessFinalize_ManifestArtifactHashes(t *testing.T) {
	runDir := setupCompletedRun(t)

	opts := assessFinalizeOpts{
		HasAssess: false,
	}

	if err := runAssessFinalize(runDir, opts); err != nil {
		t.Fatalf("runAssessFinalize: %v", err)
	}

	m := readTestManifest(t, runDir)
	if len(m.Artifacts) == 0 {
		t.Fatal("manifest.Artifacts should not be empty after finalize")
	}

	// Verify each artifact hash matches actual file content.
	for name, expectedHash := range m.Artifacts {
		path := filepath.Join(runDir, name)
		data, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			t.Errorf("reading artifact %s: %v", name, err)
			continue
		}
		sum := sha256.Sum256(data)
		actualHash := hex.EncodeToString(sum[:])
		if actualHash != expectedHash {
			t.Errorf("artifact %s: hash mismatch (manifest=%s, actual=%s)", name, expectedHash[:12], actualHash[:12])
		}
	}

	// Verify specific artifacts are present.
	expectedArtifacts := []string{"summary.json", "summary.html"}
	for _, name := range expectedArtifacts {
		if _, ok := m.Artifacts[name]; !ok {
			t.Errorf("missing artifact hash for %s", name)
		}
	}
}

func TestAssessFinalize_SkippedWithoutAllowPartial(t *testing.T) {
	runDir := setupCompletedRunWithSkip(t)

	opts := assessFinalizeOpts{
		HasAssess:    false,
		AllowPartial: false,
	}

	err := runAssessFinalize(runDir, opts)
	if err == nil {
		t.Fatal("expected error for skipped primitives without --allow-partial, got nil")
	}

	if !strings.Contains(err.Error(), "skipped primitives") {
		t.Errorf("error should mention skipped primitives, got: %v", err)
	}
}

func TestAssessFinalize_SkippedWithAllowPartial(t *testing.T) {
	runDir := setupCompletedRunWithSkip(t)

	opts := assessFinalizeOpts{
		HasAssess:    false,
		AllowPartial: true,
	}

	if err := runAssessFinalize(runDir, opts); err != nil {
		t.Fatalf("runAssessFinalize with AllowPartial: %v", err)
	}

	m := readTestManifest(t, runDir)
	if m.Status != assessStatusFinalized {
		t.Errorf("Status = %q, want %q", m.Status, assessStatusFinalized)
	}
	if !m.AllowPartial {
		t.Error("AllowPartial should be true in manifest")
	}
}

func TestAssessFinalize_AlreadyFinalized(t *testing.T) {
	runDir := setupCompletedRun(t)

	opts := assessFinalizeOpts{
		HasAssess: false,
	}

	// First finalize should succeed.
	if err := runAssessFinalize(runDir, opts); err != nil {
		t.Fatalf("first runAssessFinalize: %v", err)
	}

	// Second finalize should fail.
	err := runAssessFinalize(runDir, opts)
	if err == nil {
		t.Fatal("expected error on second finalize, got nil")
	}
	if !strings.Contains(err.Error(), "already finalized") {
		t.Errorf("error should say 'already finalized', got: %v", err)
	}
}

func TestAssessFinalize_Archive(t *testing.T) {
	runDir := setupCompletedRun(t)

	opts := assessFinalizeOpts{
		HasAssess: false,
		Archive:   true,
	}

	if err := runAssessFinalize(runDir, opts); err != nil {
		t.Fatalf("runAssessFinalize with archive: %v", err)
	}

	// Find the archive file in the parent directory.
	parent := filepath.Dir(runDir)
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatalf("reading parent dir: %v", err)
	}

	var archivePath string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "summary-") && strings.HasSuffix(e.Name(), ".tar.gz") {
			archivePath = filepath.Join(parent, e.Name())
			break
		}
	}
	if archivePath == "" {
		t.Fatal("archive .tar.gz not found")
	}

	// Verify it's a valid tar.gz.
	f, err := os.Open(filepath.Clean(archivePath))
	if err != nil {
		t.Fatalf("opening archive: %v", err)
	}
	defer func() { _ = f.Close() }()

	gr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	defer func() { _ = gr.Close() }()

	tr := tar.NewReader(gr)
	var fileNames []string
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		fileNames = append(fileNames, hdr.Name)
	}

	if len(fileNames) == 0 {
		t.Error("archive is empty")
	}

	// Should contain manifest.json at minimum.
	foundManifest := false
	for _, name := range fileNames {
		if strings.HasSuffix(name, "manifest.json") {
			foundManifest = true
			break
		}
	}
	if !foundManifest {
		t.Error("archive does not contain manifest.json")
	}
}

func TestAssessFinalize_ArchiveLicensed(t *testing.T) {
	runDir := setupCompletedRun(t)
	keystoreDir, agentName := generateTestKeys(t)

	opts := assessFinalizeOpts{
		HasAssess:   true,
		Archive:     true,
		Agent:       agentName,
		KeystoreDir: keystoreDir,
	}

	if err := runAssessFinalize(runDir, opts); err != nil {
		t.Fatalf("runAssessFinalize: %v", err)
	}

	// Licensed archive should be named "assessment-*".
	parent := filepath.Dir(runDir)
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatalf("reading parent dir: %v", err)
	}

	found := false
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "assessment-") && strings.HasSuffix(e.Name(), ".tar.gz") {
			found = true
			break
		}
	}
	if !found {
		t.Error("licensed archive should be named assessment-*.tar.gz")
	}
}

func TestAssessFinalize_ReadEvidenceSources(t *testing.T) {
	runDir := setupCompletedRun(t)

	sources, err := readEvidenceSources(runDir)
	if err != nil {
		t.Fatalf("readEvidenceSources: %v", err)
	}

	if sources.Simulate == nil {
		t.Error("Simulate source should not be nil")
	}
	if sources.AuditScore == nil {
		t.Error("AuditScore source should not be nil")
	}
	if sources.VerifyInstall == nil {
		t.Error("VerifyInstall source should not be nil")
	}
	if sources.Discover == nil {
		t.Error("Discover source should not be nil")
	}
}

func TestAssessFinalize_ReadEvidenceSources_MissingFiles(t *testing.T) {
	// Create a minimal run dir with no evidence files.
	tmp := t.TempDir()
	runDir := filepath.Join(tmp, "empty-run")
	if err := os.MkdirAll(filepath.Join(runDir, "evidence"), 0o750); err != nil {
		t.Fatalf("creating evidence dir: %v", err)
	}

	sources, err := readEvidenceSources(runDir)
	if err != nil {
		t.Fatalf("readEvidenceSources: %v", err)
	}

	// All sources should be nil (missing files = skipped primitives).
	if sources.Simulate != nil {
		t.Error("Simulate should be nil with missing evidence")
	}
	if sources.AuditScore != nil {
		t.Error("AuditScore should be nil with missing evidence")
	}
	if sources.VerifyInstall != nil {
		t.Error("VerifyInstall should be nil with missing evidence")
	}
	if sources.Discover != nil {
		t.Error("Discover should be nil with missing evidence")
	}
}

func TestAssessFinalize_ProjectToSummary(t *testing.T) {
	assessment := Assessment{
		SchemaVersion: assessSchemaVersion,
		OverallGrade:  assessGradeB,
		OverallScore:  85,
		GradeCap:      "",
		Sections: []AssessmentSection{
			{ID: sectionDetectionCoverage, Name: "Detection Coverage", Score: 90, MaxScore: 100, Detail: "18/20 detected"},
			{ID: sectionConfigPosture, Name: "Config Posture", Score: 80, MaxScore: 100, Detail: "80/100 points"},
		},
		Findings: []Finding{
			{ID: "find-1", Severity: assessSevCritical, Category: "DLP", Source: sourceSimulate, Title: "Missed leak", Remediation: "Add pattern", Evidence: json.RawMessage(`{"test":true}`)},
			{ID: "find-2", Severity: assessSevHigh, Category: "SSRF", Source: sourceSimulate, Title: "SSRF bypass"},
			{ID: "find-3", Severity: assessSevMedium, Category: "Config", Source: sourceAuditScore, Title: "Weak config"},
			{ID: "find-4", Severity: assessSevLow, Category: "Info", Source: sourceAuditScore, Title: "Low info"},
		},
		Sources: AssessSources{
			Simulate: &SimulateResult{Percentage: 90},
			Discover: &AssessDiscoverReport{
				Summary: AssessDiscoverSummary{},
			},
		},
	}

	summary := projectToSummary(assessment)

	// Sections should have empty Detail.
	for _, s := range summary.Sections {
		if s.Detail != "" {
			t.Errorf("section %q Detail should be empty in summary, got %q", s.ID, s.Detail)
		}
	}

	// Top 3 findings only.
	if len(summary.TopFindings) != 3 {
		t.Fatalf("TopFindings count = %d, want 3", len(summary.TopFindings))
	}

	// TopFindings should be highest severity first.
	if summary.TopFindings[0].Severity != assessSevCritical {
		t.Errorf("first TopFinding severity = %q, want %q", summary.TopFindings[0].Severity, assessSevCritical)
	}

	// DetectionPct.
	if summary.DetectionPct != 90 {
		t.Errorf("DetectionPct = %d, want 90", summary.DetectionPct)
	}

	// Signed is always false for summary.
	if summary.Signed {
		t.Error("Signed should be false for summary")
	}
}

func TestAssessFinalize_ProjectToSummary_FewerThan3Findings(t *testing.T) {
	assessment := Assessment{
		SchemaVersion: assessSchemaVersion,
		Findings: []Finding{
			{ID: "only-one", Severity: assessSevHigh, Title: "Single finding"},
		},
		Sources: AssessSources{},
	}

	summary := projectToSummary(assessment)

	if len(summary.TopFindings) != 1 {
		t.Errorf("TopFindings count = %d, want 1", len(summary.TopFindings))
	}
}

func TestAssessFinalize_ReconstructSimulateResult(t *testing.T) {
	scenarios := []ScenarioResult{
		{Name: "test1", Category: "DLP", Detected: true},
		{Name: "test2", Category: "DLP", Detected: false},
		{Name: "test3", Category: "DLP", Detected: true, Limitation: true},
	}

	result := reconstructSimulateResult(scenarios)
	if result == nil {
		t.Fatal("result should not be nil")
	}
	if result.Total != 3 {
		t.Errorf("Total = %d, want 3", result.Total)
	}
	if result.Passed != 1 {
		t.Errorf("Passed = %d, want 1", result.Passed)
	}
	if result.Failed != 1 {
		t.Errorf("Failed = %d, want 1", result.Failed)
	}
	if result.KnownLimits != 1 {
		t.Errorf("KnownLimits = %d, want 1", result.KnownLimits)
	}
	// Applicable = 3-1 = 2, percentage = (1*100)/2 = 50.
	if result.Percentage != 50 {
		t.Errorf("Percentage = %d, want 50", result.Percentage)
	}
}

func TestAssessFinalize_ReconstructSimulateResult_Empty(t *testing.T) {
	result := reconstructSimulateResult(nil)
	if result != nil {
		t.Error("empty scenarios should return nil")
	}

	result = reconstructSimulateResult([]ScenarioResult{})
	if result != nil {
		t.Error("zero-length scenarios should return nil")
	}
}

func TestAssessFinalize_SplitJSONLines(t *testing.T) {
	input := []byte("{\"a\":1}\n{\"b\":2}\n{\"c\":3}\n")
	lines := splitJSONLines(input)
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(lines))
	}
	// Verify each is valid JSON.
	for i, line := range lines {
		if !json.Valid(line) {
			t.Errorf("line %d is not valid JSON: %s", i, string(line))
		}
	}
}

func TestAssessFinalize_SplitJSONLines_NoTrailingNewline(t *testing.T) {
	input := []byte("{\"a\":1}\n{\"b\":2}")
	lines := splitJSONLines(input)
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}
}

func TestAssessFinalize_MissingManifest(t *testing.T) {
	tmp := t.TempDir()
	err := runAssessFinalize(tmp, assessFinalizeOpts{})
	if err == nil {
		t.Fatal("expected error for missing manifest")
	}
}

func TestAssessFinalize_WrongStatus(t *testing.T) {
	runDir, _ := initTestRun(t)

	// Manifest is in "initialized" status, not "completed".
	err := runAssessFinalize(runDir, assessFinalizeOpts{})
	if err == nil {
		t.Fatal("expected error for wrong status")
	}
	if !strings.Contains(err.Error(), "initialized") {
		t.Errorf("error should mention current status, got: %v", err)
	}
}

func TestAssessFinalize_VerifyTxtContent(t *testing.T) {
	runDir := setupCompletedRun(t)

	opts := assessFinalizeOpts{
		HasAssess: false,
	}

	if err := runAssessFinalize(runDir, opts); err != nil {
		t.Fatalf("runAssessFinalize: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(filepath.Join(runDir, "verify.txt")))
	if err != nil {
		t.Fatalf("reading verify.txt: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, "Pipelock Assessment Verification") {
		t.Error("verify.txt missing header")
	}
	if !strings.Contains(content, "Run ID:") {
		t.Error("verify.txt missing Run ID")
	}
	if !strings.Contains(content, "pipelock assess verify") {
		t.Error("verify.txt missing verify command")
	}
}

func TestAssessFinalize_HTMLFilesCreated(t *testing.T) {
	t.Run("licensed produces assessment.html", func(t *testing.T) {
		runDir := setupCompletedRun(t)
		keystoreDir, agentName := generateTestKeys(t)

		opts := assessFinalizeOpts{
			HasAssess:   true,
			Agent:       agentName,
			KeystoreDir: keystoreDir,
		}

		if err := runAssessFinalize(runDir, opts); err != nil {
			t.Fatalf("runAssessFinalize: %v", err)
		}

		data, err := os.ReadFile(filepath.Clean(filepath.Join(runDir, "assessment.html")))
		if err != nil {
			t.Fatalf("reading assessment.html: %v", err)
		}
		if !strings.Contains(string(data), "<html") {
			t.Error("assessment.html should be valid HTML")
		}
		if !strings.Contains(string(data), "Pipelock Security Assessment") {
			t.Error("assessment.html should contain title")
		}
	})

	t.Run("unlicensed produces summary.html", func(t *testing.T) {
		runDir := setupCompletedRun(t)

		opts := assessFinalizeOpts{
			HasAssess: false,
		}

		if err := runAssessFinalize(runDir, opts); err != nil {
			t.Fatalf("runAssessFinalize: %v", err)
		}

		data, err := os.ReadFile(filepath.Clean(filepath.Join(runDir, "summary.html")))
		if err != nil {
			t.Fatalf("reading summary.html: %v", err)
		}
		if !strings.Contains(string(data), "Unsigned") {
			t.Error("summary.html should mention unsigned")
		}
	})
}

func TestAssessFinalize_FilePermissions(t *testing.T) {
	runDir := setupCompletedRun(t)

	opts := assessFinalizeOpts{
		HasAssess: false,
	}

	if err := runAssessFinalize(runDir, opts); err != nil {
		t.Fatalf("runAssessFinalize: %v", err)
	}

	filesToCheck := []string{"summary.json", "summary.html", "verify.txt", "manifest.json"}
	for _, name := range filesToCheck {
		path := filepath.Join(runDir, name)
		info, err := os.Stat(path)
		if err != nil {
			t.Errorf("stat %s: %v", name, err)
			continue
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("%s permissions = %o, want 0600", name, perm)
		}
	}
}

func TestAssessFinalize_EvidenceHashes(t *testing.T) {
	runDir := setupCompletedRun(t)

	opts := assessFinalizeOpts{
		HasAssess: false,
	}

	if err := runAssessFinalize(runDir, opts); err != nil {
		t.Fatalf("runAssessFinalize: %v", err)
	}

	m := readTestManifest(t, runDir)

	// At least one evidence file should be hashed.
	evidenceHashFound := false
	for name := range m.Artifacts {
		if strings.HasPrefix(name, "evidence/") {
			evidenceHashFound = true
			break
		}
	}
	if !evidenceHashFound {
		t.Error("manifest.Artifacts should contain evidence file hashes")
	}
}

func TestAssessFinalize_SortedArtifactKeys(t *testing.T) {
	m := map[string]string{
		"zebra.json":           "hash1",
		"assessment.json":      "hash2",
		"evidence/sim.jsonl":   "hash3",
		"evidence/audit.jsonl": "hash4",
	}

	keys := sortedArtifactKeys(m)
	for i := 1; i < len(keys); i++ {
		if keys[i] < keys[i-1] {
			t.Errorf("keys not sorted: %q before %q", keys[i-1], keys[i])
		}
	}
}

// TestAssessFinalize_RoundTrip verifies the full init -> run -> finalize flow
// produces a valid, internally consistent assessment.
func TestAssessFinalize_RoundTrip(t *testing.T) {
	runDir := setupCompletedRun(t)

	opts := assessFinalizeOpts{
		HasAssess: false,
	}

	if err := runAssessFinalize(runDir, opts); err != nil {
		t.Fatalf("runAssessFinalize: %v", err)
	}

	// Read and verify summary.json.
	data, err := os.ReadFile(filepath.Clean(filepath.Join(runDir, "summary.json")))
	if err != nil {
		t.Fatalf("reading summary.json: %v", err)
	}

	var summary Summary
	if err := json.Unmarshal(data, &summary); err != nil {
		t.Fatalf("parsing summary.json: %v", err)
	}

	if summary.SchemaVersion != assessSchemaVersion {
		t.Errorf("SchemaVersion = %q, want %q", summary.SchemaVersion, assessSchemaVersion)
	}
	if summary.OverallGrade == "" {
		t.Error("OverallGrade should not be empty")
	}
	if summary.Manifest.Status != assessStatusFinalized {
		t.Errorf("Manifest.Status = %q, want %q", summary.Manifest.Status, assessStatusFinalized)
	}
}

// TestAssessFinalize_AssessmentRoundTrip verifies the licensed path produces valid assessment JSON.
func TestAssessFinalize_AssessmentRoundTrip(t *testing.T) {
	runDir := setupCompletedRun(t)
	keystoreDir, agentName := generateTestKeys(t)

	opts := assessFinalizeOpts{
		HasAssess:   true,
		Agent:       agentName,
		KeystoreDir: keystoreDir,
	}

	if err := runAssessFinalize(runDir, opts); err != nil {
		t.Fatalf("runAssessFinalize: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(filepath.Join(runDir, "assessment.json")))
	if err != nil {
		t.Fatalf("reading assessment.json: %v", err)
	}

	var assessment Assessment
	if err := json.Unmarshal(data, &assessment); err != nil {
		t.Fatalf("parsing assessment.json: %v", err)
	}

	if assessment.SchemaVersion != assessSchemaVersion {
		t.Errorf("SchemaVersion = %q, want %q", assessment.SchemaVersion, assessSchemaVersion)
	}
	if len(assessment.Sections) != 4 {
		t.Errorf("Sections count = %d, want 4", len(assessment.Sections))
	}
	if assessment.Sources.Simulate == nil {
		t.Error("Sources.Simulate should not be nil in full assessment")
	}
}

func TestAssessFinalize_CreateTarGz(t *testing.T) {
	tmp := t.TempDir()
	sourceDir := filepath.Join(tmp, "source")
	if err := os.MkdirAll(filepath.Join(sourceDir, "sub"), 0o750); err != nil {
		t.Fatalf("creating source dirs: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "file1.txt"), []byte("hello"), 0o600); err != nil {
		t.Fatalf("writing file1: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "sub", "file2.txt"), []byte("world"), 0o600); err != nil {
		t.Fatalf("writing file2: %v", err)
	}

	archivePath := filepath.Join(tmp, "test.tar.gz")
	if err := createTarGz(archivePath, sourceDir); err != nil {
		t.Fatalf("createTarGz: %v", err)
	}

	// Verify archive contents.
	f, err := os.Open(filepath.Clean(archivePath))
	if err != nil {
		t.Fatalf("opening archive: %v", err)
	}
	defer func() { _ = f.Close() }()

	gr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	defer func() { _ = gr.Close() }()

	tr := tar.NewReader(gr)
	var names []string
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("reading tar: %v", err)
		}
		names = append(names, hdr.Name)
	}

	// Should contain source dir, sub dir, and two files.
	if len(names) < 3 {
		t.Errorf("archive has %d entries, want at least 3: %v", len(names), names)
	}
}
