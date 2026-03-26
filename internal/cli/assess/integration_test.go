// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package assess

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// validGrades is the set of acceptable overall grades.
var validGrades = map[string]bool{
	assessGradeA: true,
	assessGradeB: true,
	assessGradeC: true,
	assessGradeD: true,
	assessGradeF: true,
}

// setupTestKeystore creates a temporary keystore directory and generates a
// test Ed25519 key pair using the pipelock keystore format.
func setupTestKeystore(t *testing.T) (dir string, agent string) {
	t.Helper()

	dir = filepath.Join(t.TempDir(), "keystore")
	agent = "test-agent"

	ks := signing.NewKeystore(dir)
	if _, err := ks.GenerateAgent(agent); err != nil {
		t.Fatalf("setupTestKeystore: generating agent keys: %v", err)
	}

	return dir, agent
}

// TestAssess_EndToEnd_Licensed validates the full init -> run -> finalize -> verify
// pipeline for a licensed (HasAssess=true) user with a signed output.
func TestAssess_EndToEnd_Licensed(t *testing.T) {
	// 1. Create temp dir and minimal config.
	tmp := t.TempDir()
	cfgFile := filepath.Join(tmp, "pipelock.yaml")
	if err := os.WriteFile(cfgFile, []byte("mode: balanced\n"), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	outDir := filepath.Join(tmp, "assessment-e2e-licensed")

	// 2. Init.
	runDir, err := runAssessInit(cfgFile, outDir)
	if err != nil {
		t.Fatalf("runAssessInit: %v", err)
	}

	// 3. Run.
	if err := runAssessRun(runDir, false, nil); err != nil {
		t.Fatalf("runAssessRun: %v", err)
	}

	// 4. Set up test keystore.
	keystoreDir, agentName := setupTestKeystore(t)

	// 5. Finalize (licensed, signed).
	opts := assessFinalizeOpts{
		HasAssess:   true,
		Agent:       agentName,
		KeystoreDir: keystoreDir,
	}
	if err := runAssessFinalize(runDir, opts); err != nil {
		t.Fatalf("runAssessFinalize: %v", err)
	}

	// 6. Verify — exit code 0 (integrity + authenticity).
	exitCode, err := runAssessVerify(runDir, agentName, keystoreDir)
	if err != nil {
		t.Fatalf("runAssessVerify: unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("verify exit code = %d, want 0", exitCode)
	}

	// Assert: assessment.json exists and is valid JSON.
	assessPath := filepath.Join(runDir, "assessment.json")
	if _, err := os.Stat(assessPath); err != nil {
		t.Fatal("assessment.json not found")
	}
	assessData, err := os.ReadFile(filepath.Clean(assessPath))
	if err != nil {
		t.Fatalf("reading assessment.json: %v", err)
	}
	if !json.Valid(assessData) {
		t.Fatal("assessment.json is not valid JSON")
	}

	// Assert: assessment.html exists.
	if _, err := os.Stat(filepath.Join(runDir, "assessment.html")); err != nil {
		t.Error("assessment.html not found")
	}

	// Assert: manifest.json.sig exists.
	if _, err := os.Stat(filepath.Join(runDir, "manifest.json.sig")); err != nil {
		t.Error("manifest.json.sig not found")
	}

	// Assert: verify.txt exists.
	if _, err := os.Stat(filepath.Join(runDir, "verify.txt")); err != nil {
		t.Error("verify.txt not found")
	}

	// Assert: assessment.json has all 4 sections.
	var assessment Assessment
	if err := json.Unmarshal(assessData, &assessment); err != nil {
		t.Fatalf("parsing assessment.json: %v", err)
	}
	if len(assessment.Sections) != 4 {
		t.Errorf("assessment has %d sections, want 4", len(assessment.Sections))
	}

	// Assert: assessment.json has findings (non-nil slice; may be empty).
	if assessment.Findings == nil {
		t.Error("assessment.Findings must be non-nil (use empty slice, not nil)")
	}

	// Assert: assessment.json has sources (all 4 primitives ran).
	if assessment.Sources.Simulate == nil {
		t.Error("Sources.Simulate must not be nil")
	}
	if assessment.Sources.AuditScore == nil {
		t.Error("Sources.AuditScore must not be nil")
	}
	if assessment.Sources.VerifyInstall == nil {
		t.Error("Sources.VerifyInstall must not be nil")
	}
	if assessment.Sources.Discover == nil {
		t.Error("Sources.Discover must not be nil")
	}

	// Assert: overall grade is A-F.
	if !validGrades[assessment.OverallGrade] {
		t.Errorf("OverallGrade = %q, want one of A/B/C/D/F", assessment.OverallGrade)
	}

	// Assert: manifest.Artifacts has hashes for all expected output files.
	m := readTestManifest(t, runDir)
	if len(m.Artifacts) == 0 {
		t.Fatal("manifest.Artifacts is empty after finalize")
	}
	for _, name := range []string{"assessment.json", "assessment.html"} {
		if _, ok := m.Artifacts[name]; !ok {
			t.Errorf("manifest.Artifacts missing hash for %s", name)
		}
	}

	// Assert: no summary files on the licensed path.
	if _, err := os.Stat(filepath.Join(runDir, "summary.json")); err == nil {
		t.Error("summary.json should not exist on licensed path")
	}
}

// TestAssess_EndToEnd_Unlicensed validates the full init -> run -> finalize ->
// verify pipeline for an unlicensed (HasAssess=false) user with summary output.
func TestAssess_EndToEnd_Unlicensed(t *testing.T) {
	// 1. Create temp dir and minimal config.
	tmp := t.TempDir()
	cfgFile := filepath.Join(tmp, "pipelock.yaml")
	if err := os.WriteFile(cfgFile, []byte("mode: balanced\n"), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	outDir := filepath.Join(tmp, "assessment-e2e-unlicensed")

	// 2. Init.
	runDir, err := runAssessInit(cfgFile, outDir)
	if err != nil {
		t.Fatalf("runAssessInit: %v", err)
	}

	// 3. Run.
	if err := runAssessRun(runDir, false, nil); err != nil {
		t.Fatalf("runAssessRun: %v", err)
	}

	// 4. Finalize (unlicensed, unsigned).
	opts := assessFinalizeOpts{
		HasAssess: false,
	}
	if err := runAssessFinalize(runDir, opts); err != nil {
		t.Fatalf("runAssessFinalize: %v", err)
	}

	// 5. Verify — exit code 3 (integrity verified, unsigned).
	exitCode, err := runAssessVerify(runDir, "", "")
	// runAssessVerify returns (3, nil) for unsigned-but-integrity-OK.
	if err != nil {
		t.Fatalf("runAssessVerify: unexpected error: %v", err)
	}
	if exitCode != verifyExitUnsigned {
		t.Errorf("verify exit code = %d, want %d (unsigned)", exitCode, verifyExitUnsigned)
	}

	// Assert: summary.json exists.
	summaryPath := filepath.Join(runDir, "summary.json")
	if _, err := os.Stat(summaryPath); err != nil {
		t.Fatal("summary.json not found")
	}

	// Assert: summary.html exists.
	if _, err := os.Stat(filepath.Join(runDir, "summary.html")); err != nil {
		t.Error("summary.html not found")
	}

	// Assert: NO manifest.json.sig.
	if _, err := os.Stat(filepath.Join(runDir, "manifest.json.sig")); err == nil {
		t.Error("manifest.json.sig must not exist on unlicensed path")
	}

	// Read and parse summary.json.
	summaryData, err := os.ReadFile(filepath.Clean(summaryPath))
	if err != nil {
		t.Fatalf("reading summary.json: %v", err)
	}

	var summary Summary
	if err := json.Unmarshal(summaryData, &summary); err != nil {
		t.Fatalf("parsing summary.json: %v", err)
	}

	// Assert: Signed = false.
	if summary.Signed {
		t.Error("Summary.Signed must be false on unlicensed path")
	}

	// Assert: TopFindings has at most 3 items.
	if len(summary.TopFindings) > 3 {
		t.Errorf("TopFindings has %d items, want at most 3", len(summary.TopFindings))
	}

	// Assert: no leaked fields in top_findings (no remediation, evidence, detail).
	var rawSummary map[string]json.RawMessage
	if err := json.Unmarshal(summaryData, &rawSummary); err != nil {
		t.Fatalf("parsing summary.json as raw map: %v", err)
	}

	if tfRaw, ok := rawSummary["top_findings"]; ok {
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

	// Assert: sections have no non-empty Detail field.
	if secRaw, ok := rawSummary["sections"]; ok {
		var sections []map[string]json.RawMessage
		if err := json.Unmarshal(secRaw, &sections); err != nil {
			t.Fatalf("parsing sections: %v", err)
		}
		for i, sec := range sections {
			if detailRaw, ok := sec["detail"]; ok {
				var detail string
				if err := json.Unmarshal(detailRaw, &detail); err == nil && detail != "" {
					t.Errorf("sections[%d] has non-empty detail in summary: %q", i, detail)
				}
			}
		}
	}

	// Assert: no assessment.json on the unlicensed path.
	if _, err := os.Stat(filepath.Join(runDir, "assessment.json")); err == nil {
		t.Error("assessment.json must not exist on unlicensed path")
	}
}

// TestAssess_EndToEnd_SkippedPrimitive validates grade capping and --allow-partial
// behavior when a primitive is skipped.
func TestAssess_EndToEnd_SkippedPrimitive(t *testing.T) {
	// 1. Create temp dir and minimal config.
	tmp := t.TempDir()
	cfgFile := filepath.Join(tmp, "pipelock.yaml")
	if err := os.WriteFile(cfgFile, []byte("mode: balanced\n"), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	t.Run("finalize without allow-partial fails", func(t *testing.T) {
		outDir := filepath.Join(tmp, "run-no-partial")
		runDir, err := runAssessInit(cfgFile, outDir)
		if err != nil {
			t.Fatalf("runAssessInit: %v", err)
		}

		if err := runAssessRun(runDir, false, []string{primitiveVerifyInstall}); err != nil {
			t.Fatalf("runAssessRun with skip: %v", err)
		}

		opts := assessFinalizeOpts{
			HasAssess:    false,
			AllowPartial: false,
		}
		err = runAssessFinalize(runDir, opts)
		if err == nil {
			t.Fatal("expected error finalizing with skipped primitives without --allow-partial, got nil")
		}
	})

	t.Run("finalize with allow-partial succeeds", func(t *testing.T) {
		outDir := filepath.Join(tmp, "run-with-partial")
		runDir, err := runAssessInit(cfgFile, outDir)
		if err != nil {
			t.Fatalf("runAssessInit: %v", err)
		}

		if err := runAssessRun(runDir, false, []string{primitiveVerifyInstall}); err != nil {
			t.Fatalf("runAssessRun with skip: %v", err)
		}

		opts := assessFinalizeOpts{
			HasAssess:    false,
			AllowPartial: true,
		}
		if err := runAssessFinalize(runDir, opts); err != nil {
			t.Fatalf("runAssessFinalize with AllowPartial: %v", err)
		}

		// Manifest should record allow_partial.
		m := readTestManifest(t, runDir)
		if !m.AllowPartial {
			t.Error("manifest.AllowPartial must be true when --allow-partial was used")
		}
		if m.Status != assessStatusFinalized {
			t.Errorf("Status = %q, want %q", m.Status, assessStatusFinalized)
		}

		// Grade should be capped at B when a primitive is skipped.
		summaryPath := filepath.Join(runDir, "summary.json")
		summaryData, err := os.ReadFile(filepath.Clean(summaryPath))
		if err != nil {
			t.Fatalf("reading summary.json: %v", err)
		}
		var summary Summary
		if err := json.Unmarshal(summaryData, &summary); err != nil {
			t.Fatalf("parsing summary.json: %v", err)
		}

		// Grade must be B or lower when a primitive is skipped.
		// The B cap is applied when allowPartial=true; if the raw grade is
		// already B or worse (e.g. F when deploy verification is skipped),
		// the final grade reflects the worse of the two, so we check <= B.
		allowedAfterSkip := map[string]bool{
			assessGradeB: true,
			assessGradeC: true,
			assessGradeD: true,
			assessGradeF: true,
		}
		if !allowedAfterSkip[summary.OverallGrade] {
			t.Errorf("OverallGrade = %q, want B or lower when primitive skipped", summary.OverallGrade)
		}

		// manifest.AllowPartial was already asserted above; the B cap reason
		// is recorded in CapReasons (Assessment-level only, not in Summary).
		// The Summary.GradeCap is only non-empty when the cap forced a lower
		// grade than the raw score — if the raw score is already B or worse,
		// GradeCap stays empty. Both cases are valid; we only assert the grade.
	})
}
