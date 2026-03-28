// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package assess

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// setupFinalizedRunSigned creates a fully finalized, signed assessment run.
// Returns the run directory, keystore directory, and agent name.
func setupFinalizedRunSigned(t *testing.T) (runDir, keystoreDir, agentName string) {
	t.Helper()

	runDir = setupCompletedRun(t)
	keystoreDir, agentName = generateTestKeys(t)

	opts := assessFinalizeOpts{
		HasAssess:   true,
		Agent:       agentName,
		KeystoreDir: keystoreDir,
	}
	if err := runAssessFinalize(runDir, opts); err != nil {
		t.Fatalf("runAssessFinalize (signed): %v", err)
	}

	return runDir, keystoreDir, agentName
}

// setupFinalizedRunUnsigned creates a fully finalized, unsigned assessment run.
func setupFinalizedRunUnsigned(t *testing.T) string {
	t.Helper()

	runDir := setupCompletedRun(t)

	opts := assessFinalizeOpts{
		HasAssess: false,
	}
	if err := runAssessFinalize(runDir, opts); err != nil {
		t.Fatalf("runAssessFinalize (unsigned): %v", err)
	}

	return runDir
}

func TestAssessVerify_SignedValid(t *testing.T) {
	runDir, keystoreDir, agentName := setupFinalizedRunSigned(t)

	exitCode, err := runAssessVerify(runDir, agentName, keystoreDir)
	if err != nil {
		t.Fatalf("runAssessVerify: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("exit code = %d, want 0", exitCode)
	}
}

func TestAssessVerify_UnsignedIntegrityOK(t *testing.T) {
	runDir := setupFinalizedRunUnsigned(t)

	exitCode, err := runAssessVerify(runDir, "", "")
	// runAssessVerify returns (3, nil) for unsigned-but-OK.
	if err != nil {
		t.Fatalf("runAssessVerify: unexpected error: %v", err)
	}
	if exitCode != verifyExitUnsigned {
		t.Errorf("exit code = %d, want %d (unsigned)", exitCode, verifyExitUnsigned)
	}
}

func TestAssessVerify_TamperedArtifact(t *testing.T) {
	runDir := setupFinalizedRunUnsigned(t)

	// Find an artifact and tamper with it.
	m := readTestManifest(t, runDir)
	if len(m.Artifacts) == 0 {
		t.Fatal("no artifacts in manifest")
	}

	// Tamper with the first artifact found.
	var firstArtifact string
	for name := range m.Artifacts {
		firstArtifact = name
		break
	}

	artifactPath := filepath.Join(runDir, firstArtifact)
	if err := os.WriteFile(artifactPath, []byte("tampered content"), 0o600); err != nil {
		t.Fatalf("tampering artifact: %v", err)
	}

	exitCode, err := runAssessVerify(runDir, "", "")
	if err == nil {
		t.Fatal("expected error for tampered artifact, got nil")
	}
	if exitCode != verifyExitTamperedArtifact {
		t.Errorf("exit code = %d, want %d (tampered)", exitCode, verifyExitTamperedArtifact)
	}
	if !strings.Contains(err.Error(), "integrity check failed") {
		t.Errorf("error should mention 'integrity check failed', got: %v", err)
	}
}

func TestAssessVerify_BadSignature(t *testing.T) {
	runDir, keystoreDir, agentName := setupFinalizedRunSigned(t)

	// Generate a different key pair and sign unrelated content with it,
	// producing a wrong-but-validly-formatted signature.
	_, badPrivKey, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generating bad key pair: %v", err)
	}

	// Sign something other than the manifest so the signature is wrong.
	badSig, err := signing.SignFile(filepath.Join(runDir, "verify.txt"), badPrivKey)
	if err != nil {
		t.Fatalf("signing with bad key: %v", err)
	}

	sigPath := filepath.Join(runDir, "manifest.json.sig")
	if err := signing.SaveSignature(badSig, sigPath); err != nil {
		t.Fatalf("saving bad signature: %v", err)
	}

	exitCode, err := runAssessVerify(runDir, agentName, keystoreDir)
	if err == nil {
		t.Fatal("expected error for bad signature, got nil")
	}
	if exitCode != verifyExitBadSignature {
		t.Errorf("exit code = %d, want %d (bad sig)", exitCode, verifyExitBadSignature)
	}
	if !strings.Contains(err.Error(), "signature verification failed") {
		t.Errorf("error should mention 'signature verification failed', got: %v", err)
	}
}

func TestAssessVerify_NotFinalized(t *testing.T) {
	// Use an initialized (not finalized) run.
	runDir, _ := initTestRun(t)

	exitCode, err := runAssessVerify(runDir, "", "")
	if err == nil {
		t.Fatal("expected error for non-finalized status, got nil")
	}
	if exitCode != verifyExitTamperedArtifact {
		t.Errorf("exit code = %d, want 1", exitCode)
	}
	if !strings.Contains(err.Error(), "initialized") {
		t.Errorf("error should mention current status, got: %v", err)
	}
}

func TestAssessVerify_MissingManifest(t *testing.T) {
	tmp := t.TempDir()

	exitCode, err := runAssessVerify(tmp, "", "")
	if err == nil {
		t.Fatal("expected error for missing manifest")
	}
	if exitCode != 1 {
		t.Errorf("exit code = %d, want 1", exitCode)
	}
}

func TestAssessStatus_ShowsInfo(t *testing.T) {
	runDir, _ := initTestRun(t)

	var buf bytes.Buffer
	cmd := assessStatusCmd()
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{runDir})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("assessStatusCmd: %v", err)
	}

	output := buf.String()
	m := readTestManifest(t, runDir)

	if !strings.Contains(output, m.RunID) {
		t.Errorf("output should contain run ID %q, got:\n%s", m.RunID, output)
	}
	if !strings.Contains(output, assessStatusInitialized) {
		t.Errorf("output should contain status %q, got:\n%s", assessStatusInitialized, output)
	}
}

func TestAssessStatus_FinalizedShowsArtifacts(t *testing.T) {
	runDir := setupFinalizedRunUnsigned(t)

	var buf bytes.Buffer
	cmd := assessStatusCmd()
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{runDir})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("assessStatusCmd: %v", err)
	}

	output := buf.String()

	if !strings.Contains(output, assessStatusFinalized) {
		t.Errorf("output should contain %q, got:\n%s", assessStatusFinalized, output)
	}
	// Unsigned run: signed = false.
	if !strings.Contains(output, "false") {
		t.Errorf("output should show signed=false for unsigned run, got:\n%s", output)
	}
}

func TestAssessStatus_SignedShowsSigned(t *testing.T) {
	runDir, _, _ := setupFinalizedRunSigned(t)

	var buf bytes.Buffer
	cmd := assessStatusCmd()
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{runDir})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("assessStatusCmd: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "true") {
		t.Errorf("output should show signed=true for signed run, got:\n%s", output)
	}
}

func TestAssessStatus_JSONOutput(t *testing.T) {
	runDir, _ := initTestRun(t)

	var buf bytes.Buffer
	cmd := assessStatusCmd()
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{runDir, "--json"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("assessStatusCmd --json: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, `"run_id"`) {
		t.Errorf("JSON output should contain run_id, got:\n%s", output)
	}
	if !strings.Contains(output, `"status"`) {
		t.Errorf("JSON output should contain status, got:\n%s", output)
	}
}

func TestAssessVerify_CmdRegistered(t *testing.T) {
	cmd := Cmd()
	subCmds := cmd.Commands()

	foundVerify := false
	foundStatus := false
	foundVerifyAttestation := false
	for _, sub := range subCmds {
		switch sub.Use {
		case "verify <run-dir>":
			foundVerify = true
		case "status <run-dir>":
			foundStatus = true
		case "verify-attestation <run-dir>":
			foundVerifyAttestation = true
		}
	}

	if !foundVerify {
		t.Error("assess verify command not registered")
	}
	if !foundStatus {
		t.Error("assess status command not registered")
	}
	if !foundVerifyAttestation {
		t.Error("assess verify-attestation command not registered")
	}
}
