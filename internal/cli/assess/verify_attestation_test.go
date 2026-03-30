// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package assess

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/report/attestation"
)

// setupFinalizedRunWithAttestation creates a fully finalized, signed assessment
// run with attestation and badge artifacts.
func setupFinalizedRunWithAttestation(t *testing.T) (runDir, keystoreDir, agentName string) {
	t.Helper()

	runDir = setupCompletedRun(t)
	keystoreDir, agentName = generateTestKeys(t)

	opts := assessFinalizeOpts{
		HasAssess:   true,
		Agent:       agentName,
		KeystoreDir: keystoreDir,
		Attestation: true,
		Badge:       true,
	}
	if err := runAssessFinalize(runDir, opts); err != nil {
		t.Fatalf("runAssessFinalize (attestation): %v", err)
	}

	return runDir, keystoreDir, agentName
}

func TestAssessVerifyAttestation_SignedValid(t *testing.T) {
	runDir, keystoreDir, agentName := setupFinalizedRunWithAttestation(t)

	exitCode, err := runAssessVerifyAttestation(runDir, agentName, keystoreDir)
	if err != nil {
		t.Fatalf("runAssessVerifyAttestation: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("exit code = %d, want 0", exitCode)
	}
}

func TestAssessVerifyAttestation_MissingAttestation(t *testing.T) {
	runDir, keystoreDir, agentName := setupFinalizedRunSigned(t)

	exitCode, err := runAssessVerifyAttestation(runDir, agentName, keystoreDir)
	if err == nil {
		t.Fatal("expected error for missing attestation, got nil")
	}
	if exitCode != verifyExitUnsigned {
		t.Errorf("exit code = %d, want %d", exitCode, verifyExitUnsigned)
	}
	if !strings.Contains(err.Error(), "attestation not present") {
		t.Errorf("error should mention missing attestation, got: %v", err)
	}
}

func TestAssessVerifyAttestation_CmdRegistered(t *testing.T) {
	cmd := Cmd()
	subCmds := cmd.Commands()

	found := false
	for _, sub := range subCmds {
		if sub.Use == "verify-attestation <run-dir>" {
			found = true
			break
		}
	}
	if !found {
		t.Error("assess verify-attestation command not registered")
	}
}

func TestAssessFinalize_AttestationArtifacts(t *testing.T) {
	runDir, _, _ := setupFinalizedRunWithAttestation(t)

	for _, name := range []string{"attestation.json", "attestation.json.sig", "badge.svg"} {
		if _, err := os.Stat(filepath.Join(runDir, name)); err != nil {
			t.Fatalf("%s not found after attestation finalize: %v", name, err)
		}
	}

	data, err := os.ReadFile(filepath.Clean(filepath.Join(runDir, "attestation.json")))
	if err != nil {
		t.Fatalf("reading attestation.json: %v", err)
	}

	var att attestation.Attestation
	if err := json.Unmarshal(data, &att); err != nil {
		t.Fatalf("parsing attestation.json: %v", err)
	}
	if att.PrimaryArtifact != "assessment.json" {
		t.Errorf("PrimaryArtifact = %q, want assessment.json", att.PrimaryArtifact)
	}
	if att.BadgeText != "Pipelock Verified" {
		t.Errorf("BadgeText = %q, want Pipelock Verified", att.BadgeText)
	}

	badge, err := os.ReadFile(filepath.Clean(filepath.Join(runDir, "badge.svg")))
	if err != nil {
		t.Fatalf("reading badge.svg: %v", err)
	}
	if !bytes.Contains(badge, []byte("PIPELOCK")) {
		t.Error("badge.svg should contain badge text")
	}
}
