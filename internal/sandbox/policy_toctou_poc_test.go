// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux && poc

package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const policyTOCTOUChildEnv = "__PIPELOCK_POLICY_TOCTOU_POC_CHILD"

func init() {
	if os.Getenv(policyTOCTOUChildEnv) != "1" {
		return
	}
	workspace := os.Getenv("SANDBOX_WORKSPACE")
	secretLink := os.Getenv("SECRET_LINK")
	policy := DefaultPolicy(workspace)
	policy.AllowReadDirs = append(policy.AllowReadDirs, secretLink)
	status, err := ApplyLandlock(policy)
	if err != nil || !status.Active {
		os.Exit(2)
	}
	if _, err := os.ReadFile(filepath.Join(secretLink, "id_rsa")); err == nil {
		os.Exit(42)
	}
	os.Exit(0)
}

func TestPoCPolicyMissingPathSymlinkSwapGrantsSecretRead(t *testing.T) {
	tmpHome := t.TempDir()
	sshDir := filepath.Join(tmpHome, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatalf("MkdirAll(.ssh): %v", err)
	}
	if err := os.WriteFile(filepath.Join(sshDir, "id_rsa"), []byte("secret"), 0o600); err != nil {
		t.Fatalf("WriteFile(secret): %v", err)
	}
	t.Setenv("HOME", tmpHome)

	workspace := t.TempDir()
	lateAllowPath := filepath.Join(workspace, "late-allow")
	policy := DefaultPolicy(workspace)
	policy.AllowReadDirs = append(policy.AllowReadDirs, lateAllowPath)
	err := ValidatePolicy(policy)
	if err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("ValidatePolicy() err = %v, want missing allow path rejected before symlink swap", err)
	}
	if err := os.Symlink(sshDir, lateAllowPath); err != nil {
		t.Fatalf("Symlink(late allow -> secret): %v", err)
	}
	if err := ValidatePolicy(policy); err == nil {
		t.Fatal("ValidatePolicy() accepted late symlink to secret dir")
	}
}
