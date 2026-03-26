// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

const redirectStatusError = "error"

func TestBuildID_ReturnsNonEmpty(t *testing.T) {
	t.Parallel()

	id := buildID()
	if id == "" {
		t.Error("buildID() returned empty string")
	}
	// In test binaries, there's no vcs.revision, so it should fall back
	// to info.Main.Version (e.g., "(devel)" for test builds).
}

func TestBinaryHash_ReturnsNonEmpty(t *testing.T) {
	t.Parallel()

	hash := binaryHash()
	if hash == "" {
		t.Error("binaryHash() returned empty string")
	}
	// On Linux with /proc/self/exe, should return a hex string.
	// On other platforms, returns "unavailable".
}

func TestInternalRedirect_FetchProxy(t *testing.T) {
	manifest := RedirectManifest{
		Profile:    redirectProfileFetchProxy,
		Command:    []string{"curl", "https://example.com"},
		Reason:     "test redirect",
		PolicyRule: "test-rule",
	}
	manifestJSON, _ := json.Marshal(manifest)
	t.Setenv("__PIPELOCK_REDIRECT_MANIFEST", string(manifestJSON))

	cmd := InternalRedirectCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{redirectProfileFetchProxy})

	// Handlers are not yet implemented -- they fail closed.
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error (handler not yet implemented)")
	}

	var result RedirectResult
	if jsonErr := json.Unmarshal(out.Bytes(), &result); jsonErr != nil {
		t.Fatalf("invalid JSON output: %v\n%s", jsonErr, out.String())
	}
	if result.Status != redirectStatusError {
		t.Errorf("status = %q, want error (not yet implemented)", result.Status)
	}
	if result.Profile != redirectProfileFetchProxy {
		t.Errorf("profile = %q, want %s", result.Profile, redirectProfileFetchProxy)
	}
	if result.BuildID == "" {
		t.Error("expected non-empty build_id for attestation")
	}
}

func TestInternalRedirect_MissingManifest(t *testing.T) {
	t.Setenv("__PIPELOCK_REDIRECT_MANIFEST", "")

	cmd := InternalRedirectCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{redirectProfileFetchProxy})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for missing manifest")
	}

	// Should still emit JSON error result.
	var result RedirectResult
	if jsonErr := json.Unmarshal(out.Bytes(), &result); jsonErr != nil {
		t.Fatalf("expected valid JSON error result, got unmarshal error: %v (output: %s)", jsonErr, out.String())
	}
	if result.Status != redirectStatusError {
		t.Errorf("status = %q, want error", result.Status)
	}
}

func TestInternalRedirect_QuarantineWrite(t *testing.T) {
	manifest := RedirectManifest{
		Profile: redirectProfileQuarantineWrite,
		Command: []string{"write", "/tmp/test"},
		Reason:  "policy block",
	}
	manifestJSON, _ := json.Marshal(manifest)
	t.Setenv("__PIPELOCK_REDIRECT_MANIFEST", string(manifestJSON))

	cmd := InternalRedirectCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{redirectProfileQuarantineWrite})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error (not yet implemented)")
	}

	var result RedirectResult
	if jsonErr := json.Unmarshal(out.Bytes(), &result); jsonErr != nil {
		t.Fatalf("invalid JSON: %v\n%s", jsonErr, out.String())
	}
	if result.Status != redirectStatusError {
		t.Errorf("status = %q, want error", result.Status)
	}
	if result.Profile != redirectProfileQuarantineWrite {
		t.Errorf("profile = %q", result.Profile)
	}
}

func TestInternalRedirect_UnknownProfile(t *testing.T) {
	manifest := RedirectManifest{Profile: "nonexistent"}
	manifestJSON, _ := json.Marshal(manifest)
	t.Setenv("__PIPELOCK_REDIRECT_MANIFEST", string(manifestJSON))

	cmd := InternalRedirectCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"nonexistent"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for unknown profile")
	}
	if !strings.Contains(out.String(), "unknown redirect profile") {
		t.Errorf("expected unknown profile error, got: %s", out.String())
	}
}

func TestInternalRedirect_Attestation(t *testing.T) {
	manifest := RedirectManifest{
		Profile: redirectProfileAppendOnlyLog,
		Command: []string{"echo", "test"},
		Reason:  "attestation test",
	}
	manifestJSON, _ := json.Marshal(manifest)
	t.Setenv("__PIPELOCK_REDIRECT_MANIFEST", string(manifestJSON))

	cmd := InternalRedirectCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{redirectProfileAppendOnlyLog})

	// Handler fails closed (not yet implemented), but should still emit JSON with attestation.
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error (handler not yet implemented)")
	}

	var result RedirectResult
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if result.BuildID == "" {
		t.Error("expected non-empty build_id")
	}
	if result.BinaryHash == "" {
		t.Error("expected non-empty binary_hash")
	}
}
