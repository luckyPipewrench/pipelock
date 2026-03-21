// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestInternalRedirect_FetchProxy(t *testing.T) {
	manifest := RedirectManifest{
		Profile:    redirectProfileFetchProxy,
		Command:    []string{"curl", "https://example.com"},
		Reason:     "test redirect",
		PolicyRule: "test-rule",
	}
	manifestJSON, _ := json.Marshal(manifest)
	t.Setenv("__PIPELOCK_REDIRECT_MANIFEST", string(manifestJSON))

	cmd := internalRedirectCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{redirectProfileFetchProxy})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("redirect command failed: %v", err)
	}

	var result RedirectResult
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON output: %v\n%s", err, out.String())
	}
	if result.Status != "ok" {
		t.Errorf("status = %q, want ok", result.Status)
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

	cmd := internalRedirectCmd()
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
	if jsonErr := json.Unmarshal(out.Bytes(), &result); jsonErr == nil {
		if result.Status != "error" {
			t.Errorf("status = %q, want error", result.Status)
		}
	}
}

func TestInternalRedirect_UnknownProfile(t *testing.T) {
	manifest := RedirectManifest{Profile: "nonexistent"}
	manifestJSON, _ := json.Marshal(manifest)
	t.Setenv("__PIPELOCK_REDIRECT_MANIFEST", string(manifestJSON))

	cmd := internalRedirectCmd()
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

	cmd := internalRedirectCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{redirectProfileAppendOnlyLog})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("redirect command failed: %v", err)
	}

	var result RedirectResult
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	// Build ID should be populated (may be "unknown" in test binary).
	if result.BuildID == "" {
		t.Error("expected non-empty build_id")
	}
	// Binary hash should be populated (may be "unavailable" on non-Linux).
	if result.BinaryHash == "" {
		t.Error("expected non-empty binary_hash")
	}
}
