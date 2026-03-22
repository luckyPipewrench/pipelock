// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"testing"
)

func TestReportLayer_Active(t *testing.T) {
	var buf bytes.Buffer
	status := LayerStatus{Name: LayerLandlock, Active: true, Version: 7}
	reportLayer(&buf, status, nil)
	got := buf.String()
	if got == "" {
		t.Error("expected output for active layer")
	}
	if !contains(got, "ACTIVE") {
		t.Errorf("expected ACTIVE in output, got: %s", got)
	}
	if !contains(got, "v7") {
		t.Errorf("expected version in output, got: %s", got)
	}
}

func TestReportLayer_ActiveNoVersion(t *testing.T) {
	var buf bytes.Buffer
	status := LayerStatus{Name: LayerSeccomp, Active: true}
	reportLayer(&buf, status, nil)
	got := buf.String()
	if !contains(got, "ACTIVE") {
		t.Errorf("expected ACTIVE, got: %s", got)
	}
}

func TestReportLayer_Unavailable(t *testing.T) {
	var buf bytes.Buffer
	status := LayerStatus{Name: LayerNetNS, Reason: "userns disabled"}
	reportLayer(&buf, status, nil)
	got := buf.String()
	if !contains(got, "UNAVAILABLE") {
		t.Errorf("expected UNAVAILABLE, got: %s", got)
	}
	if !contains(got, "userns disabled") {
		t.Errorf("expected reason in output, got: %s", got)
	}
}

func TestCountActive(t *testing.T) {
	tests := []struct {
		name   string
		layers []LayerStatus
		want   int
	}{
		{"all active", []LayerStatus{{Active: true}, {Active: true}, {Active: true}}, 3},
		{"none active", []LayerStatus{{Active: false}, {Active: false}}, 0},
		{"mixed", []LayerStatus{{Active: true}, {Active: false}, {Active: true}}, 2},
		{"empty", nil, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := countActive(tt.layers...)
			if got != tt.want {
				t.Errorf("countActive = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestRemoveEnvKey_Multiple(t *testing.T) {
	env := []string{"A=1", "B=2", "A=3", "C=4"}
	result := removeEnvKey(env, "A")
	if len(result) != 2 {
		t.Errorf("expected 2 entries, got %d: %v", len(result), result)
	}
}

func TestRemoveEnvKey_NotPresent(t *testing.T) {
	env := []string{"A=1", "B=2"}
	result := removeEnvKey(env, "Z")
	if len(result) != 2 {
		t.Errorf("expected 2 entries, got %d", len(result))
	}
}

func TestResolvePolicy_Default(t *testing.T) {
	// No env var set — should return default policy.
	t.Setenv("__PIPELOCK_SANDBOX_POLICY", "")
	p := resolvePolicy("/tmp/test-workspace")
	if p.Workspace != "/tmp/test-workspace" {
		t.Errorf("workspace = %q, want /tmp/test-workspace", p.Workspace)
	}
	if len(p.AllowReadDirs) == 0 {
		t.Error("expected default AllowReadDirs")
	}
}

func TestResolvePolicy_FromJSON(t *testing.T) {
	policy := Policy{
		Workspace:     "/custom/workspace",
		AllowReadDirs: []string{"/opt/custom/"},
	}
	data, _ := json.Marshal(policy)
	t.Setenv("__PIPELOCK_SANDBOX_POLICY", string(data))

	p := resolvePolicy("/ignored")
	if p.Workspace != "/custom/workspace" {
		t.Errorf("workspace = %q, want /custom/workspace", p.Workspace)
	}
	if len(p.AllowReadDirs) != 1 || p.AllowReadDirs[0] != "/opt/custom/" {
		t.Errorf("AllowReadDirs = %v, want [/opt/custom/]", p.AllowReadDirs)
	}
}

// TestResolvePolicy_InvalidJSON is not testable in-process because
// resolvePolicy now calls os.Exit(1) on invalid JSON (fail-closed).
// This is exercised by subprocess integration tests.

func TestResolvePolicy_EmptyWorkspaceInJSON(t *testing.T) {
	policy := Policy{AllowReadDirs: []string{"/opt/"}}
	data, _ := json.Marshal(policy)
	t.Setenv("__PIPELOCK_SANDBOX_POLICY", string(data))

	p := resolvePolicy("/should-fill-in")
	if p.Workspace != "/should-fill-in" {
		t.Errorf("workspace = %q, want /should-fill-in", p.Workspace)
	}
}

func TestEncodePolicyJSON(t *testing.T) {
	p := &Policy{
		Workspace:     "/test",
		AllowReadDirs: []string{"/usr/"},
	}
	s, err := encodePolicyJSON(p)
	if err != nil {
		t.Fatalf("encodePolicyJSON: %v", err)
	}
	if s == "" {
		t.Error("expected non-empty JSON")
	}

	// Round-trip.
	var decoded Policy
	if err := json.Unmarshal([]byte(s), &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.Workspace != "/test" {
		t.Errorf("decoded workspace = %q, want /test", decoded.Workspace)
	}
}

func TestLookPathIn_RelativePath(t *testing.T) {
	// Name with slash is treated as a path, not searched in PATH.
	path, err := lookPathIn("./relative/binary", nil)
	if err != nil {
		t.Fatalf("lookPathIn: %v", err)
	}
	if path != "relative/binary" {
		t.Errorf("expected cleaned relative path, got: %s", path)
	}
}

func TestLookPathIn_FallbackPATH(t *testing.T) {
	// No PATH in env — uses fallback.
	path, err := lookPathIn("sh", []string{"HOME=/tmp"})
	if err != nil {
		t.Fatalf("lookPathIn: %v", err)
	}
	if path == "" {
		t.Error("expected non-empty path for sh")
	}
}

func TestIsInitMode_False(t *testing.T) {
	// Ensure the env var is NOT set in normal test context.
	if os.Getenv(initEnvKey) != "" {
		t.Skip("init env var is set (running inside sandbox)")
	}
	if IsInitMode() {
		t.Error("should not be in init mode")
	}
}

func TestReportLayer_UnavailableWithError(t *testing.T) {
	var buf bytes.Buffer
	status := LayerStatus{Name: LayerLandlock} // no reason set
	reportLayer(&buf, status, fmt.Errorf("kernel too old"))
	got := buf.String()
	if !contains(got, "kernel too old") {
		t.Errorf("expected error message in output, got: %s", got)
	}
}

func TestCleanupSandboxCmd_NilProcess(t *testing.T) {
	// CleanupSandboxCmd should not panic on a cmd with nil Process.
	cmd := &exec.Cmd{}
	CleanupSandboxCmd(cmd) // should be a safe no-op
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && bytesContains([]byte(s), []byte(substr))
}

func bytesContains(b, sub []byte) bool {
	return bytes.Contains(b, sub)
}
