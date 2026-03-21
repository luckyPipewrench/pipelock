// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// buildTestBinary builds the pipelock binary for integration testing.
func buildTestBinary(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != osLinux {
		t.Skip("sandbox requires linux")
	}
	// Probe: try a minimal standalone sandbox. Skip if loopback setup
	// fails (AppArmor restricts CAP_NET_ADMIN on CI runners).
	if err := LaunchStandalone(StandaloneLaunchConfig{
		Command:   []string{"true"},
		Workspace: t.TempDir(),
	}); err != nil {
		t.Skipf("standalone sandbox unavailable: %v", err)
	}

	binary := filepath.Join(t.TempDir(), "pipelock-test")
	repoRoot := filepath.Join("..", "..")
	ctx := context.Background()
	//nolint:gosec // G204: controlled build command for integration tests
	cmd := exec.CommandContext(ctx, "go", "build", "-o", binary, "./cmd/pipelock/")
	cmd.Dir = repoRoot
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build pipelock: %v\n%s", err, out)
	}
	return binary
}

func runSandboxBinary(t *testing.T, binary string, args ...string) (string, string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, binary, args...) //nolint:gosec // G204: test binary
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

func TestIntegration_SandboxCLI_Echo(t *testing.T) {
	binary := buildTestBinary(t)
	workspace := t.TempDir()

	stdout, stderr, err := runSandboxBinary(t, binary,
		"sandbox", "--workspace", workspace, "--", "echo", "integration-test")
	if err != nil {
		t.Fatalf("sandbox echo failed: %v\nstderr: %s", err, stderr)
	}
	if !strings.Contains(stdout, "integration-test") {
		t.Errorf("expected 'integration-test' in stdout, got: %s", stdout)
	}
	if !strings.Contains(stderr, "containment") {
		t.Errorf("expected containment summary in stderr:\n%s", stderr)
	}
}

func TestIntegration_SandboxCLI_FilesystemBlocked(t *testing.T) {
	binary := buildTestBinary(t)
	workspace := t.TempDir()
	home := os.Getenv("HOME")
	if home == "" {
		t.Skip("HOME not set")
	}

	_, stderr, err := runSandboxBinary(t, binary,
		"sandbox", "--workspace", workspace, "--", "cat", filepath.Join(home, ".bashrc"))
	if err == nil {
		t.Error("expected sandbox to block home dir read")
	}
	_ = stderr // permission denied in child stderr
}

func TestIntegration_SandboxCLI_NetworkBlocked(t *testing.T) {
	binary := buildTestBinary(t)
	workspace := t.TempDir()

	_, _, err := runSandboxBinary(t, binary,
		"sandbox", "--workspace", workspace, "--",
		"python3", "-c", "import socket; socket.create_connection(('8.8.8.8', 53), timeout=2)")
	if err == nil {
		t.Error("expected direct network to be blocked")
	}
}

func TestIntegration_SandboxCLI_ConfigWorkspace(t *testing.T) {
	binary := buildTestBinary(t)
	workspace := t.TempDir()

	configPath := filepath.Join(t.TempDir(), "pipelock.yaml")
	config := "version: 1\nsandbox:\n  enabled: true\n  workspace: " + workspace + "\n"
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, err := runSandboxBinary(t, binary,
		"sandbox", "--config", configPath, "--", "pwd")
	if err != nil {
		t.Fatalf("sandbox with config failed: %v\nstderr: %s", err, stderr)
	}
	got := strings.TrimSpace(stdout)
	if got != workspace {
		t.Errorf("pwd = %q, want %q (from config)", got, workspace)
	}
}

func TestIntegration_McpProxy_Sandbox(t *testing.T) {
	binary := buildTestBinary(t)
	workspace := t.TempDir()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	input := `{"jsonrpc":"2.0","method":"initialize","id":1,"params":{}}` + "\n"

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, binary, //nolint:gosec // G204: test binary
		"mcp", "proxy", "--sandbox", "--workspace", workspace, "--", "cat")
	cmd.Stdin = strings.NewReader(input)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	_ = cmd.Run()

	stderrStr := stderr.String()
	if !strings.Contains(stderrStr, "SANDBOXED") {
		t.Errorf("expected [SANDBOXED] in stderr:\n%s", stderrStr)
	}
	if !strings.Contains(stderrStr, "containment") {
		t.Errorf("expected containment summary:\n%s", stderrStr)
	}
}

func TestIntegration_SandboxRejectsUpstream(t *testing.T) {
	binary := buildTestBinary(t)

	_, _, err := runSandboxBinary(t, binary,
		"mcp", "proxy", "--sandbox", "--upstream", "http://localhost:8080")
	if err == nil {
		t.Error("expected error for --sandbox + --upstream")
	}
}
