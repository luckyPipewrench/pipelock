// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestLaunchSandboxed_EchoCommand(t *testing.T) {
	if runtime.GOOS != osLinux {
		t.Skip("sandbox requires linux")
	}
	workspace := t.TempDir()

	var stdout, stderr bytes.Buffer
	cmd, err := LaunchSandboxed(LaunchConfig{
		Command:   []string{"echo", "hello-from-sandbox"},
		Workspace: workspace,
		Stdout:    &stdout,
		Stderr:    &stderr,
	})
	if err != nil {
		t.Fatalf("LaunchSandboxed: %v", err)
	}

	if err := cmd.Wait(); err != nil {
		t.Fatalf("child exited with error: %v\nstderr: %s", err, stderr.String())
	}

	if !strings.Contains(stdout.String(), "hello-from-sandbox") {
		t.Errorf("expected output 'hello-from-sandbox', got: %s", stdout.String())
	}

	// Verify sandbox layer reporting on stderr.
	stderrStr := stderr.String()
	if !strings.Contains(stderrStr, "[sandbox]") {
		t.Errorf("expected sandbox status on stderr, got: %s", stderrStr)
	}
}

func TestLaunchSandboxed_NetworkBlocked(t *testing.T) {
	if runtime.GOOS != osLinux {
		t.Skip("sandbox requires linux")
	}
	workspace := t.TempDir()

	var stdout, stderr bytes.Buffer
	cmd, err := LaunchSandboxed(LaunchConfig{
		Command:   []string{"python3", "-c", "import socket; socket.create_connection(('8.8.8.8', 53), timeout=2)"},
		Workspace: workspace,
		Stdout:    &stdout,
		Stderr:    &stderr,
	})
	if err != nil {
		t.Fatalf("LaunchSandboxed: %v", err)
	}

	err = cmd.Wait()
	if err == nil {
		t.Fatal("expected child to fail (network should be blocked)")
	}
	// Python exits with code 1 on connection error — that's what we want.
}

func TestLaunchSandboxed_FilesystemBlocked(t *testing.T) {
	if runtime.GOOS != osLinux {
		t.Skip("sandbox requires linux")
	}
	home := os.Getenv("HOME")
	if home == "" {
		t.Skip("HOME not set")
	}
	workspace := t.TempDir()

	// Try to read home directory from inside sandbox.
	var stdout, stderr bytes.Buffer
	cmd, err := LaunchSandboxed(LaunchConfig{
		Command:   []string{"ls", home},
		Workspace: workspace,
		Stdout:    &stdout,
		Stderr:    &stderr,
	})
	if err != nil {
		t.Fatalf("LaunchSandboxed: %v", err)
	}

	err = cmd.Wait()
	if err == nil {
		t.Fatal("expected child to fail (home dir should be blocked by Landlock)")
	}
}

func TestLaunchSandboxed_WorkspaceWritable(t *testing.T) {
	if runtime.GOOS != osLinux {
		t.Skip("sandbox requires linux")
	}
	workspace := t.TempDir()

	var stdout, stderr bytes.Buffer
	cmd, err := LaunchSandboxed(LaunchConfig{
		Command:   []string{"sh", "-c", "echo test-content > " + filepath.Join(workspace, "output.txt") + " && cat " + filepath.Join(workspace, "output.txt")},
		Workspace: workspace,
		Stdout:    &stdout,
		Stderr:    &stderr,
	})
	if err != nil {
		t.Fatalf("LaunchSandboxed: %v", err)
	}

	if err := cmd.Wait(); err != nil {
		t.Fatalf("child exited with error: %v\nstderr: %s", err, stderr.String())
	}

	if !strings.Contains(stdout.String(), "test-content") {
		t.Errorf("expected 'test-content' in output, got: %s", stdout.String())
	}
}

func TestLaunchSandboxed_SyntheticHOME(t *testing.T) {
	if runtime.GOOS != osLinux {
		t.Skip("sandbox requires linux")
	}
	workspace := t.TempDir()

	var stdout, stderr bytes.Buffer
	cmd, err := LaunchSandboxed(LaunchConfig{
		Command:   []string{"sh", "-c", "echo $HOME"},
		Workspace: workspace,
		Stdout:    &stdout,
		Stderr:    &stderr,
	})
	if err != nil {
		t.Fatalf("LaunchSandboxed: %v", err)
	}

	if err := cmd.Wait(); err != nil {
		t.Fatalf("child exited with error: %v\nstderr: %s", err, stderr.String())
	}

	home := strings.TrimSpace(stdout.String())
	if !strings.Contains(home, "pipelock-sandbox") {
		t.Errorf("HOME should be synthetic sandbox dir, got: %s", home)
	}
	if home == os.Getenv("HOME") {
		t.Error("HOME should NOT be the real home directory")
	}
}

func TestLaunchSandboxed_SecretsDropped(t *testing.T) {
	if runtime.GOOS != osLinux {
		t.Skip("sandbox requires linux")
	}
	// Set a secret that should NOT leak into the sandbox.
	t.Setenv("OPENAI_API_KEY", "sk-test-secret-key")
	workspace := t.TempDir()

	var stdout, stderr bytes.Buffer
	cmd, err := LaunchSandboxed(LaunchConfig{
		Command:   []string{"sh", "-c", "echo OPENAI_API_KEY=$OPENAI_API_KEY"},
		Workspace: workspace,
		Stdout:    &stdout,
		Stderr:    &stderr,
	})
	if err != nil {
		t.Fatalf("LaunchSandboxed: %v", err)
	}

	if err := cmd.Wait(); err != nil {
		t.Fatalf("child exited with error: %v\nstderr: %s", err, stderr.String())
	}

	// The env var should be empty in the sandbox.
	if strings.Contains(stdout.String(), "sk-test-secret-key") {
		t.Error("OPENAI_API_KEY leaked into sandbox!")
	}
}

func TestLaunchSandboxed_ExtraEnvPassedThrough(t *testing.T) {
	if runtime.GOOS != osLinux {
		t.Skip("sandbox requires linux")
	}
	workspace := t.TempDir()

	var stdout, stderr bytes.Buffer
	cmd, err := LaunchSandboxed(LaunchConfig{
		Command:   []string{"sh", "-c", "echo MY_VAR=$MY_VAR"},
		Workspace: workspace,
		ExtraEnv:  []string{"MY_VAR=hello"},
		Stdout:    &stdout,
		Stderr:    &stderr,
	})
	if err != nil {
		t.Fatalf("LaunchSandboxed: %v", err)
	}

	if err := cmd.Wait(); err != nil {
		t.Fatalf("child exited with error: %v\nstderr: %s", err, stderr.String())
	}

	if !strings.Contains(stdout.String(), "MY_VAR=hello") {
		t.Errorf("expected MY_VAR=hello, got: %s", stdout.String())
	}
}

func TestLaunchSandboxed_ChildCleanup(t *testing.T) {
	if runtime.GOOS != osLinux {
		t.Skip("sandbox requires linux")
	}
	workspace := t.TempDir()

	// Launch a long-running child, then kill it via process signal.
	// This verifies the child process is cleanly terminable.
	// (True Pdeathsig testing requires an intermediate parent process
	// which is tested end-to-end in the private security test suite.)
	var stderr bytes.Buffer
	cmd, err := LaunchSandboxed(LaunchConfig{
		Command:   []string{"sleep", "300"},
		Workspace: workspace,
		Stderr:    &stderr,
	})
	if err != nil {
		t.Fatalf("LaunchSandboxed: %v", err)
	}

	// Give child time to start.
	time.Sleep(100 * time.Millisecond)

	// Kill the child process.
	if cmd.Process != nil {
		_ = cmd.Process.Signal(os.Kill)
	}

	err = cmd.Wait()
	if err == nil {
		t.Error("expected child to exit with error after kill")
	}
}

func TestLaunchSandboxed_RejectsInvalidWorkspace(t *testing.T) {
	if runtime.GOOS != osLinux {
		t.Skip("sandbox requires linux")
	}
	_, err := LaunchSandboxed(LaunchConfig{
		Command:   []string{"echo", "test"},
		Workspace: "/",
	})
	if err == nil {
		t.Error("expected error for / workspace")
	}
}

func TestLaunchSandboxed_NonLinuxReturnsError(t *testing.T) {
	if runtime.GOOS == osLinux {
		t.Skip("testing non-linux behavior")
	}
	_, err := LaunchSandboxed(LaunchConfig{
		Command:   []string{"echo", "test"},
		Workspace: t.TempDir(),
	})
	if err == nil {
		t.Error("expected error on non-linux")
	}
	if !errors.Is(err, ErrUnavailable) {
		t.Errorf("expected ErrUnavailable, got: %v", err)
	}
}

func TestLaunchSandboxed_LayerReporting(t *testing.T) {
	if runtime.GOOS != osLinux {
		t.Skip("sandbox requires linux")
	}
	workspace := t.TempDir()

	var stderr bytes.Buffer
	cmd, err := LaunchSandboxed(LaunchConfig{
		Command:   []string{"true"},
		Workspace: workspace,
		Stderr:    &stderr,
	})
	if err != nil {
		t.Fatalf("LaunchSandboxed: %v", err)
	}
	_ = cmd.Wait()

	stderrStr := stderr.String()
	// Should report at least filesystem and network layers.
	if !strings.Contains(stderrStr, "filesystem") {
		t.Errorf("expected filesystem layer report in stderr:\n%s", stderrStr)
	}
	if !strings.Contains(stderrStr, "network") {
		t.Errorf("expected network layer report in stderr:\n%s", stderrStr)
	}
	if !strings.Contains(stderrStr, "containment") {
		t.Errorf("expected containment summary in stderr:\n%s", stderrStr)
	}
}

func TestIsInitMode(t *testing.T) {
	if IsInitMode() {
		t.Error("should not be in init mode during tests")
	}
}

func TestRemoveEnvKey(t *testing.T) {
	env := []string{"FOO=bar", "BAZ=qux", "FOO=override"}
	result := removeEnvKey(env, "FOO")
	if len(result) != 1 || result[0] != "BAZ=qux" {
		t.Errorf("expected [BAZ=qux], got: %v", result)
	}
}

func TestLookPathIn_AbsolutePath(t *testing.T) {
	path, err := lookPathIn("/bin/sh", nil)
	if err != nil {
		t.Fatalf("lookPathIn: %v", err)
	}
	if path != "/bin/sh" {
		t.Errorf("expected /bin/sh, got: %s", path)
	}
}

func TestLookPathIn_SearchPATH(t *testing.T) {
	env := []string{"PATH=/usr/bin:/bin"}
	path, err := lookPathIn("sh", env)
	if err != nil {
		t.Fatalf("lookPathIn: %v", err)
	}
	if path == "" {
		t.Error("expected non-empty path for sh")
	}
}

func TestLookPathIn_NotFound(t *testing.T) {
	env := []string{"PATH=/nonexistent"}
	_, err := lookPathIn("nonexistent-binary-xyz", env)
	if err == nil {
		t.Error("expected error for missing binary")
	}
	if !errors.Is(err, exec.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got: %v", err)
	}
}

func TestDetect_ReportsCapabilities(t *testing.T) {
	if runtime.GOOS != osLinux {
		t.Skip("detection requires linux")
	}
	caps := Detect()
	summary := caps.Summary()
	if summary == "" {
		t.Error("expected non-empty summary")
	}
	// On our test machine (Fedora 43), all capabilities should be available.
	if caps.LandlockABI <= 0 {
		t.Logf("Landlock unavailable (ABI: %d)", caps.LandlockABI)
	}
	if !caps.UserNamespaces {
		t.Logf("User namespaces unavailable")
	}
	if !caps.Seccomp {
		t.Logf("Seccomp unavailable")
	}
	t.Logf("Capabilities: %s", summary)
}
