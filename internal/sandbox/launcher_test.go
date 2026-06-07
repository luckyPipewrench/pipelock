// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const (
	// sandboxLaunchTimeout bounds a sandbox child's launch+wait in tests via
	// LaunchConfig.Ctx, which kills the child group on expiry. A kernel that
	// reports namespace/Landlock support but then blocks during child setup
	// (broken or partial primitives on some CI runners) would otherwise hang
	// cmd.Wait() until the whole-suite 10-minute deadline. The echo/cat-class
	// workloads here finish in well under a second; this ceiling only turns a
	// kernel-level block into a fast, clear failure, never paces a healthy run.
	sandboxLaunchTimeout = 30 * time.Second

	// sandboxWatchdogGrace makes the test-side watchdog slightly outlast the
	// ctx timeout, so the ctx-kill path (which yields a real Wait error) wins
	// on a child-side block. The watchdog itself only matters for a parent-side
	// block before the child starts, where ctx cannot help.
	sandboxWatchdogGrace = 5 * time.Second
)

// requireSandboxPrimitives skips when the kernel lacks the namespace/Landlock
// primitives the launch tests exercise, so a genuinely unsupported environment
// is reported as a skip-with-reason rather than a launch that errors (non-strict
// LaunchSandboxed returns ErrUnavailable without user namespaces) or blocks.
func requireSandboxPrimitives(t *testing.T) {
	t.Helper()
	if runtime.GOOS != osLinux {
		t.Skip("sandbox requires linux")
	}
	caps := Detect()
	if caps.LandlockABI <= 0 || !caps.UserNamespaces {
		t.Skipf("sandbox primitives unavailable (Landlock ABI=%d, user namespaces=%v); skipping launch test",
			caps.LandlockABI, caps.UserNamespaces)
	}
}

// launchSandboxedToCompletion launches cfg and waits for the child to exit,
// bounded by sandboxLaunchTimeout. cfg.Ctx is set so the child group is killed
// if the child itself blocks; the watchdog additionally covers a parent-side
// block before the child starts. On timeout it fails the test fast instead of
// letting a stuck launch ride out the suite deadline. Returns the child's Wait
// error (or the LaunchSandboxed error) for the caller to assert on.
func launchSandboxedToCompletion(t *testing.T, cfg LaunchConfig) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), sandboxLaunchTimeout)
	defer cancel()
	cfg.Ctx = ctx

	done := make(chan error, 1)
	go func() {
		cmd, err := LaunchSandboxed(cfg)
		if err != nil {
			done <- err
			return
		}
		done <- cmd.Wait()
	}()

	select {
	case err := <-done:
		return err
	case <-time.After(sandboxLaunchTimeout + sandboxWatchdogGrace):
		cancel()
		t.Fatalf("sandbox launch did not complete within %s; failing fast instead of hanging (kernel namespace/Landlock primitives may be broken)",
			sandboxLaunchTimeout+sandboxWatchdogGrace)
		return nil // unreachable; t.Fatalf stops the test
	}
}

func launchSandboxedStarted(t *testing.T, cfg LaunchConfig) (*exec.Cmd, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), sandboxLaunchTimeout)
	cfg.Ctx = ctx

	type launchResult struct {
		cmd *exec.Cmd
		err error
	}
	done := make(chan launchResult, 1)
	go func() {
		cmd, err := LaunchSandboxed(cfg)
		done <- launchResult{cmd: cmd, err: err}
	}()

	select {
	case res := <-done:
		if res.err != nil {
			cancel()
			t.Fatalf("LaunchSandboxed: %v", res.err)
		}
		return res.cmd, cancel
	case <-time.After(sandboxLaunchTimeout + sandboxWatchdogGrace):
		cancel()
		t.Fatalf("sandbox launch did not start within %s; failing fast instead of hanging (kernel namespace/Landlock primitives may be broken)",
			sandboxLaunchTimeout+sandboxWatchdogGrace)
		return nil, cancel // unreachable; t.Fatalf stops the test
	}
}

func TestLaunchSandboxed_EchoCommand(t *testing.T) {
	requireSandboxPrimitives(t)
	workspace := t.TempDir()

	var stdout, stderr bytes.Buffer
	if err := launchSandboxedToCompletion(t, LaunchConfig{
		Command:   []string{"echo", "hello-from-sandbox"},
		Workspace: workspace,
		Stdout:    &stdout,
		Stderr:    &stderr,
	}); err != nil {
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
	requireSandboxPrimitives(t)
	workspace := t.TempDir()

	// Verify network isolation by checking /proc/self/net/dev - in an
	// isolated namespace only loopback exists (2 header lines + 1 lo line).
	// No external tools or network access needed.
	var stdout, stderr bytes.Buffer
	if err := launchSandboxedToCompletion(t, LaunchConfig{
		Command:   []string{"cat", "/proc/self/net/dev"},
		Workspace: workspace,
		Stdout:    &stdout,
		Stderr:    &stderr,
	}); err != nil {
		t.Fatalf("child exited with error: %v\nstderr: %s", err, stderr.String())
	}

	// In a network namespace, only "lo" interface should exist.
	// Host would have eth0/wlan0/etc.
	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "Inter") || strings.HasPrefix(trimmed, "face") {
			continue // skip headers
		}
		if !strings.HasPrefix(trimmed, "lo:") {
			t.Errorf("unexpected network interface in sandbox: %s", trimmed)
		}
	}
}

func TestLaunchSandboxed_FilesystemBlocked(t *testing.T) {
	requireSandboxPrimitives(t)
	home := os.Getenv("HOME")
	if home == "" {
		t.Skip("HOME not set")
	}
	workspace := t.TempDir()

	// Try to read home directory from inside sandbox.
	var stdout, stderr bytes.Buffer
	err := launchSandboxedToCompletion(t, LaunchConfig{
		Command:   []string{"ls", home},
		Workspace: workspace,
		Stdout:    &stdout,
		Stderr:    &stderr,
	})
	if err == nil {
		t.Fatal("expected child to fail (home dir should be blocked by Landlock)")
	}
}

func TestLaunchSandboxed_WorkspaceWritable(t *testing.T) {
	requireSandboxPrimitives(t)
	workspace := t.TempDir()

	var stdout, stderr bytes.Buffer
	if err := launchSandboxedToCompletion(t, LaunchConfig{
		Command:   []string{"sh", "-c", "echo test-content > " + filepath.Join(workspace, "output.txt") + " && cat " + filepath.Join(workspace, "output.txt")},
		Workspace: workspace,
		Stdout:    &stdout,
		Stderr:    &stderr,
	}); err != nil {
		t.Fatalf("child exited with error: %v\nstderr: %s", err, stderr.String())
	}

	if !strings.Contains(stdout.String(), "test-content") {
		t.Errorf("expected 'test-content' in output, got: %s", stdout.String())
	}
}

func TestLaunchSandboxed_SyntheticHOME(t *testing.T) {
	requireSandboxPrimitives(t)
	workspace := t.TempDir()

	var stdout, stderr bytes.Buffer
	if err := launchSandboxedToCompletion(t, LaunchConfig{
		Command:   []string{"sh", "-c", "echo $HOME"},
		Workspace: workspace,
		Stdout:    &stdout,
		Stderr:    &stderr,
	}); err != nil {
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
	requireSandboxPrimitives(t)
	// Set a secret that should NOT leak into the sandbox.
	// Split to avoid self-scan false positive.
	t.Setenv("OPENAI_API_KEY", "sk-test"+"-not-real-key")
	workspace := t.TempDir()

	var stdout, stderr bytes.Buffer
	if err := launchSandboxedToCompletion(t, LaunchConfig{
		Command:   []string{"sh", "-c", "echo OPENAI_API_KEY=$OPENAI_API_KEY"},
		Workspace: workspace,
		Stdout:    &stdout,
		Stderr:    &stderr,
	}); err != nil {
		t.Fatalf("child exited with error: %v\nstderr: %s", err, stderr.String())
	}

	// The env var should be empty in the sandbox.
	if strings.Contains(stdout.String(), "sk-test") {
		t.Error("OPENAI_API_KEY leaked into sandbox!")
	}
}

func TestLaunchSandboxed_ExtraEnvPassedThrough(t *testing.T) {
	requireSandboxPrimitives(t)
	workspace := t.TempDir()

	var stdout, stderr bytes.Buffer
	if err := launchSandboxedToCompletion(t, LaunchConfig{
		Command:   []string{"sh", "-c", "echo MY_VAR=$MY_VAR"},
		Workspace: workspace,
		ExtraEnv:  []string{"MY_VAR=hello"},
		Stdout:    &stdout,
		Stderr:    &stderr,
	}); err != nil {
		t.Fatalf("child exited with error: %v\nstderr: %s", err, stderr.String())
	}

	if !strings.Contains(stdout.String(), "MY_VAR=hello") {
		t.Errorf("expected MY_VAR=hello, got: %s", stdout.String())
	}
}

func TestLaunchSandboxed_ChildCleanup(t *testing.T) {
	requireSandboxPrimitives(t)
	workspace := t.TempDir()

	// Launch a long-running child, then kill it via process signal.
	// This verifies the child process is cleanly terminable.
	// (True Pdeathsig testing requires an intermediate parent process
	// which is tested end-to-end in the private security test suite.)
	var stderr bytes.Buffer
	cmd, cancel := launchSandboxedStarted(t, LaunchConfig{
		Command:   []string{"sleep", "300"},
		Workspace: workspace,
		Stderr:    &stderr,
	})
	defer cancel()

	// Kill the child process.
	if cmd.Process != nil {
		_ = cmd.Process.Signal(os.Kill)
	}

	err := cmd.Wait()
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
	if runtime.GOOS == osLinux || runtime.GOOS == "darwin" {
		t.Skip("testing non-linux/non-darwin behavior")
	}
	_, err := LaunchSandboxed(LaunchConfig{
		Command:   []string{"echo", "test"},
		Workspace: t.TempDir(),
	})
	if err == nil {
		t.Error("expected error on unsupported platform")
	}
	if !errors.Is(err, ErrUnavailable) {
		t.Errorf("expected ErrUnavailable, got: %v", err)
	}
}

func TestLaunchSandboxed_LayerReporting(t *testing.T) {
	requireSandboxPrimitives(t)
	workspace := t.TempDir()

	var stderr bytes.Buffer
	if err := launchSandboxedToCompletion(t, LaunchConfig{
		Command:   []string{"true"},
		Workspace: workspace,
		Stderr:    &stderr,
	}); err != nil {
		t.Errorf("child exited with error: %v", err)
	}

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
