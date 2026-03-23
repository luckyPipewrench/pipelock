// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sandbox

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

// Landlock tests use subprocess execution because Landlock restrictions are
// permanent and inherited. We cannot apply Landlock in the test process
// itself or all subsequent tests would be restricted.
//
// Pattern: build a test helper, exec it with Landlock applied via env flag.

const landlockTestEnv = "__SANDBOX_LANDLOCK_TEST"

func TestMain(m *testing.M) {
	// Sandbox re-exec entry point. Must be checked FIRST because the
	// re-exec'd child is the test binary itself. Without this, the child
	// would run the full test suite recursively.
	if IsInitMode() {
		RunInit()
		return // RunInit calls syscall.Exec, so this is unreachable on success
	}
	if IsStandaloneInitMode() {
		RunStandaloneInit()
		return
	}

	// Landlock test child entry point.
	if op := os.Getenv(landlockTestEnv); op != "" {
		runLandlockTestChild(op)
		return
	}
	os.Exit(m.Run())
}

// runLandlockTestChild is executed in the sandboxed child process.
func runLandlockTestChild(op string) {
	workspace := os.Getenv("SANDBOX_WORKSPACE")
	if workspace == "" {
		_, _ = os.Stderr.WriteString("SANDBOX_WORKSPACE not set\n")
		os.Exit(1)
	}

	policy := DefaultPolicy(workspace)
	status, err := ApplyLandlock(policy)
	if err != nil {
		_, _ = os.Stderr.WriteString("landlock: " + err.Error() + "\n")
		os.Exit(2)
	}
	if !status.Active {
		_, _ = os.Stderr.WriteString("landlock not active: " + status.Reason + "\n")
		os.Exit(2)
	}

	switch op {
	case "read-home":
		home := os.Getenv("REAL_HOME")
		_, err := os.ReadDir(home)
		if err != nil {
			os.Exit(0) // expected: blocked
		}
		os.Exit(1) // bad: should have been blocked

	case "read-ssh":
		home := os.Getenv("REAL_HOME")
		_, err := os.ReadFile(filepath.Clean(filepath.Join(home, ".ssh", "id_rsa")))
		if err != nil {
			os.Exit(0) // expected: blocked
		}
		os.Exit(1) // bad: should have been blocked

	case "write-workspace":
		err := os.WriteFile(filepath.Join(workspace, "test-write.txt"), []byte("hello"), 0o600)
		if err != nil {
			_, _ = os.Stderr.WriteString("write workspace: " + err.Error() + "\n")
			os.Exit(1)
		}
		os.Exit(0) // expected: allowed

	case "write-outside":
		home := os.Getenv("REAL_HOME")
		err := os.WriteFile(filepath.Join(home, "sandbox-escape.txt"), []byte("bad"), 0o600)
		if err != nil {
			os.Exit(0) // expected: blocked
		}
		// Clean up if somehow it succeeded.
		_ = os.Remove(filepath.Join(home, "sandbox-escape.txt"))
		os.Exit(1) // bad: should have been blocked

	case "read-usr":
		_, err := os.ReadDir("/usr/bin")
		if err != nil {
			_, _ = os.Stderr.WriteString("read /usr/bin: " + err.Error() + "\n")
			os.Exit(1)
		}
		os.Exit(0) // expected: allowed

	case "read-etc-resolv":
		_, err := os.ReadFile("/etc/resolv.conf")
		if err != nil {
			_, _ = os.Stderr.WriteString("read /etc/resolv.conf: " + err.Error() + "\n")
			os.Exit(1)
		}
		os.Exit(0) // expected: allowed

	case "write-dev-null":
		f, err := os.OpenFile("/dev/null", os.O_WRONLY, 0)
		if err != nil {
			_, _ = os.Stderr.WriteString("open /dev/null: " + err.Error() + "\n")
			os.Exit(1)
		}
		_ = f.Close()
		os.Exit(0) // expected: allowed

	case "read-etc-passwd":
		_, err := os.ReadFile("/etc/passwd")
		if err != nil {
			_, _ = os.Stderr.WriteString("read /etc/passwd: " + err.Error() + "\n")
			os.Exit(1)
		}
		os.Exit(0) // expected: allowed

	case "exec-workspace":
		// Create a script in workspace and try to execute it.
		script := filepath.Join(workspace, "test-script.sh")
		err := os.WriteFile(script, []byte("#!/bin/sh\necho ok\n"), 0o700) //nolint:gosec // test script
		if err != nil {
			_, _ = os.Stderr.WriteString("write script: " + err.Error() + "\n")
			os.Exit(1)
		}
		ctx := context.Background()
		cmd := exec.CommandContext(ctx, filepath.Clean(script)) //nolint:gosec // G204: intentionally testing exec from writable workspace
		out, err := cmd.Output()
		if err != nil {
			_, _ = os.Stderr.WriteString("exec script: " + err.Error() + "\n")
			os.Exit(1)
		}
		if strings.TrimSpace(string(out)) != "ok" {
			os.Exit(1)
		}
		os.Exit(0) // expected: allowed

	case "inherited-child-blocked":
		// Spawn a grandchild (shell) that tries to read HOME.
		// Landlock domain is inherited across fork+exec, so the
		// grandchild should also be blocked.
		home := os.Getenv("REAL_HOME")
		ctx := context.Background()
		cmd := exec.CommandContext(ctx, "ls", filepath.Clean(home)) //nolint:gosec // G204: intentionally testing inherited Landlock with controlled path
		err := cmd.Run()
		if err != nil {
			os.Exit(0) // expected: grandchild blocked by inherited Landlock
		}
		os.Exit(1) // bad: grandchild could read HOME

	case "read-via-symlink":
		// Try to read through a symlink (workspace/escape-link -> HOME).
		// Landlock follows the real path, so this should be blocked.
		link := filepath.Join(workspace, "escape-link")
		_, err := os.ReadDir(link)
		if err != nil {
			os.Exit(0) // expected: blocked (symlink target is outside allowed paths)
		}
		os.Exit(1) // bad: symlink traversal bypassed Landlock

	default:
		_, _ = os.Stderr.WriteString("unknown operation: " + op + "\n")
		os.Exit(1)
	}
}

// runSandboxedChild runs the current test binary as a child process with
// Landlock applied. Returns the combined output and exit code.
func runSandboxedChild(t *testing.T, op, workspace string) (string, int) {
	t.Helper()
	if runtime.GOOS != osLinux {
		t.Skip("landlock requires linux")
	}

	// Use /proc/self/exe to re-exec the test binary.
	ctx := context.Background()
	cmd := exec.CommandContext(ctx, "/proc/self/exe", "-test.run=^$")
	cmd.Env = append(os.Environ(),
		landlockTestEnv+"="+op,
		"SANDBOX_WORKSPACE="+workspace,
		"REAL_HOME="+os.Getenv("HOME"),
	)
	out, err := cmd.CombinedOutput()
	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			t.Fatalf("exec error: %v", err)
		}
	}
	return string(out), exitCode
}

func TestLandlock_BlocksHomeDir(t *testing.T) {
	workspace := t.TempDir()
	out, code := runSandboxedChild(t, "read-home", workspace)
	if code != 0 {
		t.Errorf("expected exit 0 (home blocked), got %d: %s", code, out)
	}
}

func TestLandlock_BlocksSSHKey(t *testing.T) {
	home := os.Getenv("HOME")
	if _, err := os.Stat(filepath.Join(home, ".ssh", "id_rsa")); err != nil {
		t.Skip("no SSH key to test with")
	}
	workspace := t.TempDir()
	out, code := runSandboxedChild(t, "read-ssh", workspace)
	if code != 0 {
		t.Errorf("expected exit 0 (SSH key blocked), got %d: %s", code, out)
	}
}

func TestLandlock_AllowsWorkspaceWrite(t *testing.T) {
	workspace := t.TempDir()
	out, code := runSandboxedChild(t, "write-workspace", workspace)
	if code != 0 {
		t.Errorf("expected exit 0 (workspace write allowed), got %d: %s", code, out)
	}
}

func TestLandlock_BlocksWriteOutside(t *testing.T) {
	workspace := t.TempDir()
	out, code := runSandboxedChild(t, "write-outside", workspace)
	if code != 0 {
		t.Errorf("expected exit 0 (outside write blocked), got %d: %s", code, out)
	}
}

func TestLandlock_AllowsReadUsr(t *testing.T) {
	workspace := t.TempDir()
	out, code := runSandboxedChild(t, "read-usr", workspace)
	if code != 0 {
		t.Errorf("expected exit 0 (/usr/bin readable), got %d: %s", code, out)
	}
}

func TestLandlock_AllowsReadResolvConf(t *testing.T) {
	workspace := t.TempDir()
	out, code := runSandboxedChild(t, "read-etc-resolv", workspace)
	if code != 0 {
		t.Errorf("expected exit 0 (/etc/resolv.conf readable), got %d: %s", code, out)
	}
}

func TestLandlock_AllowsWriteDevNull(t *testing.T) {
	workspace := t.TempDir()
	out, code := runSandboxedChild(t, "write-dev-null", workspace)
	if code != 0 {
		t.Errorf("expected exit 0 (/dev/null writable), got %d: %s", code, out)
	}
}

func TestLandlock_AllowsReadPasswd(t *testing.T) {
	workspace := t.TempDir()
	out, code := runSandboxedChild(t, "read-etc-passwd", workspace)
	if code != 0 {
		t.Errorf("expected exit 0 (/etc/passwd readable), got %d: %s", code, out)
	}
}

func TestLandlock_AllowsExecFromWorkspace(t *testing.T) {
	workspace := t.TempDir()
	out, code := runSandboxedChild(t, "exec-workspace", workspace)
	if code != 0 {
		t.Errorf("expected exit 0 (workspace exec allowed), got %d: %s", code, out)
	}
}

func TestApplyLandlock_NonLinux(t *testing.T) {
	if runtime.GOOS == osLinux {
		t.Skip("testing non-linux stub on linux")
	}
	_, err := ApplyLandlock(DefaultPolicy(t.TempDir()))
	if err == nil {
		t.Error("expected error on non-linux")
	}
}

func TestBuildRules_HandlesNonexistentPaths(t *testing.T) {
	// Verify that building rules with nonexistent paths doesn't panic.
	// IgnoreIfMissing() at the library level handles this gracefully.
	policy := DefaultPolicy(t.TempDir())
	policy.AllowReadDirs = append(policy.AllowReadDirs, "/nonexistent/path/xyz")
	rules := buildRules(policy)
	if len(rules) == 0 {
		t.Error("expected at least one rule")
	}
}

// TestLandlock_InheritedByChild verifies that Landlock restrictions are
// inherited by child processes spawned from the sandboxed process.
// The sandboxed child spawns a grandchild (via shell) that attempts to
// read HOME — it should be blocked by the inherited Landlock domain.
func TestLandlock_InheritedByChild(t *testing.T) {
	if runtime.GOOS != osLinux {
		t.Skip("landlock requires linux")
	}
	workspace := t.TempDir()
	out, code := runSandboxedChild(t, "inherited-child-blocked", workspace)
	if code != 0 {
		t.Errorf("expected exit 0 (grandchild blocked from reading HOME), got %d: %s", code, out)
	}
}

// TestLandlock_BlocksSymlinkEscape verifies that a symlink inside the
// workspace pointing to HOME does not bypass Landlock restrictions.
// The child creates the symlink then tries to read through it.
func TestLandlock_BlocksSymlinkEscape(t *testing.T) {
	if runtime.GOOS != osLinux {
		t.Skip("landlock requires linux")
	}
	home := os.Getenv("HOME")
	if home == "" {
		t.Skip("HOME not set")
	}
	workspace := t.TempDir()
	// Pre-create symlink before sandbox (child can't create it after Landlock
	// because HOME is not in allowed paths).
	link := filepath.Join(workspace, "escape-link")
	if err := os.Symlink(home, link); err != nil {
		t.Fatal(err)
	}
	out, code := runSandboxedChild(t, "read-via-symlink", workspace)
	if code != 0 {
		t.Errorf("expected exit 0 (symlink traversal blocked), got %d: %s", code, out)
	}
}

// Verify we use SysProcAttr constants correctly (compile-time check).
var (
	_ = syscall.CLONE_NEWUSER
	_ = syscall.CLONE_NEWNET
)
