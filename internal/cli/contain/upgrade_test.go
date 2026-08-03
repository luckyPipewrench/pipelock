// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

// testUpgradeEnv returns an upgradeEnv wired to a temp directory with a fake
// binary and pin already in place (simulating a previously installed system).
func testUpgradeEnv(t *testing.T) *upgradeEnv {
	t.Helper()
	dir := t.TempDir()

	binDir := filepath.Join(dir, "bin")
	intDir := filepath.Join(dir, "integrity")
	if err := os.MkdirAll(binDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(intDir, 0o750); err != nil {
		t.Fatal(err)
	}

	// Write a fake binary.
	target := filepath.Join(binDir, "pipelock")
	oldContent := []byte("old-binary-content")
	if err := writeFileAtomic(target, oldContent, 0o755); err != nil {
		t.Fatal(err)
	}

	// Write matching pin.
	pinPath := filepath.Join(intDir, "binary-pin.sha256")
	h := sha256.Sum256(oldContent)
	oldHash := hex.EncodeToString(h[:])
	if err := writeFileAtomic(pinPath, []byte(oldHash+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer

	env := &upgradeEnv{
		out:        &out,
		errOut:     &errOut,
		stat:       os.Stat,
		lstat:      os.Lstat,
		readFile:   os.ReadFile,
		writeFile:  writeFileAtomic,
		mkdirAll:   os.MkdirAll,
		hashFile:   sha256HexOfFile,
		removeFile: os.Remove,
		lookupUser: func(string) (*user.User, error) {
			return &user.User{Uid: "1000", Gid: "1000"}, nil
		},
		chown:            func(string, int, int) error { return nil },
		chmod:            func(string, os.FileMode) error { return nil },
		proxyUserName:    defaultProxyUser,
		pipelockTarget:   target,
		integrityDir:     intDir,
		integrityPin:     pinPath,
		serviceName:      "pipelock.service",
		readinessTimeout: 2 * time.Second,
	}

	return env
}

// successRunCmd returns a runCommand that succeeds for update/systemctl/verify.
func successRunCmd(env *upgradeEnv, newBinary []byte) runCommand {
	updateCalled := false
	return func(_ context.Context, name string, args ...string) (string, int, error) {
		if name == env.pipelockTarget && len(args) > 0 {
			if args[0] == "update" && !updateCalled {
				updateCalled = true
				_ = writeFileAtomic(env.pipelockTarget, newBinary, 0o755)
				return "Updated to v9.9.9. Previous binary saved at /tmp/bak", 0, nil
			}
			if len(args) >= 2 && args[0] == "contain" && args[1] == "verify" {
				return "Result: 12 PASS / 0 FAIL / 0 SKIP — exit 0", 0, nil
			}
		}
		if name == "systemctl" {
			if len(args) > 0 && args[0] == "is-active" {
				return "active", 0, nil
			}
			return "", 0, nil
		}
		return "", 0, nil
	}
}

func TestUpgrade_BinaryMissing_FailsClosed(t *testing.T) {
	env := testUpgradeEnv(t)
	// Remove the target binary.
	_ = os.Remove(env.pipelockTarget)

	err := runUpgrade(context.Background(), env, upgradeOpts{})
	if err == nil {
		t.Fatal("expected error for missing binary, got nil")
	}
	if !strings.Contains(err.Error(), "deployed binary not found") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUpgrade_BinaryIsSymlink_FailsClosed(t *testing.T) {
	env := testUpgradeEnv(t)

	// Replace target with a symlink.
	realPath := env.pipelockTarget + ".real"
	_ = os.Rename(env.pipelockTarget, realPath)
	if err := os.Symlink(realPath, env.pipelockTarget); err != nil {
		t.Fatal(err)
	}

	err := runUpgrade(context.Background(), env, upgradeOpts{})
	if err == nil {
		t.Fatal("expected error for symlink binary, got nil")
	}
	if !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUpgrade_TamperedBinary_FailsClosed(t *testing.T) {
	env := testUpgradeEnv(t)

	// Tamper with the binary so hash no longer matches pin.
	if err := writeFileAtomic(env.pipelockTarget, []byte("tampered-content"), 0o755); err != nil {
		t.Fatal(err)
	}

	err := runUpgrade(context.Background(), env, upgradeOpts{})
	if err == nil {
		t.Fatal("expected error for tampered binary, got nil")
	}
	if !errors.Is(err, errUpgradeIntegrity) {
		t.Fatalf("expected errUpgradeIntegrity, got: %v", err)
	}
	if !strings.Contains(err.Error(), "does not match integrity pin") {
		t.Fatalf("error should mention hash mismatch, got: %v", err)
	}
}

func TestUpgrade_NoPinFile_FailsClosed(t *testing.T) {
	env := testUpgradeEnv(t)
	_ = os.Remove(env.integrityPin)

	err := runUpgrade(context.Background(), env, upgradeOpts{})
	if err == nil {
		t.Fatal("expected error for missing pin file")
	}
	if !errors.Is(err, errUpgradeIntegrity) {
		t.Fatalf("expected errUpgradeIntegrity, got: %v", err)
	}
	if !strings.Contains(err.Error(), "no integrity pin") {
		t.Fatalf("error should mention missing pin, got: %v", err)
	}
}

func TestUpgrade_UnreadablePin_FailsClosed(t *testing.T) {
	env := testUpgradeEnv(t)

	// Make the pin unreadable (simulate permission error).
	env.readFile = func(path string) ([]byte, error) {
		if path == env.integrityPin {
			return nil, fmt.Errorf("permission denied: %w", os.ErrPermission)
		}
		return os.ReadFile(filepath.Clean(path))
	}

	err := runUpgrade(context.Background(), env, upgradeOpts{})
	if err == nil {
		t.Fatal("expected error for unreadable pin")
	}
	if !errors.Is(err, errUpgradeIntegrity) {
		t.Fatalf("expected errUpgradeIntegrity, got: %v", err)
	}
	if !strings.Contains(err.Error(), "cannot read integrity pin") {
		t.Fatalf("error should mention unreadable pin, got: %v", err)
	}
}

func TestUpgrade_MalformedPin_FailsClosed(t *testing.T) {
	env := testUpgradeEnv(t)

	// Write a malformed pin.
	if err := writeFileAtomic(env.integrityPin, []byte("not-a-valid-hex\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := runUpgrade(context.Background(), env, upgradeOpts{})
	if err == nil {
		t.Fatal("expected error for malformed pin")
	}
	if !errors.Is(err, errUpgradeIntegrity) {
		t.Fatalf("expected errUpgradeIntegrity, got: %v", err)
	}
	if !strings.Contains(err.Error(), "malformed SHA-256") {
		t.Fatalf("error should mention malformed pin, got: %v", err)
	}
}

func TestUpgrade_UpdateFails_RollsBackBinary(t *testing.T) {
	env := testUpgradeEnv(t)

	oldContent, err := os.ReadFile(env.pipelockTarget)
	if err != nil {
		t.Fatal(err)
	}

	// Simulate: pipelock update fails AFTER changing the binary.
	env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
		if name == env.pipelockTarget && len(args) > 0 && args[0] == "update" {
			// Change binary then fail.
			_ = writeFileAtomic(env.pipelockTarget, []byte("partial-update"), 0o755)
			return "update failed: network error", 1, nil
		}
		return "", 0, nil
	}

	upgradeErr := runUpgrade(context.Background(), env, upgradeOpts{})
	if upgradeErr == nil {
		t.Fatal("expected error from failed update")
	}
	if !errors.Is(upgradeErr, errUpgradeUpdate) {
		t.Fatalf("expected errUpgradeUpdate, got: %v", upgradeErr)
	}

	// Binary should be restored.
	got, err := os.ReadFile(env.pipelockTarget)
	if err != nil {
		t.Fatalf("binary should exist after rollback: %v", err)
	}
	if !bytes.Equal(got, oldContent) {
		t.Fatal("binary content should be restored after rollback")
	}
}

func TestUpgrade_UpdateFailsWithoutBinaryChange_NoRestart(t *testing.T) {
	env := testUpgradeEnv(t)

	var restartCalled bool
	env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
		if name == env.pipelockTarget && len(args) > 0 && args[0] == "update" {
			// Fail WITHOUT changing the binary (network failure before replacement).
			return "update failed: connection refused", 1, nil
		}
		if name == "systemctl" && len(args) > 0 && args[0] == "restart" {
			restartCalled = true
		}
		return "", 0, nil
	}

	upgradeErr := runUpgrade(context.Background(), env, upgradeOpts{})
	if upgradeErr == nil {
		t.Fatal("expected error from failed update")
	}
	if !errors.Is(upgradeErr, errUpgradeUpdate) {
		t.Fatalf("expected errUpgradeUpdate, got: %v", upgradeErr)
	}
	if restartCalled {
		t.Error("service should not be restarted when binary was not changed")
	}
}

func TestUpgrade_RepinFails_RollsBackBinaryAndPin(t *testing.T) {
	env := testUpgradeEnv(t)

	oldContent, err := os.ReadFile(env.pipelockTarget)
	if err != nil {
		t.Fatal(err)
	}
	oldPin, err := os.ReadFile(env.integrityPin)
	if err != nil {
		t.Fatal(err)
	}

	newBinary := []byte("new-binary-content")
	env.runCmd = successRunCmd(env, newBinary)

	// Make hashFile fail to simulate re-pin failure.
	origHash := env.hashFile
	firstCall := true
	env.hashFile = func(path string) (string, error) {
		// Allow the pre-execution hash check but fail for repin.
		if firstCall {
			firstCall = false
			return origHash(path)
		}
		return "", fmt.Errorf("disk I/O error")
	}

	upgradeErr := runUpgrade(context.Background(), env, upgradeOpts{})
	if upgradeErr == nil {
		t.Fatal("expected error from failed re-pin")
	}
	if !errors.Is(upgradeErr, errUpgradeRepin) {
		t.Fatalf("expected errUpgradeRepin, got: %v", upgradeErr)
	}

	// Both binary and pin should be restored.
	got, err := os.ReadFile(env.pipelockTarget)
	if err != nil {
		t.Fatalf("binary should exist after rollback: %v", err)
	}
	if !bytes.Equal(got, oldContent) {
		t.Fatal("binary should be restored to original content")
	}

	gotPin, err := os.ReadFile(env.integrityPin)
	if err != nil {
		t.Fatalf("pin should exist after rollback: %v", err)
	}
	if !bytes.Equal(gotPin, oldPin) {
		t.Fatalf("pin should be restored: got %q want %q", gotPin, oldPin)
	}
}

func TestUpgrade_RestartFails_RollsBack(t *testing.T) {
	env := testUpgradeEnv(t)

	oldContent, err := os.ReadFile(env.pipelockTarget)
	if err != nil {
		t.Fatal(err)
	}

	newBinary := []byte("new-binary-v2")
	updateCalled := false

	env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
		if name == env.pipelockTarget && len(args) > 0 {
			if args[0] == "update" && !updateCalled {
				updateCalled = true
				_ = writeFileAtomic(env.pipelockTarget, newBinary, 0o755)
				return "Updated to v9.9.9. Previous binary saved at /tmp/bak", 0, nil
			}
		}
		if name == "systemctl" {
			if len(args) > 0 && args[0] == "restart" {
				return "Job failed", 1, nil
			}
			// daemon-reload succeeds
			return "", 0, nil
		}
		return "", 0, nil
	}

	upgradeErr := runUpgrade(context.Background(), env, upgradeOpts{})
	if upgradeErr == nil {
		t.Fatal("expected error from failed restart")
	}
	if !errors.Is(upgradeErr, errUpgradeRestart) {
		t.Fatalf("expected errUpgradeRestart, got: %v", upgradeErr)
	}

	// Binary should be restored.
	got, err := os.ReadFile(env.pipelockTarget)
	if err != nil {
		t.Fatalf("binary should exist after rollback: %v", err)
	}
	if !bytes.Equal(got, oldContent) {
		t.Fatal("binary should be restored")
	}
}

func TestUpgrade_VerifyFails_RollsBack(t *testing.T) {
	env := testUpgradeEnv(t)

	oldContent, err := os.ReadFile(env.pipelockTarget)
	if err != nil {
		t.Fatal(err)
	}

	newBinary := []byte("new-binary-v3")
	updateCalled := false

	env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
		if name == env.pipelockTarget && len(args) > 0 {
			if args[0] == "update" && !updateCalled {
				updateCalled = true
				_ = writeFileAtomic(env.pipelockTarget, newBinary, 0o755)
				return "Updated to v9.9.9. Previous binary saved at /tmp/bak", 0, nil
			}
			if len(args) >= 2 && args[0] == "contain" && args[1] == "verify" {
				return "[FAIL] probe 10: binary integrity pin (mismatch)", 1, nil
			}
		}
		if name == "systemctl" {
			if len(args) > 0 && args[0] == "is-active" {
				return "active", 0, nil
			}
			return "", 0, nil
		}
		return "", 0, nil
	}

	upgradeErr := runUpgrade(context.Background(), env, upgradeOpts{})
	if upgradeErr == nil {
		t.Fatal("expected error from failed verify")
	}
	if !errors.Is(upgradeErr, errUpgradeVerify) {
		t.Fatalf("expected errUpgradeVerify, got: %v", upgradeErr)
	}

	got, err := os.ReadFile(env.pipelockTarget)
	if err != nil {
		t.Fatalf("binary should exist after rollback: %v", err)
	}
	if !bytes.Equal(got, oldContent) {
		t.Fatal("binary should be restored")
	}
}

func TestUpgrade_FullSuccess(t *testing.T) {
	env := testUpgradeEnv(t)

	newBinary := []byte("new-binary-success")
	env.runCmd = successRunCmd(env, newBinary)

	err := runUpgrade(context.Background(), env, upgradeOpts{})
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}

	// Pin should match the new binary.
	pinData, err := os.ReadFile(env.integrityPin)
	if err != nil {
		t.Fatalf("pin should exist: %v", err)
	}
	got := strings.TrimSpace(string(pinData))
	h := sha256.Sum256(newBinary)
	want := hex.EncodeToString(h[:])
	if got != want {
		t.Fatalf("pin mismatch: got %s want %s", got, want)
	}

	// Backup should be cleaned up.
	backupPath := env.pipelockTarget + ".upgrade-bak"
	if _, err := os.Stat(backupPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("backup should be removed after successful upgrade")
	}
}

func TestUpgrade_VersionParsing(t *testing.T) {
	tests := []struct {
		name string
		out  string
		want string
	}{
		{
			name: "standard update",
			out:  "Updated to v3.2.0. Previous binary saved at /usr/local/bin/pipelock.bak.",
			want: "v3.2.0",
		},
		{
			name: "already up to date",
			out:  "You are running the latest release. Nothing to do.",
			want: "current (already up to date)",
		},
		{
			name: "unrecognized output",
			out:  "something unexpected",
			want: "unknown",
		},
		{
			name: "pre-release version",
			out:  "Updated to v3.2.0-rc1. Previous binary saved at /tmp/bak.",
			want: "v3.2.0-rc1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := upgradeExtractVersion(tt.out)
			if got != tt.want {
				t.Fatalf("upgradeExtractVersion(%q) = %q, want %q", tt.out, got, tt.want)
			}
		})
	}
}

func TestUpgradeCmd_Registration(t *testing.T) {
	cmd := Cmd()
	found := false
	for _, sub := range cmd.Commands() {
		if sub.Use == "upgrade" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("upgrade subcommand not registered on contain command")
	}
}

// TestDefaultUpgradeEnv_Wiring pins the production dependency wiring. The
// upgrade orchestration is only as safe as the real operations behind these
// function values, so an accidentally nil or mis-pointed default would make
// every injected-dependency test above prove nothing about production.
func TestDefaultUpgradeEnv_Wiring(t *testing.T) {
	t.Parallel()

	var buf, errBuf bytes.Buffer
	env := defaultUpgradeEnv(&buf, &errBuf)

	if env.out != &buf {
		t.Error("out should be the writer passed in")
	}
	if env.errOut != &errBuf {
		t.Error("errOut should be the errOut writer passed in")
	}
	for name, fn := range map[string]any{
		"stat": env.stat, "lstat": env.lstat, "readFile": env.readFile,
		"writeFile": env.writeFile, "mkdirAll": env.mkdirAll,
		"hashFile": env.hashFile, "removeFile": env.removeFile,
		"runCmd": env.runCmd, "lookupUser": env.lookupUser,
		"chown": env.chown, "chmod": env.chmod,
	} {
		v := reflect.ValueOf(fn)
		if !v.IsValid() || v.IsNil() {
			t.Errorf("%s must be wired to a real implementation", name)
		}
	}
	if env.pipelockTarget != defaultPipelockTarget {
		t.Errorf("pipelockTarget = %q, want the deployed target %q", env.pipelockTarget, defaultPipelockTarget)
	}
	if env.integrityPin != defaultIntegrityPin {
		t.Errorf("integrityPin = %q, want %q", env.integrityPin, defaultIntegrityPin)
	}
	if env.serviceName != defaultServiceName {
		t.Errorf("serviceName = %q, want %q", env.serviceName, defaultServiceName)
	}
	if env.readinessTimeout <= 0 {
		t.Error("readinessTimeout must be positive or readiness waiting cannot work")
	}
}

// TestUpgradeCmd_RequiresRoot proves the command refuses to run unprivileged.
// The test suite runs as an ordinary user, so this exercises the real guard.
func TestUpgradeCmd_RequiresRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("test must run as a non-root user to exercise the root guard")
	}

	cmd := upgradeCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected upgrade to refuse to run as a non-root user")
	}
	if !strings.Contains(err.Error(), "root") {
		t.Fatalf("error should name the root requirement, got: %v", err)
	}
}

// TestUpgrade_BackupFails_AbortsBeforeTouchingBinary proves the command stops
// before any replacement when it cannot take a backup.
func TestUpgrade_BackupFails_AbortsBeforeTouchingBinary(t *testing.T) {
	env := testUpgradeEnv(t)

	original, err := os.ReadFile(env.pipelockTarget)
	if err != nil {
		t.Fatal(err)
	}

	// Make reading the binary for backup fail (but allow pin reads).
	origReadFile := env.readFile
	env.readFile = func(path string) ([]byte, error) {
		if path == env.pipelockTarget {
			return nil, errors.New("simulated read failure")
		}
		return origReadFile(path)
	}

	var updateInvoked bool
	env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
		if name == env.pipelockTarget && len(args) > 0 && args[0] == "update" {
			updateInvoked = true
		}
		return "", 0, nil
	}

	if err := runUpgrade(context.Background(), env, upgradeOpts{}); err == nil {
		t.Fatal("expected error when the backup cannot be taken")
	}
	if updateInvoked {
		t.Error("update must not run when no backup exists; there would be no rollback path")
	}

	got, err := os.ReadFile(env.pipelockTarget)
	if err != nil {
		t.Fatalf("deployed binary should be untouched: %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Error("deployed binary must be unchanged when backup fails")
	}
}

// TestUpgrade_RollbackFailure_ReportsBothErrors covers the worst case: the
// upgrade failed AND the rollback could not fully restore.
func TestUpgrade_RollbackFailure_ReportsBothErrors(t *testing.T) {
	env := testUpgradeEnv(t)

	env.writeFile = func(path string, contents []byte, mode os.FileMode) error {
		if path == env.integrityPin {
			return errors.New("simulated pin restore failure")
		}
		return writeFileAtomic(path, contents, mode)
	}

	env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
		if name == env.pipelockTarget && len(args) > 0 && args[0] == "update" {
			// Change binary so rollback is needed.
			_ = writeFileAtomic(env.pipelockTarget, []byte("changed"), 0o755)
			return "update failed", 1, nil
		}
		return "", 0, nil
	}

	err := runUpgrade(context.Background(), env, upgradeOpts{})
	if err == nil {
		t.Fatal("expected an error when both the upgrade and its rollback fail")
	}
	if !errors.Is(err, errUpgradeUpdate) {
		t.Errorf("original failure must survive in the error chain, got: %v", err)
	}
	if !errors.Is(err, errUpgradeRollback) {
		t.Errorf("rollback failure must be reported to the operator, got: %v", err)
	}
}

// TestUpgrade_DaemonReloadFails_RollsBack covers the daemon-reload error path.
func TestUpgrade_DaemonReloadFails_RollsBack(t *testing.T) {
	env := testUpgradeEnv(t)

	newBinary := []byte("new-binary-dr")
	updateCalled := false

	env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
		if name == env.pipelockTarget && len(args) > 0 {
			if args[0] == "update" && !updateCalled {
				updateCalled = true
				_ = writeFileAtomic(env.pipelockTarget, newBinary, 0o755)
				return "Updated to v9.9.9. Previous binary saved at /tmp/bak", 0, nil
			}
		}
		if name == "systemctl" {
			if len(args) > 0 && args[0] == "daemon-reload" {
				return "", 0, fmt.Errorf("exec failed")
			}
			return "", 0, nil
		}
		return "", 0, nil
	}

	upgradeErr := runUpgrade(context.Background(), env, upgradeOpts{})
	if upgradeErr == nil {
		t.Fatal("expected error from failed daemon-reload")
	}
	if !errors.Is(upgradeErr, errUpgradeRestart) {
		t.Fatalf("expected errUpgradeRestart, got: %v", upgradeErr)
	}
}

// TestUpgrade_DaemonReloadNonZero_RollsBack covers daemon-reload exiting non-zero.
func TestUpgrade_DaemonReloadNonZero_RollsBack(t *testing.T) {
	env := testUpgradeEnv(t)

	newBinary := []byte("new-binary-drn")
	updateCalled := false

	env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
		if name == env.pipelockTarget && len(args) > 0 {
			if args[0] == "update" && !updateCalled {
				updateCalled = true
				_ = writeFileAtomic(env.pipelockTarget, newBinary, 0o755)
				return "Updated to v9.9.9. Previous binary saved at /tmp/bak", 0, nil
			}
		}
		if name == "systemctl" {
			if len(args) > 0 && args[0] == "daemon-reload" {
				return "failed", 1, nil
			}
			return "", 0, nil
		}
		return "", 0, nil
	}

	upgradeErr := runUpgrade(context.Background(), env, upgradeOpts{})
	if upgradeErr == nil {
		t.Fatal("expected error from non-zero daemon-reload")
	}
	if !errors.Is(upgradeErr, errUpgradeRestart) {
		t.Fatalf("expected errUpgradeRestart, got: %v", upgradeErr)
	}
}

// TestUpgrade_ReadinessTimeout_RollsBack covers the service never becoming active.
func TestUpgrade_ReadinessTimeout_RollsBack(t *testing.T) {
	env := testUpgradeEnv(t)
	env.readinessTimeout = 200 * time.Millisecond

	newBinary := []byte("new-binary-rt")
	updateCalled := false

	env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
		if name == env.pipelockTarget && len(args) > 0 {
			if args[0] == "update" && !updateCalled {
				updateCalled = true
				_ = writeFileAtomic(env.pipelockTarget, newBinary, 0o755)
				return "Updated to v9.9.9. Previous binary saved at /tmp/bak", 0, nil
			}
		}
		if name == "systemctl" {
			if len(args) > 0 && args[0] == "is-active" {
				return "activating", 3, nil // never becomes active
			}
			return "", 0, nil
		}
		return "", 0, nil
	}

	upgradeErr := runUpgrade(context.Background(), env, upgradeOpts{})
	if upgradeErr == nil {
		t.Fatal("expected error from readiness timeout")
	}
	if !errors.Is(upgradeErr, errUpgradeRestart) {
		t.Fatalf("expected errUpgradeRestart, got: %v", upgradeErr)
	}
	if !strings.Contains(upgradeErr.Error(), "not ready after") {
		t.Fatalf("error should mention readiness timeout, got: %v", upgradeErr)
	}
}

// TestUpgrade_ContextCancellation_RollsBack covers the ctx.Done() branch in
// upgradeRestartAndWait. The context is cancelled before the restart command
// so the select always has ctx.Done() ready on entry — proving the branch
// fires deterministically rather than relying on Go's random case selection.
func TestUpgrade_ContextCancellation_RollsBack(t *testing.T) {
	env := testUpgradeEnv(t)

	newBinary := []byte("new-binary-ctx")
	updateCalled := false
	ctx, cancel := context.WithCancel(context.Background())

	env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
		if name == env.pipelockTarget && len(args) > 0 {
			if args[0] == "update" && !updateCalled {
				updateCalled = true
				_ = writeFileAtomic(env.pipelockTarget, newBinary, 0o755)
				return "Updated to v9.9.9. Previous binary saved at /tmp/bak", 0, nil
			}
		}
		if name == "systemctl" {
			if len(args) > 0 && args[0] == "restart" {
				// Cancel the context after restart succeeds but before
				// the readiness poll loop runs. The ticker fires every
				// readinessInterval, so by the time the select runs,
				// ctx.Done() is already closed.
				cancel()
				return "", 0, nil
			}
			if len(args) > 0 && args[0] == "is-active" {
				// Should never be reached — ctx.Done() fires first.
				t.Error("is-active polled after context cancellation; ctx.Done() branch did not fire")
				return "active", 0, nil
			}
			return "", 0, nil
		}
		return "", 0, nil
	}

	upgradeErr := runUpgrade(ctx, env, upgradeOpts{})
	if upgradeErr == nil {
		t.Fatal("expected error from context cancellation")
	}
	if !errors.Is(upgradeErr, errUpgradeRestart) {
		t.Fatalf("expected errUpgradeRestart, got: %v", upgradeErr)
	}
	if !strings.Contains(upgradeErr.Error(), "context canceled") {
		t.Fatalf("error should mention context cancellation, got: %v", upgradeErr)
	}
}

// TestUpgrade_UpdateExecError covers the runCmd transport error in upgradeRunUpdate.
func TestUpgrade_UpdateExecError(t *testing.T) {
	env := testUpgradeEnv(t)

	env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
		if name == env.pipelockTarget && len(args) > 0 && args[0] == "update" {
			return "", 0, fmt.Errorf("exec: no such file")
		}
		return "", 0, nil
	}

	upgradeErr := runUpgrade(context.Background(), env, upgradeOpts{})
	if upgradeErr == nil {
		t.Fatal("expected error from exec failure")
	}
	if !errors.Is(upgradeErr, errUpgradeUpdate) {
		t.Fatalf("expected errUpgradeUpdate, got: %v", upgradeErr)
	}
}

// TestUpgrade_VerifyExecError covers the runCmd transport error in upgradePostVerify.
func TestUpgrade_VerifyExecError(t *testing.T) {
	env := testUpgradeEnv(t)

	newBinary := []byte("new-binary-ve")
	updateCalled := false

	env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
		if name == env.pipelockTarget && len(args) > 0 {
			if args[0] == "update" && !updateCalled {
				updateCalled = true
				_ = writeFileAtomic(env.pipelockTarget, newBinary, 0o755)
				return "Updated to v9.9.9. Previous binary saved at /tmp/bak", 0, nil
			}
			if len(args) >= 2 && args[0] == "contain" && args[1] == "verify" {
				return "", 0, fmt.Errorf("exec: signal: killed")
			}
		}
		if name == "systemctl" {
			if len(args) > 0 && args[0] == "is-active" {
				return "active", 0, nil
			}
			return "", 0, nil
		}
		return "", 0, nil
	}

	upgradeErr := runUpgrade(context.Background(), env, upgradeOpts{})
	if upgradeErr == nil {
		t.Fatal("expected error from verify exec failure")
	}
	if !errors.Is(upgradeErr, errUpgradeVerify) {
		t.Fatalf("expected errUpgradeVerify, got: %v", upgradeErr)
	}
}

// TestUpgrade_VersionForwarded proves opts.version reaches the child process.
func TestUpgrade_VersionForwarded(t *testing.T) {
	env := testUpgradeEnv(t)

	var capturedArgs []string
	env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
		if name == env.pipelockTarget && len(args) > 0 && args[0] == "update" {
			capturedArgs = args
			return "Updated to v3.2.0. Previous binary saved at /tmp/bak", 0, nil
		}
		if name == "systemctl" {
			if len(args) > 0 && args[0] == "is-active" {
				return "active", 0, nil
			}
			return "", 0, nil
		}
		if name == env.pipelockTarget && len(args) >= 2 && args[0] == "contain" && args[1] == "verify" {
			return "Result: 12 PASS / 0 FAIL / 0 SKIP", 0, nil
		}
		return "", 0, nil
	}

	err := runUpgrade(context.Background(), env, upgradeOpts{version: "v3.2.0"})
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}

	found := false
	for i, a := range capturedArgs {
		if a == "--version" && i+1 < len(capturedArgs) && capturedArgs[i+1] == "v3.2.0" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("--version v3.2.0 should be forwarded to pipelock update, got args: %v", capturedArgs)
	}
}

// TestUpgrade_RollbackRestartFails_ReportsWarning proves the rollback restart
// warning is emitted to errOut when the best-effort restart fails.
func TestUpgrade_RollbackRestartFails_ReportsWarning(t *testing.T) {
	env := testUpgradeEnv(t)

	newBinary := []byte("new-binary-rbr")
	updateCalled := false

	env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
		if name == env.pipelockTarget && len(args) > 0 {
			if args[0] == "update" && !updateCalled {
				updateCalled = true
				_ = writeFileAtomic(env.pipelockTarget, newBinary, 0o755)
				return "Updated to v9.9.9. Previous binary saved at /tmp/bak", 0, nil
			}
			if len(args) >= 2 && args[0] == "contain" && args[1] == "verify" {
				return "[FAIL]", 1, nil
			}
		}
		if name == "systemctl" {
			if len(args) > 0 && args[0] == "is-active" {
				return "active", 0, nil
			}
			// Restart during rollback fails.
			if len(args) > 0 && args[0] == "restart" {
				return "Job failed", 5, nil
			}
			return "", 0, nil
		}
		return "", 0, nil
	}

	upgradeErr := runUpgrade(context.Background(), env, upgradeOpts{})
	if upgradeErr == nil {
		t.Fatal("expected error")
	}

	errOutput := env.errOut.(*bytes.Buffer).String()
	if !strings.Contains(errOutput, "warning: best-effort restart") {
		t.Fatalf("expected rollback restart warning in errOut, got: %q", errOutput)
	}
}

// TestUpgrade_RepinRestoresProxyOwnership proves the freshly written integrity
// pin is handed back to the proxy user.
//
// This command runs as root, so without the ownership restore the pin is left
// root-owned. The Pipelock service runs as the proxy user and reads the pin at
// runtime, so a root-owned pin makes the binary-integrity probe report a
// mismatch on a completely healthy host. That false mismatch is the exact
// failure this command exists to eliminate, so getting it wrong here would
// reintroduce the bug through its own fix.
func TestUpgrade_RepinRestoresProxyOwnership(t *testing.T) {
	env := testUpgradeEnv(t)

	const wantUID, wantGID = 4242, 4343
	env.proxyUserName = "pipelock-proxy"
	env.lookupUser = func(name string) (*user.User, error) {
		if name != "pipelock-proxy" {
			return nil, fmt.Errorf("unexpected user %q", name)
		}
		return &user.User{Uid: strconv.Itoa(wantUID), Gid: strconv.Itoa(wantGID)}, nil
	}

	var chownedPath string
	var chownedUID, chownedGID int
	env.chown = func(path string, uid, gid int) error {
		chownedPath, chownedUID, chownedGID = path, uid, gid
		return nil
	}
	var chmodedPath string
	env.chmod = func(path string, _ os.FileMode) error {
		chmodedPath = path
		return nil
	}

	env.runCmd = successRunCmd(env, []byte("new-binary-content"))

	if err := runUpgrade(context.Background(), env, upgradeOpts{}); err != nil {
		t.Fatalf("upgrade should succeed: %v", err)
	}

	if chownedPath != env.integrityPin {
		t.Errorf("pin ownership not restored: chowned %q, want %q", chownedPath, env.integrityPin)
	}
	if chownedUID != wantUID || chownedGID != wantGID {
		t.Errorf("pin chowned to %d:%d, want the proxy user %d:%d", chownedUID, chownedGID, wantUID, wantGID)
	}
	if chmodedPath != env.integrityPin {
		t.Errorf("pin mode not reasserted: chmoded %q, want %q", chmodedPath, env.integrityPin)
	}
}

// TestUpgrade_RepinOwnershipFailure_FailsClosed proves an ownership failure is
// reported rather than silently leaving an unreadable pin behind.
func TestUpgrade_RepinOwnershipFailure_FailsClosed(t *testing.T) {
	env := testUpgradeEnv(t)

	env.proxyUserName = "pipelock-proxy"
	env.lookupUser = func(string) (*user.User, error) {
		return nil, errors.New("no such user")
	}
	env.chown = func(string, int, int) error { return nil }
	env.chmod = func(string, os.FileMode) error { return nil }
	env.runCmd = successRunCmd(env, []byte("new-binary-content"))

	err := runUpgrade(context.Background(), env, upgradeOpts{})
	if err == nil {
		t.Fatal("expected an error when the pin owner cannot be resolved")
	}
	if !errors.Is(err, errUpgradeRepin) {
		t.Fatalf("expected errUpgradeRepin, got: %v", err)
	}
}

// TestUpgrade_RollbackRestoresPinOwnership proves the ROLLBACK path hands the
// pin back to the proxy user, not just its contents.
//
// The forward path already does this. Restoring the bytes without the
// ownership would leave a rolled-back host with a root-owned pin that the
// proxy service cannot read, so it would report a false integrity mismatch --
// the exact failure this command exists to eliminate, reintroduced through its
// own recovery path.
func TestUpgrade_RollbackRestoresPinOwnership(t *testing.T) {
	env := testUpgradeEnv(t)

	const wantUID, wantGID = 4242, 4343
	env.proxyUserName = "pipelock-proxy"
	env.lookupUser = func(string) (*user.User, error) {
		return &user.User{Uid: strconv.Itoa(wantUID), Gid: strconv.Itoa(wantGID)}, nil
	}

	oldPin, readErr := os.ReadFile(env.integrityPin)
	if readErr != nil {
		t.Fatal(readErr)
	}

	// Record an ORDERED event log. Asserting only "the pin was chowned" is
	// vacuous here, because the forward re-pin chowns the same path earlier in
	// the same run, so that assertion passes even with the rollback ownership
	// restore removed entirely (verified: it did). What must be proven is that
	// a chown follows the rollback's pin RESTORE specifically.
	var events []string
	origWrite := env.writeFile
	env.writeFile = func(path string, contents []byte, mode os.FileMode) error {
		if path == env.integrityPin {
			if bytes.Equal(contents, oldPin) {
				events = append(events, "restore-pin")
			} else {
				events = append(events, "repin")
			}
		}
		return origWrite(path, contents, mode)
	}
	env.chown = func(path string, uid, gid int) error {
		if path == env.integrityPin && uid == wantUID && gid == wantGID {
			events = append(events, "chown-pin")
		}
		return nil
	}
	env.chmod = func(string, os.FileMode) error { return nil }

	// Fail AFTER the re-pin so the rollback path runs.
	env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
		if name == env.pipelockTarget && len(args) > 0 {
			if args[0] == "update" {
				_ = writeFileAtomic(env.pipelockTarget, []byte("new-binary-content"), 0o755)
				return "Updated to v9.9.9.", 0, nil
			}
			if len(args) >= 2 && args[0] == "contain" && args[1] == "verify" {
				return "Result: 11 PASS / 1 FAIL", 1, nil
			}
		}
		if name == "systemctl" && len(args) > 0 && args[0] == "is-active" {
			return "active", 0, nil
		}
		return "", 0, nil
	}

	upErr := runUpgrade(context.Background(), env, upgradeOpts{})
	if upErr == nil {
		t.Fatal("expected the upgrade to fail so the rollback path runs")
	}
	if !errors.Is(upErr, errUpgradeVerify) {
		t.Fatalf("expected errUpgradeVerify, got: %v", upErr)
	}

	restoreAt := -1
	for i, e := range events {
		if e == "restore-pin" {
			restoreAt = i
		}
	}
	if restoreAt < 0 {
		t.Fatalf("rollback never restored the pin; events = %v", events)
	}
	chownedAfterRestore := false
	for _, e := range events[restoreAt+1:] {
		if e == "chown-pin" {
			chownedAfterRestore = true
		}
	}
	if !chownedAfterRestore {
		t.Errorf("rollback restored the pin but never handed it back to the proxy user; events = %v", events)
	}
}
