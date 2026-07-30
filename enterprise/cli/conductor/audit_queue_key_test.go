//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor/auditbatcher"
)

func TestAuditQueueKeyLifecycle(t *testing.T) {
	root := t.TempDir()
	keyringPath := filepath.Join(root, "secrets", "keyring.json")
	queueDir := filepath.Join(root, "queue")

	runAuditQueueKeyCommand(t, "init", "--keyring", keyringPath)
	info, err := os.Stat(keyringPath)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("keyring mode = %o, want 600", info.Mode().Perm())
	}
	original, err := auditbatcher.LoadKeyring(keyringPath)
	if err != nil {
		t.Fatal(err)
	}
	oldID := original.ActiveKeyID()
	queue, err := auditbatcher.Open(auditbatcher.Config{Dir: queueDir, Keyring: original})
	if err != nil {
		t.Fatal(err)
	}
	if err := queue.Close(); err != nil {
		t.Fatal(err)
	}

	out := runAuditQueueKeyCommand(t, "inspect", "--keyring", keyringPath, "--queue-dir", queueDir)
	if !strings.Contains(out, oldID+" records=0 active") {
		t.Fatalf("inspect output = %q", out)
	}
	out = runAuditQueueKeyCommand(t, "migrate", "--keyring", keyringPath, "--queue-dir", queueDir)
	if !strings.Contains(out, "converged to active key "+oldID) {
		t.Fatalf("migrate output = %q", out)
	}

	out = runAuditQueueKeyCommand(t, "rotate", "--keyring", keyringPath, "--queue-dir", queueDir)
	if !strings.Contains(out, "rotated audit queue key") {
		t.Fatalf("rotate output = %q", out)
	}
	rotated, err := auditbatcher.LoadKeyring(keyringPath)
	if err != nil {
		t.Fatal(err)
	}
	if rotated.ActiveKeyID() == oldID {
		t.Fatal("rotation did not change active key")
	}
	newID := rotated.ActiveKeyID()
	if _, err := os.Stat(keyringPath + ".bak"); err != nil {
		t.Fatalf("rotation backup: %v", err)
	}
	if _, err := os.Stat(keyringPath + ".bak.previous"); err != nil {
		t.Fatalf("pre-rotation backup: %v", err)
	}

	runAuditQueueKeyCommand(t, "revoke", oldID, "--keyring", keyringPath, "--queue-dir", queueDir)
	revoked, err := auditbatcher.LoadKeyring(keyringPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range revoked.KeyIDs() {
		if id == oldID {
			t.Fatalf("revoked key %s remains", oldID)
		}
	}

	runAuditQueueKeyCommand(t, "recover", "--backup", keyringPath+".bak", "--keyring", keyringPath, "--queue-dir", queueDir)
	recovered, err := auditbatcher.LoadKeyring(keyringPath)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.ActiveKeyID() != newID {
		t.Fatalf("recovered active key = %s, want %s", recovered.ActiveKeyID(), newID)
	}
}

func TestAuditQueueKeyCommandsRespectQueueLock(t *testing.T) {
	root := t.TempDir()
	keyringPath := filepath.Join(root, "secrets", "keyring.json")
	queueDir := filepath.Join(root, "queue")
	runAuditQueueKeyCommand(t, "init", "--keyring", keyringPath)
	keyring, err := auditbatcher.LoadKeyring(keyringPath)
	if err != nil {
		t.Fatal(err)
	}
	queue, err := auditbatcher.Open(auditbatcher.Config{Dir: queueDir, Keyring: keyring})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = queue.Close() }()

	cmd := auditQueueKeyCmd()
	cmd.SetArgs([]string{"migrate", "--keyring", keyringPath, "--queue-dir", queueDir})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	err = cmd.Execute()
	if !errors.Is(err, auditbatcher.ErrQueueLocked) {
		t.Fatalf("migrate while queue live error = %v, want ErrQueueLocked", err)
	}

	initPath := filepath.Join(root, "secrets", "second-keyring.json")
	cmd = auditQueueKeyCmd()
	cmd.SetArgs([]string{"init", "--keyring", initPath, "--queue-dir", queueDir})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	err = cmd.Execute()
	if !errors.Is(err, auditbatcher.ErrQueueLocked) {
		t.Fatalf("init while queue live error = %v, want ErrQueueLocked", err)
	}
}

func TestAuditQueueKeyInitRefusesKeyringInsideQueueDir(t *testing.T) {
	root := t.TempDir()
	queueDir := filepath.Join(root, "queue")
	if err := os.MkdirAll(queueDir, 0o750); err != nil {
		t.Fatalf("MkdirAll(queueDir) error = %v", err)
	}
	insideKeyring := filepath.Join(queueDir, "keyring.json")
	cmd := auditQueueKeyCmd()
	cmd.SetArgs([]string{"init", "--keyring", insideKeyring, "--queue-dir", queueDir})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "must be outside") {
		t.Fatalf("init keyring inside queue error = %v, want \"must be outside\"", err)
	}
	if _, statErr := os.Lstat(insideKeyring); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("refused init must not create the keyring file; stat err = %v", statErr)
	}
}

func TestAuditQueueKeyInitRefusesSymlinkedKeyringIntoQueueDir(t *testing.T) {
	root := t.TempDir()
	queueDir := filepath.Join(root, "queue")
	if err := os.MkdirAll(queueDir, 0o750); err != nil {
		t.Fatalf("MkdirAll(queueDir) error = %v", err)
	}
	// A symlink whose target is the queue directory: lexically the keyring path
	// is outside queueDir, but it physically resolves inside it.
	linkDir := filepath.Join(root, "link-to-queue")
	if err := os.Symlink(queueDir, linkDir); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	smuggled := filepath.Join(linkDir, "keyring.json")
	cmd := auditQueueKeyCmd()
	cmd.SetArgs([]string{"init", "--keyring", smuggled, "--queue-dir", queueDir})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "must be outside") {
		t.Fatalf("init symlinked keyring into queue error = %v, want \"must be outside\"", err)
	}
	if _, statErr := os.Lstat(filepath.Join(queueDir, "keyring.json")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("refused init must not create the keyring through the symlink; stat err = %v", statErr)
	}
}

func TestAuditQueueKeyInitRefusesRelativeKeyringInsideQueueDir(t *testing.T) {
	root := t.TempDir()
	// A relative --queue-dir and a relative keyring path that resolves inside it.
	// The old lexical filepath.Rel between a relative and an absolute path errored
	// and returned "outside"; canonicalizing both to absolute physical paths
	// catches it.
	t.Chdir(root)
	if err := os.MkdirAll("queue", 0o750); err != nil {
		t.Fatalf("MkdirAll(queue) error = %v", err)
	}
	// Relative --queue-dir with an ABSOLUTE keyring inside it: the exact bypass a
	// lexical filepath.Rel misses (Rel of a relative parent against an absolute
	// candidate errors, so the old check reported "outside").
	absKeyring := filepath.Join(root, "queue", "keyring.json")
	cmd := auditQueueKeyCmd()
	cmd.SetArgs([]string{"init", "--keyring", absKeyring, "--queue-dir", "queue"})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "must be outside") {
		t.Fatalf("init relative keyring inside queue error = %v, want \"must be outside\"", err)
	}
	if _, statErr := os.Lstat(filepath.Join(root, "queue", "keyring.json")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("refused init must not create the relative keyring inside the queue; stat err = %v", statErr)
	}
}

func TestAuditQueueKeyInspectReportsUnreadableRecords(t *testing.T) {
	root := t.TempDir()
	keyringPath := filepath.Join(root, "secrets", "keyring.json")
	queueDir := filepath.Join(root, "queue")
	runAuditQueueKeyCommand(t, "init", "--keyring", keyringPath)
	keyring, err := auditbatcher.LoadKeyring(keyringPath)
	if err != nil {
		t.Fatal(err)
	}
	queue, err := auditbatcher.Open(auditbatcher.Config{Dir: queueDir, Keyring: keyring})
	if err != nil {
		t.Fatal(err)
	}
	if err := queue.Close(); err != nil {
		t.Fatal(err)
	}
	deadPath := filepath.Join(queueDir, "dead", "00000000000000000001-corrupt.json")
	if err := os.WriteFile(deadPath, []byte("{bad"), 0o600); err != nil {
		t.Fatal(err)
	}

	out := runAuditQueueKeyCommand(t, "inspect", "--keyring", keyringPath, "--queue-dir", queueDir)
	want := auditbatcher.UnreadableRecordID + " records=1"
	if !strings.Contains(out, want) {
		t.Fatalf("inspect output = %q, want %q", out, want)
	}
}

func TestAuditQueueKeyInitRefusesOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keyring.json")
	runAuditQueueKeyCommand(t, "init", "--keyring", path)

	cmd := auditQueueKeyCmd()
	cmd.SetArgs([]string{"init", "--keyring", path})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("second init error = %v, want overwrite refusal", err)
	}
	if !strings.Contains(err.Error(), "rotate or recover") {
		t.Fatalf("second init error = %v, want lifecycle guidance", err)
	}
}

func TestAuditQueueKeyCommandErrorPaths(t *testing.T) {
	root := t.TempDir()
	keyringPath := filepath.Join(root, "secrets", "keyring.json")
	queueDir := filepath.Join(root, "queue")

	runAuditQueueKeyCommandWantError(t, "inspect", "--keyring", filepath.Join(root, "missing.json"), "--queue-dir", queueDir)

	parentFile := filepath.Join(root, "not-a-directory")
	if err := os.WriteFile(parentFile, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	runAuditQueueKeyCommandWantError(t, "init", "--keyring", filepath.Join(parentFile, "keyring.json"))

	runAuditQueueKeyCommand(t, "init", "--keyring", keyringPath)
	keyring, err := auditbatcher.LoadKeyring(keyringPath)
	if err != nil {
		t.Fatal(err)
	}
	queue, err := auditbatcher.Open(auditbatcher.Config{Dir: queueDir, Keyring: keyring})
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"inspect", "--keyring", keyringPath, "--queue-dir", queueDir},
		{"rotate", "--keyring", keyringPath, "--queue-dir", queueDir},
		{"migrate", "--keyring", keyringPath, "--queue-dir", queueDir},
	} {
		runAuditQueueKeyCommandWantError(t, args...)
	}
	if err := queue.Close(); err != nil {
		t.Fatal(err)
	}

	runAuditQueueKeyCommandWantError(t, "revoke", keyring.ActiveKeyID(), "--keyring", keyringPath, "--queue-dir", queueDir)
	runAuditQueueKeyCommandWantError(t, "recover", "--backup", filepath.Join(root, "missing-backup.json"), "--keyring", keyringPath, "--queue-dir", queueDir)
}

func runAuditQueueKeyCommand(t *testing.T, args ...string) string {
	t.Helper()
	var out bytes.Buffer
	cmd := auditQueueKeyCmd()
	cmd.SetArgs(args)
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("audit-queue-key %s: %v\n%s", strings.Join(args, " "), err, out.String())
	}
	return out.String()
}

func runAuditQueueKeyCommandWantError(t *testing.T, args ...string) {
	t.Helper()
	cmd := auditQueueKeyCmd()
	cmd.SetArgs(args)
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	if err := cmd.Execute(); err == nil {
		t.Fatalf("audit-queue-key %s error = nil", strings.Join(args, " "))
	}
}
