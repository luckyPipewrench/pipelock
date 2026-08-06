// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// A recovery path that can itself fail must fail loudly rather than proceed on
// a keystore it could not put back into a known state. These build filesystem
// states where the cleanup or restore is genuinely impossible, so the branches
// that report those failures actually execute.

// skipIfChmodCannotDeny skips a test whose fault is injected by removing a
// permission bit. Root ignores mode bits entirely, and Windows does not enforce
// them through chmod, so on either the injected failure never happens and the
// test would assert against a fault that did not occur. Guarding on
// os.Geteuid() alone misses Windows, where Geteuid returns -1 and the guard
// silently does nothing.
func skipIfChmodCannotDeny(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("chmod does not deny access on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses the permission bit this test relies on")
	}
}

// unremovableDir returns a directory that os.RemoveAll cannot clear, by placing
// a child inside it and dropping write permission on the parent. Unlinking the
// child then requires write access the process does not have.
func unremovableDir(t *testing.T, path string) {
	t.Helper()
	skipIfChmodCannotDeny(t)
	if err := os.MkdirAll(filepath.Join(path, "child"), dirPermission); err != nil {
		t.Fatalf("creating %s: %v", path, err)
	}
	if err := os.Chmod(path, 0o500); err != nil { // #nosec G302 -- directory must stay traversable while write access is removed
		t.Fatalf("restricting %s: %v", path, err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o700) }) // #nosec G302 -- restore private directory traversal for cleanup
}

func TestRecoverAgentTransaction_ReportsUnremovableCommittedBackup(t *testing.T) {
	ks := NewKeystore(t.TempDir())
	pub, priv := encodedPair(t)
	seedAgentPair(t, ks.agentDir("agent"), pub, priv)
	unremovableDir(t, ks.agentBackupDir("agent"))

	err := ks.recoverAgentTransaction("agent")
	if err == nil {
		t.Fatal("recovery reported success while leaving a backup it could not clear")
	}
	if !strings.Contains(err.Error(), "removing committed agent backup") {
		t.Errorf("error = %q, want it to name the backup it could not remove", err)
	}
	if !ks.agentKeyPairExists("agent") {
		t.Error("the committed pair was disturbed by a failed cleanup")
	}
}

func TestRecoverAgentTransaction_ReportsUnremovableIncompleteDirectory(t *testing.T) {
	ks := NewKeystore(t.TempDir())
	// Backup holds the last good pair, the active directory is torn AND cannot
	// be cleared. Recovery must refuse rather than report a restore it did not
	// perform, because the caller would then sign with nothing.
	pub, priv := encodedPair(t)
	seedAgentPair(t, ks.agentBackupDir("agent"), pub, priv)
	unremovableDir(t, ks.agentDir("agent"))

	err := ks.recoverAgentTransaction("agent")
	if err == nil {
		t.Fatal("recovery reported success without restoring the backup")
	}
	if !strings.Contains(err.Error(), "removing incomplete agent directory") {
		t.Errorf("error = %q, want it to name the directory it could not remove", err)
	}
}

func TestRecoverAgentTransactionForRead_NoBackupIsNoop(t *testing.T) {
	ks := NewKeystore(t.TempDir())
	pub, priv := encodedPair(t)
	seedAgentPair(t, ks.agentDir("agent"), pub, priv)

	if err := ks.recoverAgentTransactionForRead("agent"); err != nil {
		t.Fatalf("recoverAgentTransactionForRead: %v", err)
	}
	if !ks.agentKeyPairExists("agent") {
		t.Error("read-side recovery disturbed a settled agent")
	}
}

func TestRecoverAgentTransactionForRead_RestoresPendingBackup(t *testing.T) {
	ks := NewKeystore(t.TempDir())
	pub, priv := encodedPair(t)
	seedAgentPair(t, ks.agentBackupDir("agent"), pub, priv)
	if err := os.MkdirAll(ks.agentDir("agent"), dirPermission); err != nil {
		t.Fatalf("creating torn agent dir: %v", err)
	}

	if err := ks.recoverAgentTransactionForRead("agent"); err != nil {
		t.Fatalf("recoverAgentTransactionForRead: %v", err)
	}
	if !ks.agentKeyPairExists("agent") {
		t.Error("read-side recovery did not restore the pending backup")
	}
}

func TestLoadPrivateKey_ReportsMissingAgent(t *testing.T) {
	ks := NewKeystore(t.TempDir())
	if _, err := ks.LoadPrivateKey("absent"); err == nil {
		t.Error("LoadPrivateKey succeeded for an agent that does not exist")
	}
	if _, err := ks.LoadPublicKey("absent"); err == nil {
		t.Error("LoadPublicKey succeeded for an agent that does not exist")
	}
}

func TestLoadKeys_ReportUnrecoverableBackupState(t *testing.T) {
	ks := NewKeystore(t.TempDir())
	// A backup that cannot be cleared makes read-side recovery fail. The load
	// must surface that rather than fall through and report the key missing,
	// which would send an operator looking for the wrong problem.
	pub, priv := encodedPair(t)
	seedAgentPair(t, ks.agentDir("agent"), pub, priv)
	unremovableDir(t, ks.agentBackupDir("agent"))

	if _, err := ks.LoadPrivateKey("agent"); err == nil {
		t.Error("LoadPrivateKey ignored an unrecoverable transaction state")
	}
	if _, err := ks.LoadPublicKey("agent"); err == nil {
		t.Error("LoadPublicKey ignored an unrecoverable transaction state")
	}
}

func TestGenerateAgent_ReportsUnclearableStagingDirectory(t *testing.T) {
	ks := NewKeystore(t.TempDir())
	if err := os.MkdirAll(filepath.Join(ks.baseDir, agentsSubdir), dirPermission); err != nil {
		t.Fatalf("creating agents dir: %v", err)
	}
	// Residue from an interrupted run that cannot be cleared. Generation must
	// stop rather than stage a new pair into a directory it does not control.
	unremovableDir(t, ks.agentStageDir("agent"))

	_, err := ks.GenerateAgent("agent")
	if err == nil {
		t.Fatal("generation proceeded over an unclearable staging directory")
	}
	if !strings.Contains(err.Error(), "removing stale agent staging directory") {
		t.Errorf("error = %q, want it to name the staging directory", err)
	}
	if ks.AgentExists("agent") {
		t.Error("an identity was published despite the staging failure")
	}
}

func TestPublishAgentDirectoryPortable_RollsBackPriorPairOnInstallFailure(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "agent")
	stage := filepath.Join(root, "missing-stage")
	backup := filepath.Join(root, ".backup")

	// The staged directory does not exist, so the install fails and rollback
	// runs. Rollback is expected to SUCCEED here: publication renames the active
	// directory to the backup path before attempting the install, so by the time
	// the install fails the active path is free and the prior pair renames
	// straight back. The caller therefore gets the install error alone, and the
	// operator keeps a working identity, which is the contract that matters.
	// backup is a SCRATCH path this function creates and overwrites, not a place
	// to pre-stage anything: its first act is os.RemoveAll(backup). The prior
	// pair therefore lives at the ACTIVE path, which is what the real caller
	// does. Seeding the backup path instead destroys the pair on the first line
	// and tests nothing.
	seedAgentPair(t, target, []byte("prior-public"), []byte("prior-private"))

	err := publishAgentDirectoryPortable(target, stage, backup)
	if err == nil {
		t.Fatal("publication reported success with no staged directory")
	}
	if !strings.Contains(err.Error(), "installing staged agent directory") {
		t.Errorf("error = %q, want it to name the failed install", err)
	}

	// A rollback that reports the right error but loses the key pair is the
	// failure this transaction exists to prevent, so assert the pair is back
	// rather than trusting the error string.
	restored, readErr := os.ReadFile(filepath.Clean(filepath.Join(target, publicKeyFile)))
	if readErr != nil {
		t.Fatalf("prior public key was not restored: %v", readErr)
	}
	if string(restored) != "prior-public" {
		t.Errorf("restored public key = %q, want the prior pair back", restored)
	}
	if _, statErr := os.Stat(backup); !os.IsNotExist(statErr) {
		t.Errorf("backup survived a completed rollback (stat err = %v)", statErr)
	}
}
