// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The transaction's whole purpose is to behave correctly when something fails
// partway. These drive the failure branches directly, because a rollback path
// that has never executed is a rollback path nobody knows works.

func TestWithAgentLock_RefusesSymlinkedLockPath(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatalf("creating symlink target: %v", err)
	}
	lockPath := filepath.Join(dir, "lock")
	if err := os.Symlink(target, lockPath); err != nil {
		t.Skipf("cannot create symlink on this filesystem: %v", err)
	}

	called := false
	err := withAgentLock(lockPath, func() error {
		called = true
		return nil
	})
	if err == nil {
		t.Fatal("withAgentLock followed a symlinked lock path")
	}
	if !strings.Contains(err.Error(), "opening agent key lock") {
		t.Errorf("error = %q, want it to name the failed open", err)
	}
	if called {
		t.Error("the critical section ran through a symlinked lock")
	}
}

func TestWithAgentLock_PropagatesCriticalSectionError(t *testing.T) {
	sentinel := errors.New("inner failure")
	err := withAgentLock(filepath.Join(t.TempDir(), "lock"), func() error {
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Errorf("error = %v, want the critical section error to propagate", err)
	}
}

func TestGenerateAgent_KeyWriteFailureLeavesNoIdentity(t *testing.T) {
	ks := NewKeystore(t.TempDir())
	// Fail the key write after staging has been created. Nothing may reach the
	// active directory, because a half-written pair is precisely the state this
	// transaction exists to make impossible.
	ks.writeAgentPair = func(string, ed25519.PublicKey, ed25519.PrivateKey) error {
		return fmt.Errorf("simulated key write failure")
	}

	if _, err := ks.GenerateAgent("agent"); err == nil {
		t.Fatal("generation succeeded despite a key write failure")
	}
	if ks.AgentExists("agent") {
		t.Error("a failed generation published an identity")
	}
	// The agent directory itself is created before the lock is taken, so its
	// presence is expected and harmless. What must not exist is key material.
	for _, name := range []string{privateKeyFile, publicKeyFile} {
		path := filepath.Join(ks.agentDir("agent"), name)
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s was published by a failed generation (stat err = %v)", name, err)
		}
	}
	if _, err := os.Stat(ks.agentStageDir("agent")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("staging directory leaked after a failed write (stat err = %v)", err)
	}
}

func TestForceGenerateAgent_WriteFailureKeepsPriorPair(t *testing.T) {
	ks := NewKeystore(t.TempDir())
	pub, err := ks.GenerateAgent("agent")
	if err != nil {
		t.Fatalf("seeding identity: %v", err)
	}

	// A force-regenerate that cannot write the new pair must leave the old one
	// intact. Destroying a working identity on a failed rotation is worse than
	// the failed rotation.
	ks.writeAgentPair = func(string, ed25519.PublicKey, ed25519.PrivateKey) error {
		return fmt.Errorf("simulated key write failure")
	}
	if _, err := ks.ForceGenerateAgent("agent"); err == nil {
		t.Fatal("force regeneration succeeded despite a key write failure")
	}

	ks.writeAgentPair = nil
	got, err := ks.ResolvePublicKey("agent")
	if err != nil {
		t.Fatalf("prior identity unusable after a failed rotation: %v", err)
	}
	if !got.Equal(pub) {
		t.Error("prior public key changed after a failed rotation")
	}
}

func TestRejectAgentKeyPathCollisions_RefusesDirectoryAtKeyPath(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, privateKeyFile), dirPermission); err != nil {
		t.Fatalf("creating colliding directory: %v", err)
	}

	err := rejectAgentKeyPathCollisions(dir)
	if err == nil {
		t.Fatal("a directory occupying the private key path was accepted")
	}
	if !strings.Contains(err.Error(), "target path is a directory") {
		t.Errorf("error = %q, want it to name the directory collision", err)
	}
}

func TestGenerateAgent_RefusesDirectoryAtKeyPath(t *testing.T) {
	ks := NewKeystore(t.TempDir())
	agentDir := ks.agentDir("agent")
	if err := os.MkdirAll(filepath.Join(agentDir, publicKeyFile), dirPermission); err != nil {
		t.Fatalf("creating colliding directory: %v", err)
	}

	if _, err := ks.GenerateAgent("agent"); err == nil {
		t.Fatal("generation proceeded over a directory at the public key path")
	}
}

func TestLoadPrivateKey_RecoversThroughPendingBackup(t *testing.T) {
	ks := NewKeystore(t.TempDir())
	// A reader arriving mid-publication sees a backup and an incomplete active
	// directory. It must recover and return the prior key rather than report
	// the identity missing.
	pub, priv := encodedPair(t)
	seedAgentPair(t, ks.agentBackupDir("agent"), pub, priv)
	if err := os.MkdirAll(ks.agentDir("agent"), dirPermission); err != nil {
		t.Fatalf("creating torn agent dir: %v", err)
	}

	got, err := ks.LoadPrivateKey("agent")
	if err != nil {
		t.Fatalf("LoadPrivateKey during pending publication: %v", err)
	}
	if len(got) == 0 {
		t.Error("recovered private key is empty")
	}

	gotPub, err := ks.LoadPublicKey("agent")
	if err != nil {
		t.Fatalf("LoadPublicKey during pending publication: %v", err)
	}
	if len(gotPub) == 0 {
		t.Error("recovered public key is empty")
	}
}

func TestLoadPrivateKey_RejectsInvalidAgentName(t *testing.T) {
	ks := NewKeystore(t.TempDir())
	if _, err := ks.LoadPrivateKey("../escape"); err == nil {
		t.Error("LoadPrivateKey accepted a traversal agent name")
	}
	if _, err := ks.LoadPublicKey("../escape"); err == nil {
		t.Error("LoadPublicKey accepted a traversal agent name")
	}
}

func TestPublishAgentDirectoryPortable_ReportsUnremovableBackup(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "agent")
	stage := filepath.Join(root, ".stage")
	holder := filepath.Join(root, "holder")
	backup := filepath.Join(holder, ".backup")

	seedAgentPair(t, target, []byte("p"), []byte("k"))
	seedAgentPair(t, stage, []byte("p"), []byte("k"))
	seedAgentPair(t, backup, []byte("p"), []byte("k"))

	// A read-only parent makes the stale backup impossible to clear. The
	// publication must stop before touching the active pair.
	if err := os.Chmod(holder, 0o500); err != nil { // #nosec G302 -- directory must stay traversable while write access is removed
		t.Fatalf("restricting backup parent: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(holder, 0o700) }) // #nosec G302 -- restore private directory traversal for cleanup
	skipIfChmodCannotDeny(t)

	err := publishAgentDirectoryPortable(target, stage, backup)
	if err == nil {
		t.Fatal("publication proceeded despite an unclearable stale backup")
	}
	if !strings.Contains(err.Error(), "removing stale agent backup") {
		t.Errorf("error = %q, want it to name the stale backup", err)
	}
	if _, statErr := os.Stat(filepath.Join(target, privateKeyFile)); statErr != nil {
		t.Errorf("active pair was disturbed by a failed publication: %v", statErr)
	}
}
