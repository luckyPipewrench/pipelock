// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The containment checks are what stop a symlinked keystore path from moving
// key material outside the directory the operator thinks holds it. Each case
// plants a link that escapes and asserts the operation refuses.

func TestPublishAgentDirectory_ReportsExchangeFailure(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "agent")
	backup := filepath.Join(root, ".backup")
	if err := os.MkdirAll(target, dirPermission); err != nil {
		t.Fatalf("creating target: %v", err)
	}

	// No staged directory: the atomic exchange has nothing to swap in, and the
	// error must reach the caller rather than leave a silently unpublished pair.
	err := publishAgentDirectory(target, filepath.Join(root, "missing-stage"), backup)
	if err == nil {
		t.Fatal("publication reported success with no staged directory")
	}
}

func TestWriteAgentKeyPair_ReportsUnwritableDirectory(t *testing.T) {
	skipIfChmodCannotDeny(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil { // #nosec G302 -- directory must stay traversable while write access is removed
		t.Fatalf("restricting dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) // #nosec G302 -- restore private directory traversal for cleanup

	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	writeErr := writeAgentKeyPair(dir, pub, priv)
	if writeErr == nil {
		t.Fatal("key pair written into an unwritable directory")
	}
	if !strings.Contains(writeErr.Error(), "saving private key") {
		t.Errorf("error = %q, want it to name the failed private key write", writeErr)
	}
}

func TestRecoverAgentTransaction_RefusesBackupOutsideKeystore(t *testing.T) {
	base := t.TempDir()
	outside := t.TempDir()
	ks := NewKeystore(base)

	pub, priv := encodedPair(t)
	seedAgentPair(t, ks.agentDir("agent"), pub, priv)

	// A backup path that resolves outside the keystore would let recovery pull
	// key material from somewhere the operator never authorized.
	escaped := filepath.Join(outside, "planted")
	seedAgentPair(t, escaped, pub, priv)
	if err := os.Symlink(escaped, ks.agentBackupDir("agent")); err != nil {
		t.Skipf("cannot create symlink on this filesystem: %v", err)
	}

	err := ks.recoverAgentTransaction("agent")
	if err == nil {
		t.Fatal("recovery accepted a backup resolving outside the keystore")
	}
	if !strings.Contains(err.Error(), "containment") {
		t.Errorf("error = %q, want it to name the containment failure", err)
	}
}

func TestLoadKeys_RefuseKeyFileResolvingOutsideKeystore(t *testing.T) {
	base := t.TempDir()
	outside := t.TempDir()
	ks := NewKeystore(base)

	pub, priv := encodedPair(t)
	seedAgentPair(t, ks.agentDir("agent"), pub, priv)

	plantedPriv := filepath.Join(outside, "id_ed25519")
	if err := os.WriteFile(plantedPriv, priv, 0o600); err != nil {
		t.Fatalf("planting private key: %v", err)
	}
	if err := os.Remove(filepath.Join(ks.agentDir("agent"), privateKeyFile)); err != nil {
		t.Fatalf("removing in-keystore private key: %v", err)
	}
	if err := os.Symlink(plantedPriv, filepath.Join(ks.agentDir("agent"), privateKeyFile)); err != nil {
		t.Skipf("cannot create symlink on this filesystem: %v", err)
	}

	if _, err := ks.LoadPrivateKey("agent"); err == nil {
		t.Error("LoadPrivateKey followed a key symlink out of the keystore")
	}

	plantedPub := filepath.Join(outside, "id_ed25519.pub")
	if err := os.WriteFile(plantedPub, pub, 0o600); err != nil {
		t.Fatalf("planting public key: %v", err)
	}
	if err := os.Remove(filepath.Join(ks.agentDir("agent"), publicKeyFile)); err != nil {
		t.Fatalf("removing in-keystore public key: %v", err)
	}
	if err := os.Symlink(plantedPub, filepath.Join(ks.agentDir("agent"), publicKeyFile)); err != nil {
		t.Skipf("cannot create symlink on this filesystem: %v", err)
	}
	if _, err := ks.LoadPublicKey("agent"); err == nil {
		t.Error("LoadPublicKey followed a key symlink out of the keystore")
	}
}

func TestRecoverAgentTransactionForRead_RefusesAgentsDirOutsideKeystore(t *testing.T) {
	base := t.TempDir()
	outside := t.TempDir()
	ks := NewKeystore(base)

	// The whole agents directory resolves outside the keystore. Read-side
	// recovery must refuse before taking a lock in a directory it does not own.
	if err := os.Symlink(outside, filepath.Join(base, agentsSubdir)); err != nil {
		t.Skipf("cannot create symlink on this filesystem: %v", err)
	}
	pub, priv := encodedPair(t)
	seedAgentPair(t, filepath.Join(outside, agentBackupPrefix+"agent"), pub, priv)

	err := ks.recoverAgentTransactionForRead("agent")
	if err == nil {
		t.Fatal("read-side recovery accepted an agents directory outside the keystore")
	}
	if !strings.Contains(err.Error(), "containment") {
		t.Errorf("error = %q, want it to name the containment failure", err)
	}
}

func TestGenerateAgent_RefusesAgentDirOutsideKeystore(t *testing.T) {
	base := t.TempDir()
	outside := t.TempDir()
	ks := NewKeystore(base)

	if err := os.MkdirAll(filepath.Join(base, agentsSubdir), dirPermission); err != nil {
		t.Fatalf("creating agents dir: %v", err)
	}
	escaped := filepath.Join(outside, "agent")
	if err := os.MkdirAll(escaped, dirPermission); err != nil {
		t.Fatalf("creating escape target: %v", err)
	}
	if err := os.Symlink(escaped, ks.agentDir("agent")); err != nil {
		t.Skipf("cannot create symlink on this filesystem: %v", err)
	}

	if _, err := ks.GenerateAgent("agent"); err == nil {
		t.Fatal("generation wrote through a symlink escaping the keystore")
	}
	if _, err := os.Stat(filepath.Join(escaped, privateKeyFile)); err == nil {
		t.Error("a private key was written outside the keystore")
	}
}
