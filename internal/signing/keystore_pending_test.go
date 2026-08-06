// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A reader that arrives while a publication is in flight retries once rather
// than reporting the identity missing. These cover what happens when the retry
// does not help, which is the case that must not turn into a confident "no such
// key" while another process is mid-swap.

// danglingBackup leaves a backup path that Lstat sees but Stat does not, which
// is what a reader observes in the window between the backup being renamed away
// and the new pair landing. Recovery correctly treats it as nothing to restore,
// so the pending marker persists for the duration of the load.
func danglingBackup(t *testing.T, ks *Keystore, name string) {
	t.Helper()
	if err := os.MkdirAll(ks.agentDir(name), dirPermission); err != nil {
		t.Fatalf("creating agent dir: %v", err)
	}
	target := filepath.Join(ks.baseDir, agentsSubdir, "vanished")
	if err := os.Symlink(target, ks.agentBackupDir(name)); err != nil {
		t.Skipf("cannot create symlink on this filesystem: %v", err)
	}
}

func TestLoadPrivateKey_ReportsUnavailableDuringPublication(t *testing.T) {
	ks := NewKeystore(t.TempDir())
	danglingBackup(t, ks, "agent")

	_, err := ks.LoadPrivateKey("agent")
	if err == nil {
		t.Fatal("LoadPrivateKey returned a key that does not exist")
	}
	if !strings.Contains(err.Error(), "unavailable during concurrent key publication") {
		t.Errorf("error = %q, want it to name the in-flight publication rather than a missing key", err)
	}
}

func TestLoadPublicKey_ReportsUnavailableDuringPublication(t *testing.T) {
	ks := NewKeystore(t.TempDir())
	danglingBackup(t, ks, "agent")

	_, err := ks.LoadPublicKey("agent")
	if err == nil {
		t.Fatal("LoadPublicKey returned a key that does not exist")
	}
	if !strings.Contains(err.Error(), "unavailable during concurrent key publication") {
		t.Errorf("error = %q, want it to name the in-flight publication rather than a missing key", err)
	}
}

func TestWriteAgentKeyPair_ReportsPublicKeyFailure(t *testing.T) {
	dir := t.TempDir()
	// A directory sitting at the public key path lets the private key write
	// succeed and the public one fail, which is the asymmetric failure the
	// staged transaction has to catch before anything is published.
	if err := os.Mkdir(filepath.Join(dir, publicKeyFile), dirPermission); err != nil {
		t.Fatalf("creating colliding directory: %v", err)
	}

	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	writeErr := writeAgentKeyPair(dir, pub, priv)
	if writeErr == nil {
		t.Fatal("key pair written with a directory at the public key path")
	}
	if !strings.Contains(writeErr.Error(), "saving public key") {
		t.Errorf("error = %q, want it to name the failed public key write", writeErr)
	}
}

func TestGenerateAgent_ReportsPublicationFailure(t *testing.T) {
	ks := NewKeystore(t.TempDir())
	// Write the pair, then remove the staging directory out from under the
	// publish step. The exchange has nothing to swap in and the failure must
	// reach the caller instead of leaving a silently unpublished identity.
	ks.writeAgentPair = func(dir string, pub ed25519.PublicKey, priv ed25519.PrivateKey) error {
		if err := writeAgentKeyPair(dir, pub, priv); err != nil {
			return err
		}
		return os.RemoveAll(dir)
	}

	_, err := ks.GenerateAgent("agent")
	if err == nil {
		t.Fatal("generation reported success without publishing a pair")
	}
	if !strings.Contains(err.Error(), "publishing agent key pair") {
		t.Errorf("error = %q, want it to name the failed publication", err)
	}
	if ks.AgentExists("agent") {
		t.Error("an identity was published despite the publication failure")
	}
}
