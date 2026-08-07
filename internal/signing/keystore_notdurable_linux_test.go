// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package signing

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// denySyncOnParent makes a directory writable and traversable but unreadable.
// A rename into it still works, so the exchange commits, while opening it for
// fsync fails. That is the only state where publication succeeds and durability
// confirmation does not, and it needs no injected seam to produce.
func denySyncOnParent(t *testing.T, parent string) {
	t.Helper()
	skipIfChmodCannotDeny(t)
	if err := os.Chmod(parent, 0o300); err != nil { // #nosec G302 -- write and traverse must remain while read is removed
		t.Fatalf("restricting %s: %v", parent, err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o700) }) // #nosec G302 -- restore for cleanup
}

func TestPublishAgentDirectory_ReportsCommittedButNotDurable(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "agents")
	if err := os.MkdirAll(parent, dirPermission); err != nil {
		t.Fatalf("creating parent: %v", err)
	}
	target := filepath.Join(parent, "agent")
	stage := filepath.Join(parent, ".stage")
	seedAgentPair(t, target, []byte("old-public"), []byte("old-private"))
	seedAgentPair(t, stage, []byte("new-public"), []byte("new-private"))

	denySyncOnParent(t, parent)
	err := publishAgentDirectory(target, stage, filepath.Join(parent, ".backup"))
	_ = os.Chmod(parent, 0o700) // #nosec G302 -- inspect the result

	if err == nil {
		t.Fatal("publication reported success without confirming durability")
	}
	if !errors.Is(err, ErrPublishedNotDurable) {
		t.Fatalf("error = %v, want it to wrap ErrPublishedNotDurable so callers can tell it apart from a failed publication", err)
	}

	// The distinction is only worth anything if the exchange really did commit.
	active, readErr := os.ReadFile(filepath.Clean(filepath.Join(target, publicKeyFile)))
	if readErr != nil {
		t.Fatalf("reading active public key: %v", readErr)
	}
	if string(active) != "new-public" {
		t.Errorf("active public key = %q, want the new pair; if the exchange did not commit this error is the wrong one", active)
	}
}

func TestForceGenerateAgent_KeepsPriorPairWhenDurabilityIsUnconfirmed(t *testing.T) {
	ks := NewKeystore(t.TempDir())
	if _, err := ks.GenerateAgent("agent"); err != nil {
		t.Fatalf("seeding first identity: %v", err)
	}
	priorPub, err := os.ReadFile(filepath.Clean(filepath.Join(ks.agentDir("agent"), publicKeyFile)))
	if err != nil {
		t.Fatalf("reading prior public key: %v", err)
	}

	denySyncOnParent(t, filepath.Dir(ks.agentDir("agent")))
	_, genErr := ks.ForceGenerateAgent("agent")
	_ = os.Chmod(filepath.Dir(ks.agentDir("agent")), 0o700) // #nosec G302 -- inspect the result

	if genErr == nil {
		t.Skip("this platform confirmed durability despite the restricted parent")
	}
	if !errors.Is(genErr, ErrPublishedNotDurable) {
		t.Fatalf("error = %v, want ErrPublishedNotDurable", genErr)
	}

	// The regression this guards: the deferred cleanup used to delete the
	// staging directory unconditionally, and after the exchange that directory
	// holds the PREVIOUS pair. Losing it here destroys the only recoverable
	// copy at the exact moment durability is in doubt.
	backup := ks.agentBackupDir("agent")
	kept, readErr := os.ReadFile(filepath.Clean(filepath.Join(backup, publicKeyFile)))
	if readErr != nil {
		t.Fatalf("prior pair was not preserved for recovery: %v", readErr)
	}
	if string(kept) != string(priorPub) {
		t.Errorf("preserved public key = %q, want the prior pair %q", kept, priorPub)
	}

	// And the new identity really is live, which is why the error says so.
	if !ks.agentKeyPairExists("agent") {
		t.Error("active directory does not hold a coherent pair after a committed exchange")
	}
	activePub, readErr := os.ReadFile(filepath.Clean(filepath.Join(ks.agentDir("agent"), publicKeyFile)))
	if readErr != nil {
		t.Fatalf("reading active public key: %v", readErr)
	}
	if string(activePub) == string(priorPub) {
		t.Error("active public key is still the prior one, so the error misreports what happened")
	}
}
