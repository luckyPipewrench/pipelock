// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// publishAgentDirectoryPortable is the key-publication path on every platform
// except Linux, so on this build it is never reached through generateAgent and
// would otherwise ship with no coverage at all. It compiles everywhere, so the
// tests below drive it directly. What they protect is the invariant the whole
// transaction exists for: the active agent directory must always hold one
// coherent key pair, never a mixture and never nothing.

func portableKeyPair(t *testing.T, dir, marker string) {
	t.Helper()
	if err := os.MkdirAll(dir, dirPermission); err != nil {
		t.Fatalf("creating %s: %v", dir, err)
	}
	for _, name := range []string{privateKeyFile, publicKeyFile} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(marker+"-"+name), 0o600); err != nil {
			t.Fatalf("writing %s: %v", path, err)
		}
	}
}

func readPairMarker(t *testing.T, dir string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(filepath.Join(dir, privateKeyFile)))
	if err != nil {
		t.Fatalf("reading published private key: %v", err)
	}
	return strings.TrimSuffix(string(data), "-"+privateKeyFile)
}

func TestPublishAgentDirectoryPortable_ReplacesActivePair(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "agent")
	stage := filepath.Join(root, ".stage")
	backup := filepath.Join(root, ".backup")

	portableKeyPair(t, target, "old")
	portableKeyPair(t, stage, "new")

	if err := publishAgentDirectoryPortable(target, stage, backup); err != nil {
		t.Fatalf("publishAgentDirectoryPortable: %v", err)
	}

	if got := readPairMarker(t, target); got != "new" {
		t.Errorf("published pair = %q, want the staged pair", got)
	}
	if _, err := os.Stat(filepath.Join(target, publicKeyFile)); err != nil {
		t.Errorf("public half missing after publication: %v", err)
	}
	if _, err := os.Stat(backup); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("backup survived a successful publication (stat err = %v)", err)
	}
	if _, err := os.Stat(stage); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("stage directory survived publication (stat err = %v)", err)
	}
}

func TestPublishAgentDirectoryPortable_CheckpointsRecoveryAndPublication(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "agent")
	stage := filepath.Join(root, ".stage")
	backup := filepath.Join(root, ".backup")

	portableKeyPair(t, target, "old")
	portableKeyPair(t, stage, "new")

	var checkpoints []string
	if err := publishAgentDirectoryPortableWithSync(target, stage, backup, func(path string) {
		checkpoints = append(checkpoints, path)
	}); err != nil {
		t.Fatalf("publishAgentDirectoryPortableWithSync: %v", err)
	}
	if len(checkpoints) != 2 || checkpoints[0] != root || checkpoints[1] != root {
		t.Errorf("directory checkpoints = %q, want recovery and publication checkpoints for %q", checkpoints, root)
	}
}

func TestPublishAgentDirectoryPortable_ClearsStaleBackup(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "agent")
	stage := filepath.Join(root, ".stage")
	backup := filepath.Join(root, ".backup")

	// A backup left behind by an interrupted earlier run must not block the
	// next publication, and must not be mistaken for the active pair.
	portableKeyPair(t, backup, "interrupted")
	portableKeyPair(t, target, "old")
	portableKeyPair(t, stage, "new")

	if err := publishAgentDirectoryPortable(target, stage, backup); err != nil {
		t.Fatalf("publishAgentDirectoryPortable: %v", err)
	}
	if got := readPairMarker(t, target); got != "new" {
		t.Errorf("published pair = %q, want the staged pair", got)
	}
}

func TestPublishAgentDirectoryPortable_RestoresPriorPairOnInstallFailure(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "agent")
	backup := filepath.Join(root, ".backup")
	// A stage path that does not exist makes the install rename fail after the
	// active directory has already been moved aside. That is the moment the
	// keystore is empty, and the rollback is the only thing standing between a
	// failed regenerate and a destroyed identity.
	stage := filepath.Join(root, "missing-stage")

	portableKeyPair(t, target, "old")

	var checkpoints []string
	err := publishAgentDirectoryPortableWithSync(target, stage, backup, func(path string) {
		checkpoints = append(checkpoints, path)
	})
	if err == nil {
		t.Fatal("publication succeeded with no staged directory")
	}
	if !strings.Contains(err.Error(), "installing staged agent directory") {
		t.Errorf("error = %q, want it to name the failed install", err)
	}
	if got := readPairMarker(t, target); got != "old" {
		t.Errorf("active pair = %q, want the prior pair restored", got)
	}
	if _, statErr := os.Stat(filepath.Join(target, publicKeyFile)); statErr != nil {
		t.Errorf("restored pair is missing its public half: %v", statErr)
	}
	if len(checkpoints) != 2 || checkpoints[0] != root || checkpoints[1] != root {
		t.Errorf("directory checkpoints = %q, want recovery and rollback checkpoints for %q", checkpoints, root)
	}
}

func TestPublishAgentDirectoryPortable_ReportsMissingActiveDirectory(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "absent")
	stage := filepath.Join(root, ".stage")
	backup := filepath.Join(root, ".backup")

	portableKeyPair(t, stage, "new")

	err := publishAgentDirectoryPortable(target, stage, backup)
	if err == nil {
		t.Fatal("publication succeeded with no active directory to back up")
	}
	if !strings.Contains(err.Error(), "backing up active agent directory") {
		t.Errorf("error = %q, want it to name the failed backup", err)
	}
}

func TestRemoveEmptyDirectory_RefusesPopulatedDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "agent")
	portableKeyPair(t, dir, "live")

	err := removeEmptyDirectory(dir)
	if err == nil {
		t.Fatal("removeEmptyDirectory removed a directory holding key material")
	}
	if !strings.Contains(err.Error(), "not empty") {
		t.Errorf("error = %q, want it to say the directory is not empty", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, privateKeyFile)); statErr != nil {
		t.Errorf("private key was removed from a populated directory: %v", statErr)
	}
}

func TestInstallStagedAgentDirectory_ClearsEmptyTargetAndRetries(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "agent")
	stage := filepath.Join(root, ".stage")

	// An empty directory at the target is the residue of a concurrent
	// preflight. It must be cleared and the rename retried, not treated as a
	// live pair worth preserving.
	if err := os.MkdirAll(target, dirPermission); err != nil {
		t.Fatalf("creating empty target: %v", err)
	}
	portableKeyPair(t, stage, "new")

	if err := installStagedAgentDirectory(target, stage); err != nil {
		t.Fatalf("installStagedAgentDirectory: %v", err)
	}
	if got := readPairMarker(t, target); got != "new" {
		t.Errorf("installed pair = %q, want the staged pair", got)
	}
}
