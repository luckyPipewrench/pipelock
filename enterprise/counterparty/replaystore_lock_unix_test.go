//go:build enterprise && !windows && !js

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package counterparty

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

const replayLockAliasHelperEnv = "PIPELOCK_COUNTERPARTY_LOCK_ALIAS_HELPER"

func TestReplayStoreUnixLockFollowsSymlinkAlias(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "replay.jsonl")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("seed replay store: %v", err)
	}
	alias := filepath.Join(dir, "alias.jsonl")
	if err := os.Symlink(path, alias); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	lockFile, err := os.OpenFile(path, os.O_RDWR, 0o600) // #nosec G304 -- test path from t.TempDir()
	if err != nil {
		t.Fatalf("open store for lock: %v", err)
	}
	defer func() { _ = lockFile.Close() }()
	release, err := acquireReplayStoreLock(lockFile)
	if err != nil {
		t.Fatalf("acquire primary lock: %v", err)
	}
	released := false
	defer func() {
		if !released {
			release()
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestReplayStoreUnixLockAliasHelper$", "--", alias) // #nosec G204 G702 -- test re-execs its own binary with a t.TempDir() alias path
	cmd.Env = append(os.Environ(), replayLockAliasHelperEnv+"=1")
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		t.Fatalf("alias lock acquired while primary lock was held: err=%v output=%s", err, output.String())
	case <-time.After(150 * time.Millisecond):
	}

	release()
	released = true
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("helper after release: %v output=%s", err, output.String())
		}
	case <-time.After(2 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("helper did not acquire alias lock after primary release; output=%s", output.String())
	}
}

// TestFileReplayStoreFailsClosedAfterPathReplacement proves the inode-consistency
// guard: if the store file is renamed away and replaced, CommitIfNew fails closed
// instead of operating on a split inode (which would double-accept).
func TestFileReplayStoreFailsClosedAfterPathReplacement(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "replay.jsonl")
	store, err := OpenFileReplayStore(path)
	if err != nil {
		t.Fatalf("OpenFileReplayStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.CommitIfNew(sampleEntry("nonce-1", replayHashA)); err != nil {
		t.Fatalf("first CommitIfNew: %v", err)
	}

	// Replace the store file with a fresh inode at the same path.
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove store: %v", err)
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("recreate store: %v", err)
	}

	err = store.CommitIfNew(sampleEntry("nonce-2", replayHashB))
	if err == nil || errors.Is(err, ErrReplayConflict) {
		t.Fatalf("CommitIfNew after path replacement = %v, want a non-conflict fail-closed error", err)
	}
}

// TestFileReplayStoreFailsClosedAfterPathReplacementDuringCommit proves the
// post-fsync inode guard: replacing the configured path after the pre-commit
// inode check but before the append must not return a pass-shaped commit for an
// entry written to the old, now-unlinked inode.
func TestFileReplayStoreFailsClosedAfterPathReplacementDuringCommit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "replay.jsonl")
	store, err := OpenFileReplayStore(path)
	if err != nil {
		t.Fatalf("OpenFileReplayStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	store.mu.Lock()
	defer store.mu.Unlock()
	release, err := acquireReplayStoreLock(store.file)
	if err != nil {
		t.Fatalf("acquireReplayStoreLock: %v", err)
	}
	defer release()
	if err := verifyStorePathInode(store.file, store.path); err != nil {
		t.Fatalf("pre-commit verifyStorePathInode: %v", err)
	}

	if err := os.Remove(path); err != nil {
		t.Fatalf("remove store: %v", err)
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("recreate store: %v", err)
	}
	if err := store.reindexLocked(); err != nil {
		t.Fatalf("reindexLocked: %v", err)
	}

	_, err = store.appendEntryLocked(sampleEntry("nonce-1", replayHashA))
	if err == nil || errors.Is(err, ErrReplayConflict) {
		t.Fatalf("append after mid-commit path replacement = %v, want a non-conflict fail-closed error", err)
	}
}

func TestReplayStoreUnixLockAliasHelper(t *testing.T) {
	if os.Getenv(replayLockAliasHelperEnv) == "" {
		return
	}
	if len(os.Args) == 0 {
		fmt.Fprintln(os.Stderr, "missing args")
		os.Exit(2)
	}
	path := os.Args[len(os.Args)-1]
	lockFile, err := os.OpenFile(path, os.O_RDWR, 0o600) // #nosec G304 -- test path from the parent test's t.TempDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "open alias for lock: %v\n", err)
		os.Exit(2)
	}
	defer func() { _ = lockFile.Close() }()
	release, err := acquireReplayStoreLock(lockFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "acquire alias lock: %v\n", err)
		os.Exit(2)
	}
	release()
	_, _ = fmt.Fprintln(os.Stdout, "acquired")
	os.Exit(0)
}
