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
	"strings"
	"testing"
	"time"
)

const replayLockTimeoutHelperEnv = "PIPELOCK_COUNTERPARTY_LOCK_TIMEOUT_HELPER"

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
	primaryReleased := false
	defer func() {
		if !primaryReleased {
			release()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestReplayStoreUnixLockTimeoutHelper$", "--", alias) // #nosec G204 G702 -- test re-execs its own binary with a t.TempDir() alias path
	cmd.Env = append(os.Environ(), replayLockTimeoutHelperEnv+"=1")
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Run(); err != nil {
		t.Fatalf("timeout helper on alias failed: %v output=%s", err, output.String())
	}

	release()
	primaryReleased = true

	aliasFile, err := os.OpenFile(alias, os.O_RDWR, 0o600) // #nosec G304 -- test path from t.TempDir()
	if err != nil {
		t.Fatalf("open alias for free lock: %v", err)
	}
	defer func() { _ = aliasFile.Close() }()
	releaseAlias, err := acquireReplayStoreLock(aliasFile)
	if err != nil {
		t.Fatalf("acquire alias lock after primary release: %v", err)
	}
	releaseAlias()
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

func TestReplayStoreUnixLockTimeoutFailsClosed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "replay.jsonl")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("seed replay store: %v", err)
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
	defer release()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestReplayStoreUnixLockTimeoutHelper$", "--", path) // #nosec G204 G702 -- test re-execs its own binary with a t.TempDir() path
	cmd.Env = append(os.Environ(), replayLockTimeoutHelperEnv+"=1")
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Run(); err != nil {
		t.Fatalf("timeout helper failed: %v output=%s", err, output.String())
	}
}

func TestReplayStoreUnixLockTimeoutHelper(t *testing.T) {
	if os.Getenv(replayLockTimeoutHelperEnv) == "" {
		return
	}
	if len(os.Args) == 0 {
		fmt.Fprintln(os.Stderr, "missing args")
		os.Exit(2)
	}
	replayStoreLockTimeout = 75 * time.Millisecond
	replayStoreLockRetryInterval = 5 * time.Millisecond
	path := os.Args[len(os.Args)-1]
	lockFile, err := os.OpenFile(path, os.O_RDWR, 0o600) // #nosec G304 -- test path from the parent test's t.TempDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "open contender for lock: %v\n", err)
		os.Exit(2)
	}
	defer func() { _ = lockFile.Close() }()
	release, err := acquireReplayStoreLock(lockFile)
	if err == nil {
		release()
		fmt.Fprintln(os.Stderr, "lock unexpectedly acquired")
		os.Exit(2)
	}
	if !strings.Contains(err.Error(), "timed out") {
		fmt.Fprintf(os.Stderr, "acquire lock error = %v, want timeout\n", err)
		os.Exit(2)
	}
	_, _ = fmt.Fprintln(os.Stdout, "timed out")
	os.Exit(0)
}
