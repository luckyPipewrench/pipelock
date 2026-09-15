// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package contain

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestContainmentReconcileLockPathForDerivesFromRulesPath pins the shared
// derivation both install and reload use: the lock lives beside the rules
// file, so any test (or deployment) that changes rulesPath automatically
// gets a matching, collision-free lock path.
func TestContainmentReconcileLockPathForDerivesFromRulesPath(t *testing.T) {
	got := containmentReconcileLockPathFor("/etc/nftables.d/50-pipelock-containment.nft")
	want := "/etc/nftables.d/50-pipelock-containment.nft.reconcile.lock"
	if got != want {
		t.Fatalf("containmentReconcileLockPathFor() = %q, want %q", got, want)
	}
}

// TestWithContainmentReconcileLockRefusesSymlink is the MEDIUM-severity
// proof, half one: a symlink placed at the lock path (simulating a
// compromised or malicious writer of the lock's parent directory swapping
// the pathname) is refused via O_NOFOLLOW -- the open itself fails, never
// resolving the link -- rather than silently locking whatever it points to.
func TestWithContainmentReconcileLockRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("not a lock"), 0o600); err != nil {
		t.Fatalf("write symlink target: %v", err)
	}
	lockPath := filepath.Join(dir, "50-pipelock-containment.nft.reconcile.lock")
	if err := os.Symlink(target, lockPath); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	called := false
	err := withContainmentReconcileLock(lockPath, func() error {
		called = true
		return nil
	})
	if err == nil {
		t.Fatal("expected withContainmentReconcileLock to refuse a symlink at the lock path")
	}
	if called {
		t.Fatal("fn must not run when the lock file is refused")
	}
	if !strings.Contains(err.Error(), lockPath) || !strings.Contains(err.Error(), "pipelock contain install") {
		t.Fatalf("error = %v, want it to name the lock path and the recovery command", err)
	}
}

// TestWithContainmentReconcileLockRefusesFIFOWithoutBlocking is the
// MEDIUM-severity proof, half two: a FIFO placed at the lock path (the
// other way a hostile parent-directory writer could hang a root caller
// before it ever reaches Flock) is refused via the post-open fstat
// non-regular-file check, and the refusal is immediate -- proven by a hard
// deadline well under what a blocking open would need -- not merely
// "eventually returns," because O_RDWR is what keeps this open from
// blocking on a FIFO in the first place; a caller that opened O_WRONLY here
// would hang forever with no peer reader.
func TestWithContainmentReconcileLockRefusesFIFOWithoutBlocking(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "50-pipelock-containment.nft.reconcile.lock")
	if err := syscall.Mkfifo(lockPath, 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}

	done := make(chan error, 1)
	called := false
	go func() {
		done <- withContainmentReconcileLock(lockPath, func() error {
			called = true
			return nil
		})
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected withContainmentReconcileLock to refuse a FIFO at the lock path")
		}
		if called {
			t.Fatal("fn must not run when the lock file is refused")
		}
		if !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("error = %v, want it to name the non-regular-file refusal", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("withContainmentReconcileLock blocked on a FIFO instead of refusing it immediately via the fstat check")
	}
}

// TestWithContainmentReconcileLockRefusesForeignOwner proves the
// owner-verification half of the fstat check independently of file type:
// a plain regular file that is NOT owned by root or the invoking uid is
// refused even though O_NOFOLLOW and the regular-file check both pass.
func TestWithContainmentReconcileLockRefusesForeignOwner(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root to fabricate a foreign-uid lock file for this proof")
	}
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "50-pipelock-containment.nft.reconcile.lock")
	if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
		t.Fatalf("write lock file: %v", err)
	}
	if err := os.Chown(lockPath, 65534, 65534); err != nil { // nobody:nogroup
		t.Fatalf("chown lock file: %v", err)
	}
	err := withContainmentReconcileLock(lockPath, func() error {
		t.Fatal("fn must not run when the lock file is owned by neither root nor the invoking uid")
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "owned by uid") {
		t.Fatalf("error = %v, want the foreign-owner refusal", err)
	}
}

// TestWithContainmentReconcileLockRefusesUnwritableParentWithRecoveryError
// proves the plain unwritable-parent-directory failure (no attack, just a
// misconfigured/missing directory) also gets a hard error naming the
// recovery command, not a silent skip of locking.
func TestWithContainmentReconcileLockRefusesUnwritableParentWithRecoveryError(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "does-not-exist", "50-pipelock-containment.nft.reconcile.lock")
	err := withContainmentReconcileLock(lockPath, func() error {
		t.Fatal("fn must not run when the lock file cannot be opened at all")
		return nil
	})
	if err == nil {
		t.Fatal("expected an error for a lock path whose parent directory does not exist")
	}
	if !strings.Contains(err.Error(), lockPath) || !strings.Contains(err.Error(), "pipelock contain install") {
		t.Fatalf("error = %v, want it to name the lock path and the recovery command", err)
	}
}

// TestWithContainmentReconcileLockAcceptsOwnRegularFile is the non-attack
// control: a plain lock file this process (or root) already owns is
// accepted, fn runs exactly once, and repeated calls remain safe -- the
// hardening above must not make the ordinary, uncompromised path fail.
func TestWithContainmentReconcileLockAcceptsOwnRegularFile(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "50-pipelock-containment.nft.reconcile.lock")
	calls := 0
	for range 3 {
		if err := withContainmentReconcileLock(lockPath, func() error {
			calls++
			return nil
		}); err != nil {
			t.Fatalf("withContainmentReconcileLock: %v", err)
		}
	}
	if calls != 3 {
		t.Fatalf("fn ran %d times, want 3", calls)
	}
}
