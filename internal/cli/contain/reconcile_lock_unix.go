// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package contain

import (
	"fmt"
	"os"
	"syscall"
)

// withContainmentReconcileLock acquires an exclusive flock on lockPath,
// runs fn, then releases the lock, whether or not fn returns an error. It
// serializes the critical section shared by `contain install` and `contain
// reload-nft-rules`: snapshot the managed config, compute the declared
// loopback services, apply the nft transaction, and persist the rules file.
// Without this, an install promoting a new managed config and a concurrent
// reload can interleave -- the reload reads config A, install writes config
// B and its rules, and the reload then re-applies and re-persists based on
// its stale A snapshot, silently restoring an entry B just revoked. The
// lock file is created if absent; it is never removed, matching the other
// flock-based locks in this repository (see internal/rules/freshness_unix.go).
func withContainmentReconcileLock(lockPath string, fn func() error) error {
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_WRONLY, modeConfigSecret) //nolint:gosec // G304: lockPath is a fixed operator/install-time constant, not attacker input.
	if err != nil {
		return fmt.Errorf("containment reconcile lock: open %s: %w", lockPath, err)
	}
	defer func() { _ = f.Close() }()
	fd := int(f.Fd()) //nolint:gosec // Fd() returns a valid file descriptor, no overflow risk on 64-bit.
	if err := syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		return fmt.Errorf("containment reconcile lock: acquire %s: %w", lockPath, err)
	}
	defer func() { _ = syscall.Flock(fd, syscall.LOCK_UN) }()
	return fn()
}
