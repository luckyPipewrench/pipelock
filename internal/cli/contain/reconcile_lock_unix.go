// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package contain

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// containmentReconcileLockRecovery is the operator remedy named in every
// refusal below: a lock file this code will not trust is exactly the state
// `contain install` already knows how to repair (it owns /etc/nftables.d/
// and re-derives everything under it).
const containmentReconcileLockRecovery = "rerun `pipelock contain install` to restore a safe lock file"

// withContainmentReconcileLock acquires an exclusive flock on lockPath,
// runs fn, then releases the lock, whether or not fn returns an error. It
// serializes the critical section shared by `contain install` and `contain
// reload-nft-rules`: snapshot the managed config, compute the declared
// loopback services, apply the nft transaction, and persist the rules file.
// Without this, an install promoting a new managed config and a concurrent
// reload can interleave -- the reload reads config A, install writes config
// B and its rules, and the reload then re-applies and re-persists based on
// its stale A snapshot, silently restoring an entry B just revoked.
//
// lockPath MUST live in a directory only root writes (see
// containmentReconcileLockPathFor: it sits beside the nft rules file under
// /etc/nftables.d/, never under the pipelock-proxy-owned data directory).
// The proxy identity is unprivileged relative to root but still a distinct,
// separately-compromisable account; if it could write the lock's parent
// directory, it could unlink and recreate the lock pathname (two root
// callers then flock different inodes and the race this lock exists to
// close comes back) or replace it with a FIFO so a boot-time O_WRONLY open
// blocks forever. openContainmentReconcileLockFile below refuses to trust
// anything at lockPath that is not a plain, root/self-owned regular file,
// so even a parent-directory compromise this code does not know about yet
// fails closed instead of silently accepting a swapped-out lock target.
func withContainmentReconcileLock(lockPath string, fn func() error) error {
	f, err := openContainmentReconcileLockFile(lockPath)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	fd := int(f.Fd()) //nolint:gosec // Fd() returns a valid file descriptor, no overflow risk on 64-bit.
	if err := syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		return fmt.Errorf("containment reconcile lock: acquire %s: %w; %s", lockPath, err, containmentReconcileLockRecovery)
	}
	defer func() { _ = syscall.Flock(fd, syscall.LOCK_UN) }()
	return fn()
}

// openContainmentReconcileLockFile opens (creating if absent) the lock file
// at lockPath and refuses to hand back anything unsafe to flock, BEFORE any
// Flock call:
//
//   - O_NOFOLLOW makes the open itself fail (ELOOP) if the final path
//     component is a symlink, so a symlink swap is refused without ever
//     resolving it.
//   - O_CREAT|O_RDWR|0o600 creates a plain, non-executable, owner-only file
//     when none exists yet; O_RDWR (rather than O_WRONLY/O_RDONLY) also
//     means opening a FIFO here does not block waiting for a reader/writer
//     on the other end, so a FIFO swap cannot hang the caller before the
//     mode check below runs.
//   - The post-open Fstat rejects anything that is not a regular file
//     (catches a FIFO, device node, socket, or directory placed at
//     lockPath) and rejects a file not owned by root or the invoking uid
//     (catches a lock file some other, non-root identity created or took
//     over, even one that happens to be a regular file).
//
// Every refusal is a hard error naming lockPath and the recovery command;
// none of them silently proceed without the lock.
func openContainmentReconcileLockFile(lockPath string) (*os.File, error) {
	f, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600) //nolint:gosec // G304: lockPath is a fixed operator/install-time constant, not attacker input; O_NOFOLLOW below refuses a symlink at that path.
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// The lock's parent directory (the nft rules directory) does
			// not exist. `contain install` creates it BEFORE ever
			// acquiring this lock (ensureNFTRulesDirSafe), so this
			// should only be reached by `contain reload-nft-rules` on a
			// host that has never completed an install.
			return nil, fmt.Errorf("containment reconcile lock: directory %s is missing; %s", filepath.Dir(lockPath), containmentReconcileLockRecovery)
		}
		return nil, fmt.Errorf("containment reconcile lock: open %s refused: %w; %s", lockPath, err, containmentReconcileLockRecovery)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("containment reconcile lock: stat %s: %w; %s", lockPath, err, containmentReconcileLockRecovery)
	}
	if !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, fmt.Errorf("containment reconcile lock: %s is not a regular file (mode %v); refusing to lock it; %s", lockPath, info.Mode(), containmentReconcileLockRecovery)
	}
	sys, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		_ = f.Close()
		return nil, fmt.Errorf("containment reconcile lock: cannot verify the owner of %s; %s", lockPath, containmentReconcileLockRecovery)
	}
	invokingUID := uint32(os.Getuid()) //nolint:gosec // Getuid() is always non-negative on every supported platform.
	if sys.Uid != 0 && sys.Uid != invokingUID {
		_ = f.Close()
		return nil, fmt.Errorf("containment reconcile lock: %s is owned by uid %d, not root or the invoking uid %d; refusing to lock it; %s", lockPath, sys.Uid, invokingUID, containmentReconcileLockRecovery)
	}
	return f, nil
}
