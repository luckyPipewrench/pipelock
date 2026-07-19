//go:build enterprise && !windows && !js

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package counterparty

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// acquireReplayStoreLock takes an exclusive, cross-process advisory lock on the
// OPEN store file descriptor. Locking the fd (not a path-derived sibling) ties
// the lock to the same inode the store reads and writes, so path aliases
// (symlinks, relative paths, hardlinks) contend on the same inode and the lock
// cannot drift from the I/O target. The returned release closure unlocks. Lock
// acquisition is bounded so verification fails closed instead of hanging
// indefinitely behind a wedged peer.
func acquireReplayStoreLock(f *os.File) (func(), error) {
	fd := int(f.Fd()) // #nosec G115 -- file descriptors fit in int on supported Unix targets
	deadline := time.Now().Add(replayStoreLockTimeout)
	for {
		err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() { _ = syscall.Flock(fd, syscall.LOCK_UN) }, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			return nil, fmt.Errorf("acquire replay store lock: %w", err)
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("acquire replay store lock: timed out after %s: %w", replayStoreLockTimeout, err)
		}
		time.Sleep(replayStoreLockRetryInterval)
	}
}

// verifyStorePathInode fails closed if the configured path no longer resolves to
// the open file's inode (for example the store file was renamed away and a fresh
// file created in its place). Without this check the lock would guard the open
// inode while a second process operates on the replacement inode, splitting
// replay state and double-accepting records.
func verifyStorePathInode(f *os.File, path string) error {
	var fdStat, pathStat syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &fdStat); err != nil { // #nosec G115 -- fd fits in int
		return fmt.Errorf("fstat replay store: %w", err)
	}
	if err := syscall.Stat(filepath.Clean(path), &pathStat); err != nil {
		return fmt.Errorf("stat replay store path: %w", err)
	}
	if fdStat.Dev != pathStat.Dev || fdStat.Ino != pathStat.Ino {
		return errors.New("replay store path no longer resolves to the open store file")
	}
	return nil
}
