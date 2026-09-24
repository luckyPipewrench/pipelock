// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package hermes

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// withHermesLock holds an exclusive flock on the Hermes config's directory
// for fn. One lock per config directory serializes every install and rollback
// that edits it, including the agent-browser defaults and their ownership
// record, so concurrent runs cannot interleave and strand a flag or a record.
//
// The directory itself is locked rather than a lock file beside the config:
// its inode is stable (config.yaml is replaced by atomic rename, so locking
// the file would lock a stale inode), and a refused install must leave no new
// file behind. A directory that is not owned by the invoking user or root is
// refused before locking.
func withHermesLock(hermesConfig string, fn func() error) error {
	dir := filepath.Dir(hermesConfig)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("hermes lock: create %s: %w", dir, err)
	}
	f, err := os.OpenFile(filepath.Clean(dir), os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("hermes lock: open %s: %w", dir, err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("hermes lock: stat %s: %w", dir, err)
	}
	sys, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("hermes lock: cannot verify the config directory owner")
	}
	if sys.Uid != 0 && int(sys.Uid) != os.Getuid() {
		return fmt.Errorf("hermes lock: %s is owned by uid %d, not root or the invoking uid %d", dir, sys.Uid, os.Getuid())
	}
	fd := int(f.Fd())
	if err := syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		return fmt.Errorf("hermes lock: acquire %s: %w", dir, err)
	}
	defer func() { _ = syscall.Flock(fd, syscall.LOCK_UN) }()
	return fn()
}
