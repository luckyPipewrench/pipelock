// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package commitmentkey

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func withLifecycleLock(keyringPath string, fn func() error) error {
	lockPath := filepath.Clean(keyringPath) + ".lock"
	if err := rejectSymlink(lockPath); err != nil {
		return fmt.Errorf("commitment keyring lock: %w", err)
	}
	root, err := os.OpenRoot(filepath.Dir(lockPath))
	if err != nil {
		return fmt.Errorf("open commitment keyring lock directory: %w", err)
	}
	defer func() { _ = root.Close() }()
	f, err := root.OpenFile(filepath.Base(lockPath), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open commitment keyring lock: %w", err)
	}
	defer func() { _ = f.Close() }()
	if err := f.Chmod(0o600); err != nil {
		return fmt.Errorf("secure commitment keyring lock: %w", err)
	}
	if uint64(f.Fd()) > uint64(^uint(0)>>1) {
		return fmt.Errorf("commitment keyring lock descriptor is out of range")
	}
	fd := int(f.Fd())
	if err := syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		return fmt.Errorf("acquire commitment keyring lock: %w", err)
	}
	defer func() { _ = syscall.Flock(fd, syscall.LOCK_UN) }()
	return fn()
}
