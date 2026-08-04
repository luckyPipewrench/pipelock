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
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600) //nolint:gosec // operator-selected state path; symlinks are rejected above
	if err != nil {
		return fmt.Errorf("open commitment keyring lock: %w", err)
	}
	defer func() { _ = f.Close() }()
	if err := f.Chmod(0o600); err != nil {
		return fmt.Errorf("secure commitment keyring lock: %w", err)
	}
	fd := int(f.Fd()) //nolint:gosec // file descriptors fit in int on supported Unix targets
	if err := syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		return fmt.Errorf("acquire commitment keyring lock: %w", err)
	}
	defer func() { _ = syscall.Flock(fd, syscall.LOCK_UN) }()
	return fn()
}
