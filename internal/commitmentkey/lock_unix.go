// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package commitmentkey

import (
	"fmt"
	"path/filepath"
	"syscall"
)

func withLifecycleLock(keyringPath string, fn func() error) error {
	lockPath := filepath.Clean(keyringPath) + ".lock"
	f, err := openSecureLock(lockPath)
	if err != nil {
		return fmt.Errorf("open commitment keyring lock: %w", err)
	}
	defer func() { _ = f.Close() }()
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
