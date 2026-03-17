// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// acquireRulesLock acquires an advisory file lock using flock(2).
// Returns a release function and an error.
func acquireRulesLock(rulesDir string) (func(), error) {
	lockPath := filepath.Join(rulesDir, ".rules.lock")

	f, err := os.OpenFile(filepath.Clean(lockPath), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening lock file: %w", err)
	}

	fd := int(f.Fd()) //nolint:gosec // G115: file descriptors always fit in int
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("another rules command is running (lock: %s)", lockPath)
	}

	return func() {
		_ = syscall.Flock(fd, syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}
