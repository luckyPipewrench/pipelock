// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// WithFreshnessLock acquires an exclusive flock on a lock file in rulesDir,
// runs fn, then releases the lock. Prevents concurrent pipelock processes
// from racing on the freshness state file.
func WithFreshnessLock(rulesDir string, fn func() error) error {
	lockPath := filepath.Join(rulesDir, freshnessFilename+".lock")
	f, err := os.OpenFile(filepath.Clean(lockPath), os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("freshness lock: %w", err)
	}
	defer func() { _ = f.Close() }()
	fd := int(f.Fd()) //nolint:gosec // Fd() returns a valid file descriptor, no overflow risk on 64-bit
	if err := syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		return fmt.Errorf("freshness lock acquire: %w", err)
	}
	defer func() { _ = syscall.Flock(fd, syscall.LOCK_UN) }()
	return fn()
}
