// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

const (
	errSharingViolation = syscall.Errno(32)
	errLockViolation    = syscall.Errno(33)
)

// acquireRulesLock acquires an exclusive lock file handle for mutating
// operations. On Windows, opening a file with share mode 0 prevents other
// processes from opening the same path until the handle is closed.
func acquireRulesLock(rulesDir string) (func(), error) {
	lockPath := filepath.Join(rulesDir, ".rules.lock")

	pathp, err := syscall.UTF16PtrFromString(lockPath)
	if err != nil {
		return nil, fmt.Errorf("encoding lock file path: %w", err)
	}

	handle, err := syscall.CreateFile(
		pathp,
		syscall.GENERIC_READ|syscall.GENERIC_WRITE,
		0,
		nil,
		syscall.OPEN_ALWAYS,
		syscall.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		if err == errSharingViolation || err == errLockViolation {
			return nil, fmt.Errorf("another rules command is running (lock: %s)", lockPath)
		}
		return nil, fmt.Errorf("opening lock file: %w", err)
	}

	f := os.NewFile(uintptr(handle), lockPath)
	if f == nil {
		_ = syscall.CloseHandle(handle)
		return nil, fmt.Errorf("creating lock file handle: %s", lockPath)
	}

	return func() {
		_ = f.Close()
	}, nil
}
