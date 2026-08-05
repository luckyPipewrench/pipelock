// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package commitmentkey

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func withLifecycleLock(keyringPath string, fn func() error) error {
	lockPath := filepath.Clean(keyringPath) + ".lock"
	if err := ensureParent(lockPath); err != nil {
		return fmt.Errorf("commitment keyring lock: %w", err)
	}
	if err := validateWindowsFinal(lockPath); err != nil {
		return fmt.Errorf("commitment keyring lock: %w", err)
	}
	pathPointer, err := windows.UTF16PtrFromString(lockPath)
	if err != nil {
		return fmt.Errorf("encode commitment keyring lock path: %w", err)
	}
	handle, err := windows.CreateFile(pathPointer, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return fmt.Errorf("open commitment keyring lock: %w", err)
	}
	f := os.NewFile(uintptr(handle), lockPath)
	if f == nil {
		_ = windows.CloseHandle(handle)
		return fmt.Errorf("create commitment keyring lock handle: %s", lockPath)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat commitment keyring lock: %w", err)
	}
	if isWindowsReparse(info) || !info.Mode().IsRegular() {
		return fmt.Errorf("%w: commitment keyring lock is a reparse point or not a regular file", ErrSymlink)
	}
	if err := f.Chmod(0o600); err != nil {
		return fmt.Errorf("secure commitment keyring lock: %w", err)
	}
	var overlapped windows.Overlapped
	if err := windows.LockFileEx(handle, windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 0xffffffff, 0xffffffff, &overlapped); err != nil {
		return fmt.Errorf("acquire commitment keyring lock: %w", err)
	}
	defer func() { _ = windows.UnlockFileEx(handle, 0, 0xffffffff, 0xffffffff, &overlapped) }()
	return fn()
}
