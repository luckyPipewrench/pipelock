// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package signing

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func withAgentLock(path string, fn func() error) error {
	clean := filepath.Clean(path)
	p, err := windows.UTF16PtrFromString(clean)
	if err != nil {
		return fmt.Errorf("encoding agent key lock path: %w", err)
	}
	handle, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return fmt.Errorf("opening agent key lock: %w", err)
	}
	f := os.NewFile(uintptr(handle), clean)
	if f == nil {
		_ = windows.CloseHandle(handle)
		return fmt.Errorf("opening agent key lock: invalid handle")
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("checking agent key lock: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("agent key lock is a reparse point or not a regular file")
	}
	if err := f.Chmod(0o600); err != nil {
		return fmt.Errorf("securing agent key lock: %w", err)
	}
	var overlapped windows.Overlapped
	if err := windows.LockFileEx(handle, windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 0xffffffff, 0xffffffff, &overlapped); err != nil {
		return fmt.Errorf("acquiring agent key lock: %w", err)
	}
	defer func() { _ = windows.UnlockFileEx(handle, 0, 0xffffffff, 0xffffffff, &overlapped) }()
	return fn()
}
