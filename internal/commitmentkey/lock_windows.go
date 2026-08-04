// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package commitmentkey

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

const exclusiveLock = 0x00000002

var (
	kernel32              = syscall.NewLazyDLL("kernel32.dll")
	lockFileExProcedure   = kernel32.NewProc("LockFileEx")
	unlockFileExProcedure = kernel32.NewProc("UnlockFileEx")
)

func withLifecycleLock(keyringPath string, fn func() error) error {
	lockPath := filepath.Clean(keyringPath) + ".lock"
	if err := rejectSymlink(lockPath); err != nil {
		return fmt.Errorf("commitment keyring lock: %w", err)
	}
	pathPointer, err := syscall.UTF16PtrFromString(lockPath)
	if err != nil {
		return fmt.Errorf("encode commitment keyring lock path: %w", err)
	}
	handle, err := syscall.CreateFile(pathPointer, syscall.GENERIC_READ|syscall.GENERIC_WRITE, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, nil, syscall.OPEN_ALWAYS, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return fmt.Errorf("open commitment keyring lock: %w", err)
	}
	f := os.NewFile(uintptr(handle), lockPath)
	if f == nil {
		_ = syscall.CloseHandle(handle)
		return fmt.Errorf("create commitment keyring lock handle: %s", lockPath)
	}
	defer func() { _ = f.Close() }()
	if err := f.Chmod(0o600); err != nil {
		return fmt.Errorf("secure commitment keyring lock: %w", err)
	}
	var overlapped syscall.Overlapped
	if err := callLockFileEx(handle, exclusiveLock, &overlapped); err != nil {
		return fmt.Errorf("acquire commitment keyring lock: %w", err)
	}
	defer func() { _ = callUnlockFileEx(handle, &overlapped) }()
	return fn()
}

func callLockFileEx(handle syscall.Handle, flags uint32, overlapped *syscall.Overlapped) error {
	result, _, err := lockFileExProcedure.Call(uintptr(handle), uintptr(flags), 0, 0xffffffff, 0xffffffff, uintptr(unsafe.Pointer(overlapped)))
	if result == 0 {
		return err
	}
	return nil
}

func callUnlockFileEx(handle syscall.Handle, overlapped *syscall.Overlapped) error {
	result, _, err := unlockFileExProcedure.Call(uintptr(handle), 0, 0xffffffff, 0xffffffff, uintptr(unsafe.Pointer(overlapped)))
	if result == 0 {
		return err
	}
	return nil
}
