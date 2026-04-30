// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package store

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

const lockfileExclusiveLock = 0x00000002

var (
	kernel32Proc     = syscall.NewLazyDLL("kernel32.dll")
	procLockFileEx   = kernel32Proc.NewProc("LockFileEx")
	procUnlockFileEx = kernel32Proc.NewProc("UnlockFileEx")
)

func (s Store) withLock(fn func() error) error {
	if err := os.MkdirAll(s.root, dirPerm); err != nil {
		return fmt.Errorf("create contract store root: %w", err)
	}
	lockPath := filepath.Join(s.root, ".lock")
	pathp, err := syscall.UTF16PtrFromString(lockPath)
	if err != nil {
		return fmt.Errorf("encode contract store lock path: %w", err)
	}
	handle, err := syscall.CreateFile(
		pathp,
		syscall.GENERIC_READ|syscall.GENERIC_WRITE,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,
		nil,
		syscall.OPEN_ALWAYS,
		syscall.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return fmt.Errorf("open contract store lock: %w", err)
	}
	f := os.NewFile(uintptr(handle), lockPath)
	if f == nil {
		_ = syscall.CloseHandle(handle)
		return fmt.Errorf("create contract store lock handle: %s", lockPath)
	}
	defer func() { _ = f.Close() }()
	var overlapped syscall.Overlapped
	if err := lockFileEx(handle, lockfileExclusiveLock, 0xffffffff, 0xffffffff, &overlapped); err != nil {
		return fmt.Errorf("acquire contract store lock: %w", err)
	}
	defer func() { _ = unlockFileEx(handle, 0xffffffff, 0xffffffff, &overlapped) }()
	return fn()
}

func lockFileEx(handle syscall.Handle, flags, lowBytes, highBytes uint32, overlapped *syscall.Overlapped) error {
	r1, _, err := procLockFileEx.Call(
		uintptr(handle),
		uintptr(flags),
		0,
		uintptr(lowBytes),
		uintptr(highBytes),
		uintptr(unsafe.Pointer(overlapped)),
	)
	if r1 == 0 {
		return err
	}
	return nil
}

func unlockFileEx(handle syscall.Handle, lowBytes, highBytes uint32, overlapped *syscall.Overlapped) error {
	r1, _, err := procUnlockFileEx.Call(
		uintptr(handle),
		0,
		uintptr(lowBytes),
		uintptr(highBytes),
		uintptr(unsafe.Pointer(overlapped)),
	)
	if r1 == 0 {
		return err
	}
	return nil
}
