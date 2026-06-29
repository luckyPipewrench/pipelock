// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package anchor

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

const (
	localLogErrSharingViolation = syscall.Errno(32)
	localLogErrLockViolation    = syscall.Errno(33)

	localLogLockTimeout = 2 * time.Second
	localLogLockPoll    = 20 * time.Millisecond
)

func acquireLocalLogLock(logPath string) (func(), error) {
	lockPath := filepath.Clean(logPath) + ".lock"
	if err := os.MkdirAll(filepath.Dir(lockPath), dirPermissions); err != nil {
		return nil, fmt.Errorf("create local anchor log lock directory: %w", err)
	}
	pathp, err := syscall.UTF16PtrFromString(lockPath)
	if err != nil {
		return nil, fmt.Errorf("encode local anchor log lock path: %w", err)
	}
	deadline := time.Now().Add(localLogLockTimeout)
	for {
		handle, createErr := syscall.CreateFile(
			pathp,
			syscall.GENERIC_READ|syscall.GENERIC_WRITE,
			0,
			nil,
			syscall.OPEN_ALWAYS,
			syscall.FILE_ATTRIBUTE_NORMAL,
			0,
		)
		if createErr == nil {
			f := os.NewFile(uintptr(handle), lockPath)
			if f == nil {
				_ = syscall.CloseHandle(handle)
				return nil, fmt.Errorf("create local anchor log lock handle: %s", lockPath)
			}
			return func() { _ = f.Close() }, nil
		}
		if !errors.Is(createErr, localLogErrSharingViolation) &&
			!errors.Is(createErr, localLogErrLockViolation) {
			return nil, fmt.Errorf("open local anchor log lock: %w", createErr)
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("local anchor log locked by another process: %s", lockPath)
		}
		time.Sleep(localLogLockPoll)
	}
}
