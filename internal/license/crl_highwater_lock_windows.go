// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package license

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

const (
	crlHighWaterErrSharingViolation = syscall.Errno(32)
	crlHighWaterErrLockViolation    = syscall.Errno(33)

	// crlHighWaterLockTimeout bounds how long we wait for another process to
	// release the lock. The critical section is a tiny atomic write, so real
	// contention clears in milliseconds; the timeout only guards against a
	// wedged holder rather than failing instantly on a benign race.
	crlHighWaterLockTimeout = 2 * time.Second
	crlHighWaterLockPoll    = 20 * time.Millisecond
)

func acquireCRLHighWaterLock(crlFile string) (func(), error) {
	lockPath := CRLHighWaterPath(crlFile) + ".lock"
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o750); err != nil {
		return nil, fmt.Errorf("create license CRL high-water lock dir: %w", err)
	}
	pathp, err := syscall.UTF16PtrFromString(lockPath)
	if err != nil {
		return nil, fmt.Errorf("encode license CRL high-water lock path: %w", err)
	}
	// CreateFile with an exclusive share mode fails immediately on a
	// sharing/lock violation rather than blocking, so poll briefly to tolerate
	// the tiny window another process holds the lock. This mirrors the blocking
	// flock on Unix and avoids surfacing benign concurrent verification (an
	// operator CLI command running alongside the runtime's periodic CRL check)
	// as a fail-closed teardown.
	deadline := time.Now().Add(crlHighWaterLockTimeout)
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
				return nil, fmt.Errorf("create license CRL high-water lock handle: %s", lockPath)
			}
			return func() { _ = f.Close() }, nil
		}
		if !errors.Is(createErr, crlHighWaterErrSharingViolation) &&
			!errors.Is(createErr, crlHighWaterErrLockViolation) {
			return nil, fmt.Errorf("open license CRL high-water lock: %w", createErr)
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("license CRL high-water locked by another process: %s", lockPath)
		}
		time.Sleep(crlHighWaterLockPoll)
	}
}
