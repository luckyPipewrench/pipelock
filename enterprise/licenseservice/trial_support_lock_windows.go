//go:build enterprise && windows

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package licenseservice

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

func acquireTrialSupportLock(ctx context.Context, path string) (func(), error) {
	pathPointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, fmt.Errorf("encode trial support lock path: %w", err)
	}
	handle, err := windows.CreateFile(pathPointer, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, fmt.Errorf("open trial support lock: %w", err)
	}
	f := os.NewFile(uintptr(handle), path)
	if f == nil {
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf("create trial support lock handle: %s", path)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("stat trial support lock: %w", err)
	}
	if !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, fmt.Errorf("trial support lock is not a regular file: %s", path)
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("secure trial support lock: %w", err)
	}
	var overlapped windows.Overlapped
	retry := time.NewTicker(10 * time.Millisecond)
	defer retry.Stop()
	for {
		err = windows.LockFileEx(handle, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 0xffffffff, 0xffffffff, &overlapped)
		if err == nil {
			break
		}
		if !errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			_ = f.Close()
			return nil, fmt.Errorf("acquire trial support lock: %w", err)
		}
		select {
		case <-ctx.Done():
			_ = f.Close()
			return nil, fmt.Errorf("acquire trial support lock: %w", ctx.Err())
		case <-retry.C:
		}
	}
	return func() {
		_ = windows.UnlockFileEx(handle, 0, 0xffffffff, 0xffffffff, &overlapped)
		_ = f.Close()
	}, nil
}
