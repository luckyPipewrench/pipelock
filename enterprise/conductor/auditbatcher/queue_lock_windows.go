//go:build enterprise && windows

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package auditbatcher

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

const windowsLockAllBytes = ^uint32(0)

// acquireQueueLock takes an exclusive, non-blocking advisory lock on a .lock
// file under the queue root. On Windows this uses LockFileEx over the whole
// file so a second process on the same host / local filesystem fails closed
// with ErrQueueLocked. This is not a distributed lock for cross-host shared
// PVCs.
func acquireQueueLock(dir string) (*os.File, error) {
	path := filepath.Join(filepath.Clean(dir), lockFileName)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, fileMode)
	if err != nil {
		return nil, fmt.Errorf("auditbatcher: open queue lock %s: %w", path, err)
	}
	ol := new(windows.Overlapped)
	err = windows.LockFileEx(
		windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0,
		windowsLockAllBytes,
		windowsLockAllBytes,
		ol,
	)
	if err != nil {
		_ = f.Close()
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) || errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
			return nil, fmt.Errorf("%w: %s", ErrQueueLocked, path)
		}
		return nil, fmt.Errorf("auditbatcher: lock queue %s: %w", path, err)
	}
	return f, nil
}

func (q *Queue) releaseLock() error {
	if q.lockFile == nil {
		return nil
	}
	f := q.lockFile
	q.lockFile = nil
	ol := new(windows.Overlapped)
	_ = windows.UnlockFileEx(
		windows.Handle(f.Fd()),
		0,
		windowsLockAllBytes,
		windowsLockAllBytes,
		ol,
	)
	if err := f.Close(); err != nil {
		return fmt.Errorf("auditbatcher: close queue lock: %w", err)
	}
	return nil
}

func ignoreDirSyncError(err error) bool {
	return errors.Is(err, windows.ERROR_ACCESS_DENIED) ||
		errors.Is(err, windows.ERROR_INVALID_FUNCTION) ||
		errors.Is(err, windows.ERROR_INVALID_HANDLE)
}
