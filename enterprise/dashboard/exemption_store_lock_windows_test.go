//go:build enterprise && windows

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package dashboard

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestExemptionStoreFileLockWindowsExcludesOtherHandles(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "state.lock")
	lock, err := acquireExemptionStoreFileLock(path)
	if err != nil {
		t.Fatalf("acquireExemptionStoreFileLock: %v", err)
	}
	defer func() { _ = lock.Close() }()

	file, err := os.OpenFile(filepath.Clean(path), os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	defer func() { _ = file.Close() }()

	var overlapped windows.Overlapped
	err = windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, ^uint32(0), ^uint32(0), &overlapped)
	if !errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		if err == nil {
			_ = windows.UnlockFileEx(windows.Handle(file.Fd()), 0, ^uint32(0), ^uint32(0), &overlapped)
		}
		t.Fatalf("competing lock error = %v, want ERROR_LOCK_VIOLATION", err)
	}
}
