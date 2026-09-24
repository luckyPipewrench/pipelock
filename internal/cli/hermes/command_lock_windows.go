//go:build windows

package hermes

import (
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

func ensureHermesLockDir(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("hermes command lock: create %s: %w", path, err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("hermes command lock: unsafe lock directory %s", path)
	}
	return nil
}

func acquireHermesLock(path string, deadline time.Time) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("hermes command lock: open %s: %w", path, err)
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, fmt.Errorf("hermes command lock: unsafe lock file %s: %v", path, err)
	}
	handle := windows.Handle(f.Fd())
	for {
		overlap := new(windows.Overlapped)
		err = windows.LockFileEx(handle, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, overlap)
		if err == nil {
			return func() { _ = windows.UnlockFileEx(handle, 0, 1, 0, overlap); _ = f.Close() }, nil
		}
		if err != windows.ERROR_LOCK_VIOLATION {
			_ = f.Close()
			return nil, fmt.Errorf("hermes command lock: lock %s: %w", path, err)
		}
		if !time.Now().Before(deadline) {
			_ = f.Close()
			return nil, hermesLockBusy(path)
		}
		time.Sleep(min(10*time.Millisecond, time.Until(deadline)))
	}
}
