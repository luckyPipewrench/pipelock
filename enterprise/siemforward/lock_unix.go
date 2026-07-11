//go:build enterprise && !windows

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package siemforward

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// acquireStateLock takes an exclusive advisory lock on a sidecar lock file so a
// second process cannot deliver against the same spool and cursor. The lock is
// held for the forwarder's lifetime and released by releaseStateLock on Close.
func acquireStateLock(spoolPath string) (*os.File, error) {
	lockPath := filepath.Clean(spoolPath + ".lock")
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open siem forwarder lock file %q: %w", lockPath, err)
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("siem forwarder state files %q are locked by another process: %w", spoolPath, err)
	}
	return file, nil
}

// releaseStateLock unlocks and closes the lock file. Safe to call with nil.
func releaseStateLock(file *os.File) {
	if file == nil {
		return
	}
	_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
	_ = file.Close()
}
