//go:build enterprise && windows

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package dashboard

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

type exemptionStoreFileLock struct {
	file       *os.File
	overlapped windows.Overlapped
}

func acquireExemptionStoreFileLock(path string) (*exemptionStoreFileLock, error) {
	file, err := os.OpenFile(filepath.Clean(path), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	lock := &exemptionStoreFileLock{file: file}
	if err := windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, ^uint32(0), ^uint32(0), &lock.overlapped); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("lock file: %w", err)
	}
	return lock, nil
}

func (l *exemptionStoreFileLock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	unlockErr := windows.UnlockFileEx(windows.Handle(l.file.Fd()), 0, ^uint32(0), ^uint32(0), &l.overlapped)
	closeErr := l.file.Close()
	if unlockErr != nil {
		return fmt.Errorf("unlock: %w", unlockErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close lock file: %w", closeErr)
	}
	return nil
}
