// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package directorysync

import (
	"errors"
	"fmt"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// Sync flushes the directory handle after the artifact file itself is synced.
func Sync(path string) error {
	name, err := windows.UTF16PtrFromString(filepath.Clean(path))
	if err != nil {
		return fmt.Errorf("encode directory path: %w", err)
	}
	// Microsoft requires FILE_FLAG_BACKUP_SEMANTICS for directory handles and
	// GENERIC_WRITE for FlushFileBuffers.
	handle, err := windows.CreateFile(name, windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return fmt.Errorf("open directory for sync: %w", err)
	}
	flushErr := windows.FlushFileBuffers(handle)
	closeErr := windows.CloseHandle(handle)
	return errors.Join(flushErr, closeErr)
}
