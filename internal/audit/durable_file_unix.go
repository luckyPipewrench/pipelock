// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package audit

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// openDurableAuditFile binds a lifecycle sink to a non-blocking, final-symlink
// refusing descriptor before callers inspect its type or identity.
func openDurableAuditFile(path string) (*os.File, bool, error) {
	cleanPath := filepath.Clean(path)
	flags := syscall.O_APPEND | syscall.O_WRONLY | syscall.O_CREAT | syscall.O_EXCL | syscall.O_CLOEXEC | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
	fd, err := syscall.Open(cleanPath, flags, 0o600)
	created := err == nil
	if errors.Is(err, fs.ErrExist) {
		fd, err = syscall.Open(cleanPath, syscall.O_APPEND|syscall.O_WRONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	}
	if err != nil {
		return nil, false, err
	}
	file := os.NewFile(uintptr(fd), cleanPath)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, false, errors.New("wrap durable audit log file descriptor")
	}
	return file, created, nil
}
