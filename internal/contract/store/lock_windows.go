// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package store

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func (s Store) withLock(fn func() error) error {
	if err := os.MkdirAll(s.root, 0o700); err != nil {
		return fmt.Errorf("create contract store root: %w", err)
	}
	lockPath := filepath.Join(s.root, ".lock")
	pathp, err := syscall.UTF16PtrFromString(lockPath)
	if err != nil {
		return fmt.Errorf("encode contract store lock path: %w", err)
	}
	handle, err := syscall.CreateFile(
		pathp,
		syscall.GENERIC_READ|syscall.GENERIC_WRITE,
		0,
		nil,
		syscall.OPEN_ALWAYS,
		syscall.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return fmt.Errorf("open contract store lock: %w", err)
	}
	f := os.NewFile(uintptr(handle), lockPath)
	if f == nil {
		_ = syscall.CloseHandle(handle)
		return fmt.Errorf("create contract store lock handle: %s", lockPath)
	}
	defer func() { _ = f.Close() }()
	return fn()
}
