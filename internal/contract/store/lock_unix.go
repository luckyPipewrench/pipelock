// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package store

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func (s Store) withLock(fn func() error) error {
	if err := os.MkdirAll(s.root, dirPerm); err != nil {
		return fmt.Errorf("create contract store root: %w", err)
	}
	f, err := os.OpenFile(filepath.Join(s.root, ".lock"), os.O_CREATE|os.O_RDWR, filePerm)
	if err != nil {
		return fmt.Errorf("open contract store lock: %w", err)
	}
	defer func() { _ = f.Close() }()
	fd := int(f.Fd()) //nolint:gosec // file descriptors fit in int on supported Unix targets.
	if err := syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		return fmt.Errorf("acquire contract store lock: %w", err)
	}
	defer func() { _ = syscall.Flock(fd, syscall.LOCK_UN) }()
	return fn()
}
