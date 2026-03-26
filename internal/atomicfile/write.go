// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package atomicfile provides atomic file write operations using
// temp-file-then-rename to prevent partial writes on crash.
package atomicfile

import (
	"fmt"
	"os"
	"path/filepath"
)

// file is the interface needed for atomic write operations.
// *os.File satisfies this. Tests provide a mock.
type file interface {
	Name() string
	Write([]byte) (int, error)
	Chmod(os.FileMode) error
	Close() error
}

// Write atomically writes data to path with the given permissions.
// Uses temp-file-then-rename to prevent partial writes.
func Write(path string, data []byte, perm os.FileMode) error {
	path = filepath.Clean(path)
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	return finalize(tmp, path, data, perm)
}

// finalize completes the atomic write using the given file.
// Unexported; tests in the same package can access it directly.
func finalize(f file, targetPath string, data []byte, perm os.FileMode) error {
	tmpPath := f.Name()

	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("writing temp file: %w", err)
	}
	if err := f.Chmod(perm); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("setting permissions: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("closing temp file: %w", err)
	}
	if err := os.Rename(tmpPath, targetPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("renaming to target: %w", err)
	}
	return nil
}
