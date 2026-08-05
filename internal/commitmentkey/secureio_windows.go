// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package commitmentkey

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/luckyPipewrench/pipelock/internal/atomicfile"
	"golang.org/x/sys/windows"
)

func ensureParent(path string) error {
	parent := filepath.Dir(filepath.Clean(path))
	if err := os.MkdirAll(parent, 0o750); err != nil {
		return fmt.Errorf("create commitment keyring directory: %w", err)
	}
	return validateWindowsDirectory(parent)
}

func readSecure(path string) ([]byte, error) {
	return readSecureLimited(path, maxBytes, "commitment keyring", ErrInvalidKeyring)
}

func readSecureLimited(path string, limit int64, label string, invalidErr error) ([]byte, error) {
	clean := filepath.Clean(path)
	if err := validateWindowsDirectory(filepath.Dir(clean)); err != nil {
		return nil, err
	}
	pointer, err := windows.UTF16PtrFromString(clean)
	if err != nil {
		return nil, fmt.Errorf("encode %s path: %w", label, err)
	}
	handle, err := windows.CreateFile(pointer, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", label, err)
	}
	f := os.NewFile(uintptr(handle), clean)
	if f == nil {
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf("open %s: invalid handle", label)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", label, err)
	}
	if isWindowsReparse(info) {
		return nil, fmt.Errorf("%w: %s", ErrSymlink, clean)
	}
	if !info.Mode().IsRegular() {
		return nil, invalidReadError(invalidErr, label, "not a regular file")
	}
	if info.Size() > limit {
		return nil, invalidReadError(invalidErr, label, "file exceeds %d bytes", limit)
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", label, err)
	}
	if int64(len(raw)) > limit {
		return nil, invalidReadError(invalidErr, label, "file exceeds %d bytes", limit)
	}
	return raw, nil
}

func writeSecureNew(path string, data []byte) error {
	if err := ensureParent(path); err != nil {
		return err
	}
	if err := validateWindowsFinal(path); err != nil {
		return err
	}
	if err := atomicfile.WriteNew(filepath.Clean(path), data, 0o600); err != nil {
		if errors.Is(err, os.ErrExist) {
			return ErrAlreadyExists
		}
		return err
	}
	return nil
}

func writeSecureReplace(path string, data []byte) error {
	if err := validateWindowsDirectory(filepath.Dir(filepath.Clean(path))); err != nil {
		return err
	}
	if err := validateWindowsFinal(path); err != nil {
		return err
	}
	return atomicfile.Write(filepath.Clean(path), data, 0o600)
}

func validateWindowsDirectory(path string) error {
	clean := filepath.Clean(path)
	parent := filepath.Dir(clean)
	if parent != clean {
		if err := validateWindowsDirectory(parent); err != nil {
			return err
		}
	}
	info, err := os.Lstat(clean)
	if err != nil {
		return fmt.Errorf("inspect commitment keyring parent directory: %w", err)
	}
	if isWindowsReparse(info) || !info.IsDir() {
		return fmt.Errorf("%w: commitment keyring parent is a reparse point or not a directory: %s", ErrSymlink, clean)
	}
	return nil
}

func validateWindowsFinal(path string) error {
	info, err := os.Lstat(filepath.Clean(path))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect commitment keyring: %w", err)
	}
	if isWindowsReparse(info) {
		return fmt.Errorf("%w: %s", ErrSymlink, filepath.Clean(path))
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%w: not a regular file", ErrInvalidKeyring)
	}
	return nil
}

func isWindowsReparse(info os.FileInfo) bool {
	return info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0
}
