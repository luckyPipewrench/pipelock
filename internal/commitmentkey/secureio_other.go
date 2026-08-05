// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !unix && !windows

package commitmentkey

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/luckyPipewrench/pipelock/internal/atomicfile"
)

func ensureParent(path string) error {
	if err := os.MkdirAll(filepath.Dir(filepath.Clean(path)), 0o750); err != nil {
		return fmt.Errorf("create commitment keyring directory: %w", err)
	}
	return nil
}

func readSecure(path string) ([]byte, error) {
	return readSecureLimited(path, maxBytes, "commitment keyring")
}

func readSecureLimited(path string, limit int64, label string) ([]byte, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", label, err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", label, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("invalid %s: not a regular file", label)
	}
	if info.Mode().Perm() != 0o600 {
		return nil, fmt.Errorf("%w: got %04o, want 0600", ErrUnsafePermission, info.Mode().Perm())
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", label, err)
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("invalid %s: file exceeds %d bytes", label, limit)
	}
	return raw, nil
}

func writeSecureNew(path string, data []byte) error {
	if err := ensureParent(path); err != nil {
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
	return atomicfile.Write(filepath.Clean(path), data, 0o600)
}
