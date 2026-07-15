// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package securefile provides bounded, race-resistant reads for local security
// material such as bearer tokens, private keys, and certificate bundles.
package securefile

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/secperm"
)

// Options defines the filesystem boundary enforced by Read.
type Options struct {
	MaxBytes        int64
	DisallowedPerms fs.FileMode
	RejectSymlink   bool
}

// Read opens a bounded regular file and verifies that the descriptor still
// identifies the path that was validated. Kubernetes Secret-volume symlinks
// are accepted only when their final target remains inside the symlink's
// directory; links that escape the mount are rejected.
func Read(path string, opts Options) ([]byte, error) {
	if opts.MaxBytes <= 0 {
		return nil, fmt.Errorf("secure file max bytes must be positive")
	}
	clean := filepath.Clean(path)
	before, err := os.Lstat(clean)
	if err != nil {
		return nil, err
	}
	resolved := clean
	if before.Mode()&os.ModeSymlink != 0 {
		if opts.RejectSymlink {
			return nil, fmt.Errorf("%q must not be a symlink", clean)
		}
		resolved, err = filepath.EvalSymlinks(clean)
		if err != nil {
			return nil, fmt.Errorf("resolve symlink: %w", err)
		}
		root, rootErr := filepath.Abs(filepath.Dir(clean))
		target, targetErr := filepath.Abs(resolved)
		if rootErr != nil {
			return nil, fmt.Errorf("resolve secure file directory: %w", rootErr)
		}
		if targetErr != nil {
			return nil, fmt.Errorf("resolve secure file target: %w", targetErr)
		}
		rel, relErr := filepath.Rel(root, target)
		if relErr != nil {
			return nil, fmt.Errorf("resolve relative symlink target: %w", relErr)
		}
		if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return nil, fmt.Errorf("symlink escapes its secret directory")
		}
		before, err = os.Lstat(resolved)
		if err != nil {
			return nil, err
		}
	}
	if !before.Mode().IsRegular() {
		return nil, fmt.Errorf("%q is not a regular file", clean)
	}
	if secperm.TooPermissive(before.Mode().Perm(), opts.DisallowedPerms) {
		return nil, fmt.Errorf("%q has insecure permissions %04o", clean, before.Mode().Perm())
	}
	file, err := openRegularNonblocking(resolved)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	after, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return nil, fmt.Errorf("%q changed during secure open", clean)
	}
	if secperm.TooPermissive(after.Mode().Perm(), opts.DisallowedPerms) {
		return nil, fmt.Errorf("%q has insecure permissions %04o", clean, after.Mode().Perm())
	}
	data, err := io.ReadAll(io.LimitReader(file, opts.MaxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > opts.MaxBytes {
		return nil, fmt.Errorf("%q exceeds %d bytes", clean, opts.MaxBytes)
	}
	return data, nil
}
