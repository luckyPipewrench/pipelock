// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build js && wasm

package recorder

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Browser receipt verification only mounts a validated archive into the
// private in-memory filesystem installed by receipt-memfs.js. That filesystem
// has no symlink primitive. Still check every component and compare opened
// objects with their lstat results so a malformed adapter cannot redirect a
// read to another archive path.
func openEvidenceLocationDirectory(location EvidenceLocation) (*os.File, error) {
	if err := validateEvidenceFileAccess(); err != nil {
		return nil, err
	}
	if err := validateEvidenceLocation(location); err != nil {
		return nil, err
	}
	root, err := filepath.Abs(filepath.Clean(location.Root))
	if err != nil {
		return nil, fmt.Errorf("resolve evidence root: %w", err)
	}
	parts := strings.Split(strings.TrimPrefix(root, string(filepath.Separator)), string(filepath.Separator))
	parts = append(parts, strings.Split(filepath.FromSlash(location.ID), string(filepath.Separator))...)
	current := string(filepath.Separator)
	var before os.FileInfo
	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		before, err = os.Lstat(current)
		if err != nil {
			return nil, fmt.Errorf("stat evidence root component %q: %w", current, err)
		}
		if before.Mode()&os.ModeSymlink != 0 || !before.IsDir() {
			return nil, fmt.Errorf("%w: evidence location component is symlinked or not a directory", ErrEvidenceRefused)
		}
	}
	if before == nil {
		before, err = os.Lstat(current)
		if err != nil {
			return nil, fmt.Errorf("stat evidence root: %w", err)
		}
	}
	file, err := os.Open(current)
	if err != nil {
		return nil, fmt.Errorf("open evidence location: %w", err)
	}
	after, err := file.Stat()
	if err != nil || !after.IsDir() || !os.SameFile(before, after) {
		_ = file.Close()
		if err != nil {
			return nil, err
		}
		return nil, errors.New("evidence location changed while opening")
	}
	return file, nil
}

func openEvidenceLocationFile(location EvidenceLocation, name string) (*os.File, os.FileInfo, error) {
	if name != filepath.Base(name) || name == "." || name == ".." {
		return nil, nil, errors.New("evidence filename must be a base name")
	}
	directory, err := openEvidenceLocationDirectory(location)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = directory.Close() }()
	path := filepath.Join(location.Dir, name)
	before, err := os.Lstat(path)
	if err != nil {
		return nil, nil, fmt.Errorf("stat evidence file %q: %w", name, err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("%w: evidence file is symlinked or non-regular", ErrEvidenceRefused)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open evidence file %q: %w", name, err)
	}
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) {
		_ = file.Close()
		if err != nil {
			return nil, nil, err
		}
		return nil, nil, errors.New("evidence file changed or is non-regular")
	}
	return file, after, nil
}
