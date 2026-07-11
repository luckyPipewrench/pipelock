// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package baseline

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// errELOOP is a Windows sentinel: the Unix ELOOP symlink-loop error has no
// portable Windows equivalent, so this value never matches a real open error.
// The shared caller's errors.Is(err, errELOOP) branch is therefore inert on
// Windows, and a rejected symlink surfaces via the explicit checks below.
var errELOOP = errors.New("ELOOP-not-supported-on-windows")

// openRegularFileNoSymlinkBelowRoot opens a regular file below canonicalRoot
// without following a symlink or reparse point at the final path component.
//
// Windows has no portable openat/O_NOFOLLOW per-component walk like the Unix
// build, so this mirrors the no-follow guarantee at the final component with an
// Lstat reject and relies on the shared caller
// (readRegularFileNoSymlinkInRootWithOpenHook) for the two guards that ARE
// portable: rejectSymlinkParents Lstat-walks every parent directory, and the
// post-open os.SameFile identity re-check closes the TOCTOU window between this
// Lstat and the open. Normal regular-file reads succeed; only symlinks and
// reparse points are rejected. (Earlier this function failed every Windows read
// unconditionally, breaking baseline profile and integrity-state loading on
// Windows; that fail-closed denial is removed here.)
func openRegularFileNoSymlinkBelowRoot(canonicalRoot, relPath, displayPath string) (*os.File, error) {
	fullPath := filepath.Clean(filepath.Join(canonicalRoot, relPath))
	info, err := os.Lstat(fullPath)
	if err != nil {
		return nil, fmt.Errorf("lstat %s: %w", displayPath, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s must not be a symlink", displayPath)
	}
	// A non-symlink reparse point (junction, mount point, or other name
	// surrogate) surfaces with the irregular mode bit; reject it so a
	// redirected read cannot escape the trusted root.
	if info.Mode()&os.ModeIrregular != 0 {
		return nil, fmt.Errorf("%s must not be a reparse point", displayPath)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s must be a regular file", displayPath)
	}
	f, err := os.Open(fullPath)
	if err != nil {
		return nil, err
	}
	return f, nil
}
