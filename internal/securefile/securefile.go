// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package securefile provides bounded, race-resistant reads for local security
// material such as bearer tokens, private keys, and certificate bundles.
package securefile

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/secperm"
)

// ErrUnsupportedSecureOpen means the current platform cannot provide the
// nonblocking, no-follow open required by Read's security contract.
var ErrUnsupportedSecureOpen = errors.New("secure file open unsupported on this platform")

// DisallowGroupOrWorldWrite is the shared integrity-material policy: public
// read access is permitted, but no non-owner may modify the trusted file.
const DisallowGroupOrWorldWrite fs.FileMode = 0o022

// Options defines the filesystem boundary enforced by Read.
type Options struct {
	MaxBytes        int64
	DisallowedPerms fs.FileMode
	RejectSymlink   bool
	// OwnedState marks a file Pipelock writes and owns, rather than an
	// operator-supplied credential. For those files group read/write is accepted
	// when the group is one this process belongs to and no other-perms are set,
	// because a container platform widens the mode of its own volumes: Kubernetes
	// fsGroup ORs writable files with 0660 on every mount, so a file we wrote at
	// 0600 comes back group-writable and refusing it means a non-root workload
	// cannot use a persistent volume at all.
	//
	// It does NOT relax anything for credentials or private keys. Leave it false
	// for those: group-write there is a real confidentiality and tamper concern,
	// not a platform artifact. See secperm.OwnedGroupWritableAllowed for what the
	// check can and cannot prove.
	OwnedState bool
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
	if err := checkPerm(clean, before, opts); err != nil {
		return nil, err
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
	if err := checkPerm(clean, after, opts); err != nil {
		return nil, err
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

// checkPerm applies the permission policy for one stat of the target. Both the
// pre-open and post-open checks go through it so the two cannot drift.
func checkPerm(clean string, info fs.FileInfo, opts Options) error {
	if opts.OwnedState {
		if err := secperm.OwnedGroupWritableAllowed(info); err != nil {
			return fmt.Errorf("%q %w", clean, err)
		}
		return nil
	}
	if secperm.TooPermissive(info.Mode().Perm(), opts.DisallowedPerms) {
		return fmt.Errorf("%q has insecure permissions %04o", clean, info.Mode().Perm())
	}
	return nil
}
