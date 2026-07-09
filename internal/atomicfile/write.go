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
	Sync() error
	Close() error
}

// Write atomically AND durably writes data to path with the given permissions.
// Uses temp-file-then-rename to prevent partial writes, and fsyncs the file
// data before the rename plus the parent directory after it, so a completed
// write survives a crash or power loss. Every caller persists security-relevant
// state (keys, receipts, posture proofs, revocation high-water marks, learned
// baselines), so durability is the default rather than an opt-in.
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
	// fsync the file's data+metadata before the rename so the target dentry can
	// never point at contents that were only in the page cache. A Sync failure
	// on a regular file means the write is not durable, so it fails closed.
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("syncing temp file: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("closing temp file: %w", err)
	}
	if err := os.Rename(tmpPath, targetPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("renaming to target: %w", err)
	}
	// fsync the parent directory so the rename itself (the new dentry) is durable
	// and the file is findable after a crash. This is best-effort: some
	// filesystems/platforms do not support directory fsync, and the file data is
	// already durable and the rename atomic, so a dir-sync failure must not fail
	// an otherwise-successful write.
	syncDir(filepath.Dir(targetPath))
	return nil
}

// syncDir fsyncs a directory so a rename into it survives a crash. Failures on
// filesystems or platforms that do not support directory fsync are ignored:
// this hardening rides on top of the already-durable file data and the atomic
// rename, so it can only add durability, never remove it.
func syncDir(dir string) {
	d, err := os.Open(filepath.Clean(dir))
	if err != nil {
		return
	}
	// A directory-fsync error (e.g. EINVAL/ENOTSUP on some Windows and network
	// filesystems) is swallowed rather than propagated: the file data is already
	// durable and the rename atomic, so this can only add durability.
	_ = d.Sync()
	_ = d.Close()
}
