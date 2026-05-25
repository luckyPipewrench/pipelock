// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcpwrap

import (
	"os"
	"path/filepath"
	"testing"
)

// TestAtomicWriteFile_RenameFails covers the final-rename error branch by
// pointing the target at an existing directory (rename of a file onto a
// directory fails).
func TestAtomicWriteFile_RenameFails(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	target := filepath.Join(dir, "target-dir")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatalf("mkdir target dir: %v", err)
	}
	if err := AtomicWriteFile(target, []byte("data"), dir); err == nil {
		t.Fatal("expected rename-onto-directory to fail")
	}
}

// TestCommitHeaderSidecar_RenameFails covers commitHeaderSidecar's rename error
// branch the same way: the destination path is an existing directory.
func TestCommitHeaderSidecar_RenameFails(t *testing.T) {
	t.Parallel()

	base := t.TempDir()
	dest := filepath.Join(base, "x.headers")
	if err := os.Mkdir(dest, 0o700); err != nil {
		t.Fatalf("mkdir dest: %v", err)
	}
	if err := commitHeaderSidecar(dest, []byte("X: 1\n")); err == nil {
		t.Fatal("expected rename-onto-directory to fail")
	}
}
