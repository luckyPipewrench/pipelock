// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package diag

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPathWritableDirUsesReadOnlyPermissionInspection(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "receipts")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if !pathWritableDir(dir) {
		t.Fatal("owner-writable directory reported unwritable")
	}

	if err := os.Chmod(dir, 0o500); err != nil { //nolint:gosec // Directory needs execute permission while intentionally removing write permission.
		t.Fatal(err)
	}
	if os.Geteuid() != 0 && pathWritableDir(dir) {
		t.Fatal("owner-read-only directory reported writable")
	}

	missingChild := filepath.Join(dir, "new-receipts")
	if os.Geteuid() != 0 && pathWritableDir(missingChild) {
		t.Fatal("missing child of unwritable parent reported writable")
	}

	nestedMissing := filepath.Join(t.TempDir(), "one", "two", "receipts")
	if !pathWritableDir(nestedMissing) {
		t.Fatal("nested missing directory under writable ancestor reported unwritable")
	}
}
