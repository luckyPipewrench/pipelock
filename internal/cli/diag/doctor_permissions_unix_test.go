// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package diag

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

type permissionFileInfo struct {
	os.FileInfo
	mode os.FileMode
	stat syscall.Stat_t
}

func (i permissionFileInfo) Mode() os.FileMode { return i.mode }
func (i permissionFileInfo) Sys() any          { return &i.stat }

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

func TestDirWritableExecutableByCurrentUserUsesGroupPermissions(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root uses the execute-bit branch")
	}
	base, err := os.Stat(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	baseStat, ok := base.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("temporary directory did not expose Unix stat data")
	}
	stat := *baseStat
	stat.Uid++
	info := permissionFileInfo{
		FileInfo: base,
		mode:     0o030,
		stat:     stat,
	}
	if !dirWritableExecutableByCurrentUser(info) {
		t.Fatal("group-writable and executable directory reported unwritable")
	}
}
