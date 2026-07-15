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

type permissionInfoWithoutStat struct {
	os.FileInfo
	mode os.FileMode
}

func (i permissionInfoWithoutStat) Mode() os.FileMode { return i.mode }
func (i permissionInfoWithoutStat) Sys() any          { return struct{}{} }

func TestPathWritableDirProbesExistingDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "receipts")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if !pathWritableDir(dir) {
		t.Fatal("owner-writable directory reported unwritable")
	}

	readExecuteOnly := os.FileMode(0o700)
	readExecuteOnly &^= 0o200
	if err := os.Chmod(dir, readExecuteOnly); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 && pathWritableDir(dir) {
		t.Fatal("owner-read-only directory reported writable")
	}

	missingChild := filepath.Join(dir, "new-receipts")
	if pathWritableDir(missingChild) {
		t.Fatal("missing directory reported writable without a real probe")
	}
	if os.Geteuid() != 0 && pathProbablyCreatableDir(missingChild) {
		t.Fatal("missing child of unwritable parent reported probably creatable")
	}

	nestedMissing := filepath.Join(t.TempDir(), "one", "two", "receipts")
	if !pathProbablyCreatableDir(nestedMissing) {
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

func TestDirWritableExecutableByCurrentUserRejectsUnexpectedStat(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root uses the execute-bit branch")
	}
	base, err := os.Stat(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if dirWritableExecutableByCurrentUser(permissionInfoWithoutStat{FileInfo: base, mode: 0o777}) {
		t.Fatal("directory with unexpected stat metadata reported writable")
	}
}

func TestDirWritableExecutableByCurrentUserUsesSupplementaryAndOtherPermissions(t *testing.T) {
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

	other := *baseStat
	other.Uid = ^uint32(0)
	other.Gid = ^uint32(0)
	if !dirWritableExecutableByCurrentUser(permissionFileInfo{FileInfo: base, mode: 0o003, stat: other}) {
		t.Fatal("other-writable and executable directory reported unwritable")
	}

	groups, err := os.Getgroups()
	if err != nil {
		t.Fatal(err)
	}
	for _, gid := range groups {
		if gid == os.Getegid() || gid < 0 || uint64(gid) > uint64(^uint32(0)) {
			continue
		}
		supplementary := *baseStat
		supplementary.Uid = ^uint32(0)
		supplementary.Gid = uint32(gid)
		if !dirWritableExecutableByCurrentUser(permissionFileInfo{FileInfo: base, mode: 0o030, stat: supplementary}) {
			t.Fatal("supplementary-group writable and executable directory reported unwritable")
		}
		return
	}
	t.Skip("current user has no supplementary group distinct from the effective group")
}
