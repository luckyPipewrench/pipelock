//go:build !windows

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package launchcontract

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

type ownedInfo struct {
	mode fs.FileMode
	uid  uint32
}

func (i ownedInfo) Name() string       { return "entry" }
func (i ownedInfo) Size() int64        { return 0 }
func (i ownedInfo) Mode() fs.FileMode  { return i.mode }
func (i ownedInfo) ModTime() time.Time { return time.Time{} }
func (i ownedInfo) IsDir() bool        { return i.mode.IsDir() }
func (i ownedInfo) Sys() any           { return &syscall.Stat_t{Uid: i.uid} }

func TestPrivateModeOwnership(t *testing.T) {
	t.Parallel()
	const euid = 1000
	for _, tt := range []struct {
		name        string
		info        ownedInfo
		wantTighten bool
		wantErr     bool
	}{
		{"own private", ownedInfo{fs.ModeDir | 0o700, euid}, false, false},
		{"own group writable", ownedInfo{fs.ModeDir | 0o775, euid}, true, false},
		{"own world writable", ownedInfo{fs.ModeDir | 0o777, euid}, true, false},
		{"root private", ownedInfo{fs.ModeDir | 0o755, 0}, false, false},
		{"root world writable", ownedInfo{fs.ModeDir | 0o777, 0}, false, true},
		{"other account private", ownedInfo{fs.ModeDir | 0o700, 2000}, false, true},
		{"other account file", ownedInfo{0o600, 2000}, false, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tighten, err := privateMode(tt.info, euid)
			if tighten != tt.wantTighten || (err != nil) != tt.wantErr {
				t.Fatalf("privateMode = %v, %v; want tighten=%v err=%v", tighten, err, tt.wantTighten, tt.wantErr)
			}
		})
	}
}

// A cache directory the user owns but left writable by other accounts is
// tightened before a bundle is trusted from it.
func TestWriteBundleTightensOwnedCacheDirectories(t *testing.T) {
	dir := t.TempDir()
	data := certificate(t, nil)
	execDir := filepath.Join(dir, "pipelock", "exec-ca")
	if err := os.MkdirAll(execDir, 0o750); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{filepath.Join(dir, "pipelock"), execDir} {
		if err := os.Chmod(p, 0o777); err != nil {
			t.Fatal(err)
		}
	}
	path, err := WriteBundle(dir, data)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{filepath.Join(dir, "pipelock"), execDir} {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0o022 != 0 {
			t.Fatalf("%s mode %o still writable by other accounts", p, info.Mode().Perm())
		}
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteBundle(dir, data); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o022 != 0 {
		t.Fatalf("bundle mode %o still writable by other accounts", info.Mode().Perm())
	}
}

func TestWriteBundleRefusesSharedCacheRoot(t *testing.T) {
	dir := t.TempDir()
	data := certificate(t, nil)
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteBundle(dir, data); err == nil || !strings.Contains(err.Error(), "writable by other accounts") {
		t.Fatalf("shared cache root err=%v", err)
	}
	if err := os.Chmod(dir, 0o777|os.ModeSticky); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteBundle(dir, data); err != nil {
		t.Fatalf("sticky shared cache root err=%v", err)
	}
}
