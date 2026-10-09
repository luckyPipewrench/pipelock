// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// Filesystem magic numbers from statfs(2) for the filesystems a benchmark
// output directory realistically lives on.
var filesystemNames = map[int64]string{
	0x01021994: "tmpfs",
	0xEF53:     "ext2/ext3/ext4",
	0x9123683E: "btrfs",
	0x58465342: "xfs",
	0x794c7630: "overlayfs",
	0x2fc12fc1: "zfs",
	0x6969:     "nfs",
	0xF2F52010: "f2fs",
	0x65735546: "fuse",
	0x4d44:     "vfat",
	0x858458f6: "ramfs",
}

// filesystemType names the filesystem holding path. Output on tmpfs and output
// on a disk differ in write cost, so the type is part of the pinned inputs.
func filesystemType(path string) string {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return "unavailable: " + err.Error()
	}
	kind := int64(st.Type) //nolint:unconvert // Type is int32 or int64 depending on the architecture
	if name, ok := filesystemNames[kind]; ok {
		return name
	}
	return fmt.Sprintf("unknown (0x%x)", kind)
}

// holdLock takes an exclusive advisory lock on path, blocking until it is
// free, and returns a release function. It serializes load runs that share
// one machine so they cannot distort each other's measurements.
func holdLock(path string) (func(), error) {
	f, err := os.OpenFile(filepath.Clean(path), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil { //nolint:gosec // fd fits in int
		_ = f.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) //nolint:gosec // fd fits in int
		_ = f.Close()
	}, nil
}
