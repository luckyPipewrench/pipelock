// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
)

const atClockTicks = 17

// readProcessAuxv is a test seam for the Linux process auxiliary vector.
var readProcessAuxv = func() ([]byte, error) { return os.ReadFile("/proc/self/auxv") }

func clockTicks(context.Context) (float64, error) { return readClockTicks() }

func readClockTicks() (float64, error) {
	data, err := readProcessAuxv()
	if err != nil {
		return 0, fmt.Errorf("read /proc/self/auxv: %w", err)
	}
	wordSize := strconv.IntSize / 8
	entrySize := 2 * wordSize
	if len(data)%entrySize != 0 {
		return 0, fmt.Errorf("invalid /proc/self/auxv length %d", len(data))
	}
	for offset := 0; offset < len(data); offset += entrySize {
		var kind, value uint64
		if wordSize == 8 {
			kind = binary.NativeEndian.Uint64(data[offset : offset+wordSize])
			value = binary.NativeEndian.Uint64(data[offset+wordSize : offset+entrySize])
		} else {
			kind = uint64(binary.NativeEndian.Uint32(data[offset : offset+wordSize]))
			value = uint64(binary.NativeEndian.Uint32(data[offset+wordSize : offset+entrySize]))
		}
		if kind == atClockTicks {
			if value == 0 {
				return 0, fmt.Errorf("AT_CLKTCK is zero in /proc/self/auxv")
			}
			return float64(value), nil
		}
		if kind == 0 {
			break
		}
	}
	return 0, fmt.Errorf("AT_CLKTCK missing from /proc/self/auxv")
}

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
	kind := widen(st.Type)
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
	fd := int(f.Fd()) // #nosec G115 -- file descriptors fit in int
	if err := syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(fd, syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}

// widen converts Statfs_t.Type, which is int32 or int64 depending on the
// architecture, to int64 without a conversion that is a no-op on some targets.
func widen[T int32 | int64](v T) int64 { return int64(v) }
