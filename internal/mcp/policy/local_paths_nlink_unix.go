// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package policy

import (
	"os"
	"syscall"
)

// mayHaveOtherLinks reports whether the file may be reachable under more than
// one name. A link count of one means the name just resolved is the only one,
// so no other directory entry can be the same file.
func mayHaveOtherLinks(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return true
	}
	// Nlink is uint64 on some platforms and uint32 on others.
	return widen(st.Nlink) > 1
}

// onDifferentDevice reports whether a and b are known to be on different
// filesystems. A hard link cannot cross one. It is false when either device is
// unknown.
func onDifferentDevice(a, b os.FileInfo) bool {
	sa, okA := a.Sys().(*syscall.Stat_t)
	sb, okB := b.Sys().(*syscall.Stat_t)
	if !okA || !okB {
		return false
	}
	// Dev is uint64 on some platforms and int32 on others.
	return widen(sa.Dev) != widen(sb.Dev)
}

// fileID returns the device and inode of info.
func fileID(info os.FileInfo) (fileKey, bool) {
	if info == nil {
		return fileKey{}, false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fileKey{}, false
	}
	// Dev and Ino widths differ per platform.
	return fileKey{dev: widen(st.Dev), ino: widen(st.Ino)}, true
}

// widen converts a stat field to uint64. Stat_t field widths differ across
// platforms (Nlink and Dev are 32-bit on some), so a plain conversion is a
// no-op on some builds and needed on others.
func widen[T ~uint16 | ~uint32 | ~uint64 | ~int32 | ~int64](v T) uint64 {
	return uint64(v)
}
