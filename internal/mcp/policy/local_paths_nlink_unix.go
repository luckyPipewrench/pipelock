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
	return uint64(st.Nlink) > 1 //nolint:unconvert // width differs per platform
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
	return uint64(sa.Dev) != uint64(sb.Dev) //nolint:unconvert // width differs per platform
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
	return fileKey{dev: uint64(st.Dev), ino: uint64(st.Ino)}, true //nolint:unconvert // width differs per platform
}
