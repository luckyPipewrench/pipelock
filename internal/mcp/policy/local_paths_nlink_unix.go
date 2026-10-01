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

// ownedByCurrentUser reports whether this process's user owns the file.
func ownedByCurrentUser(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && int64(st.Uid) == int64(os.Getuid())
}
