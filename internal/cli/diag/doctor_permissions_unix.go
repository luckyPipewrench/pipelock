// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package diag

import (
	"os"
	"syscall"
)

func dirWritableExecutableByCurrentUser(info os.FileInfo) bool {
	mode := info.Mode().Perm()
	if os.Geteuid() == 0 {
		return mode&0o111 != 0
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	// Widen both sides rather than narrowing the euid: uint32 -> int64 cannot
	// overflow, so the comparison is exact on every supported Unix platform.
	if int64(stat.Uid) == int64(os.Geteuid()) {
		return mode&0o300 == 0o300
	}
	if int64(stat.Gid) == int64(os.Getegid()) {
		return mode&0o030 == 0o030
	}
	groups, err := os.Getgroups()
	if err == nil {
		for _, gid := range groups {
			if int64(stat.Gid) == int64(gid) {
				return mode&0o030 == 0o030
			}
		}
	}
	return mode&0o003 == 0o003
}
