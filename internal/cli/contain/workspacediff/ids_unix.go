// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package workspacediff

import (
	"os"
	"syscall"
)

// statIDs returns the device and inode numbers backing fi, when the
// underlying platform exposes them via syscall.Stat_t (true for every unix
// this repo targets). ok is false only if fi's Sys() is not a *syscall.Stat_t.
func statIDs(fi os.FileInfo) (dev, ino uint64, ok bool) {
	st, isStatT := fi.Sys().(*syscall.Stat_t)
	if !isStatT {
		return 0, 0, false
	}
	return uint64(st.Dev), uint64(st.Ino), true
}
