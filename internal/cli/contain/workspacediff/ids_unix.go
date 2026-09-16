// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package workspacediff

import (
	"fmt"
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

// openRegularNoFollow opens path for reading with O_NOFOLLOW so a path that
// was replaced by a symlink between the directory walk and this open fails
// closed instead of silently reading through the symlink's target.
func openRegularNoFollow(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s (no-follow): %w", path, err)
	}
	return os.NewFile(uintptr(fd), path), nil
}
