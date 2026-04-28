// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package privacy

import "syscall"

// noFollowFlag is OR'd into os.OpenFile flags so the kernel refuses to
// resolve the final path component if it is a symlink. Closes the
// stat-then-open TOCTOU window after Lstat has already rejected
// directory-entry-level symlinks.
const noFollowFlag = syscall.O_NOFOLLOW

// errELOOP is the sentinel returned by openat(2) when O_NOFOLLOW catches
// a symlink raced into place between Lstat and Open.
var errELOOP error = syscall.ELOOP
