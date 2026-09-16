// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package workspacediff

import "golang.org/x/sys/unix"

// mountID returns path's Linux mount ID (STATX_MNT_ID) and whether the
// kernel supplied one. Unlike st_dev, a bind mount of a directory from
// elsewhere on the SAME filesystem gets its own distinct mount ID even
// though st_dev is identical to the source, so mount ID is the primitive
// that actually detects a same-device bind mount (H3). ok is false only if
// the statx call fails or the running kernel does not report STATX_MNT_ID
// (pre-5.8), in which case callers fall back to the device-only check.
func mountID(path string) (id uint64, ok bool) {
	var stx unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, path, unix.AT_SYMLINK_NOFOLLOW, unix.STATX_MNT_ID, &stx); err != nil {
		return 0, false
	}
	if stx.Mask&unix.STATX_MNT_ID == 0 {
		return 0, false
	}
	return stx.Mnt_id, true
}

// crossedMount reports whether entryMnt names a DIFFERENT mount than
// rootMnt. Both mount IDs must be known (rootOK && entryOK); when either is
// unavailable this returns false so the caller relies on its device-based
// fallback instead of silently treating "unknown" as "not crossed".
func crossedMount(rootMnt, entryMnt uint64, rootOK, entryOK bool) bool {
	if !rootOK || !entryOK {
		return false
	}
	return rootMnt != entryMnt
}
