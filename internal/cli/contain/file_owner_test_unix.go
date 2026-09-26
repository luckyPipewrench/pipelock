// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package contain

import "syscall"

func fakeFileSysWithUID(uid uint32) any {
	return &syscall.Stat_t{Uid: uid, Gid: uid}
}

func fakeFileSysWithOwner(uid, gid uint32) any {
	return &syscall.Stat_t{Uid: uid, Gid: gid}
}
