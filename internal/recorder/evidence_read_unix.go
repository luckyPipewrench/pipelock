// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package recorder

import "syscall"

const (
	evidenceReadNoFollowFlag = syscall.O_NOFOLLOW
	evidenceReadNonblockFlag = syscall.O_NONBLOCK
)
