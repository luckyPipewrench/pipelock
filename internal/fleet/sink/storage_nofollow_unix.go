// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package sink

import "syscall"

const storeNoFollowFlag = syscall.O_NOFOLLOW
