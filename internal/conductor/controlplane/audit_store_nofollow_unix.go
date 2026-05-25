// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package controlplane

import "syscall"

const auditStoreNoFollowFlag = syscall.O_NOFOLLOW
