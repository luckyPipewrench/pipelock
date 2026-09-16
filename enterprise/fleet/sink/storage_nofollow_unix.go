//go:build enterprise && !windows

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package sink

import "syscall"

const storeNoFollowFlag = syscall.O_NOFOLLOW
