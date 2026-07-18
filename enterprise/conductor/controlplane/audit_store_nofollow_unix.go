//go:build enterprise && !windows

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package controlplane

import "syscall"

const auditStoreNoFollowFlag = syscall.O_NOFOLLOW
