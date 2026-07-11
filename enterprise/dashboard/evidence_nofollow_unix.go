//go:build enterprise && !windows

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package dashboard

import "syscall"

const evidenceNoFollowFlag = syscall.O_NOFOLLOW
