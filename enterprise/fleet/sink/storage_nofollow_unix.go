//go:build enterprise && !windows

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package sink

import "syscall"

const storeNoFollowFlag = syscall.O_NOFOLLOW
