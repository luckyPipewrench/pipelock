//go:build enterprise && !windows

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package siemforward

import "syscall"

// noFollowFlag closes the Lstat-to-open race on the final path component.
const noFollowFlag = syscall.O_NOFOLLOW
