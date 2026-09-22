// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package sandbox

import "syscall"

// killProcessGroup terminates the whole group led by pid.
//
// The launcher starts a sandboxed child with Setpgid, and the command under
// test runs beneath an intermediate parent, so signalling only the direct
// child orphans its descendants. A `sleep` left that way outlived the test
// binary and the CI process supervisor failed the job for the stray
// descendant, with every package reported as passing.
func killProcessGroup(pid int) error {
	return syscall.Kill(-pid, syscall.SIGKILL)
}
