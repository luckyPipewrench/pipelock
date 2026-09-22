// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package sandbox

import (
	"errors"
	"syscall"
)

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

// processGone reports whether pid no longer names a live process.
//
// Signal 0 performs the permission and existence checks without delivering
// anything, so ESRCH is the answer that matters. The descendant under test is
// not a child of the test binary, so Wait cannot be used and its reaping is
// the intermediate parent's job; polling for ESRCH is what observes that.
func processGone(pid int) bool {
	return errors.Is(syscall.Kill(pid, 0), syscall.ESRCH)
}
