// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sandbox

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// SetChildSubreaper makes this process adopt orphaned descendants.
// Grandchildren that call setsid() or change PGID will still be
// reparented to us instead of PID 1 when their parent exits.
func SetChildSubreaper() error {
	return unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)
}

// ReapOrphans waits for all adopted orphan children to exit.
// Call after the main child exits when subreaper is active.
func ReapOrphans() {
	for {
		pid, err := syscall.Wait4(-1, nil, syscall.WNOHANG, nil)
		if pid <= 0 || err != nil {
			break
		}
	}
}
