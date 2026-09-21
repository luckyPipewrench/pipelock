// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package contain

import (
	"fmt"
	"os"
	"syscall"

	"github.com/luckyPipewrench/pipelock/internal/cli/session"
)

// repairLeafModeNoFollow reads and tightens the mode of the FILE ITSELF rather
// than of whatever its path resolves to at each call, and reports the mode it
// found.
//
// The managed config lives in a directory the proxy account owns, so that
// account can replace the leaf between a path-based stat and a path-based
// chmod and redirect a privileged mode change onto any file on the host
// (CWE-59). Opening once with O_NOFOLLOW and operating on the descriptor
// removes the window: the open fails outright if the leaf is a symlink, and
// the fstat and fchmod both target the object that open returned, whatever the
// path means by then.
//
// It is deliberately mode-only. applyAgentOwnershipNoFollow is the sibling for
// agent-readable files and also chowns to the agent, which would be wrong here:
// the managed config is proxy-owned and agent-denied on purpose.
func setLeafModeNoFollow(path string, mode os.FileMode, onlyWhenTooPermissive bool) (os.FileMode, bool, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return 0, false, fmt.Errorf("open %s without following symlinks: %w", path, err)
	}
	defer func() { _ = syscall.Close(fd) }()

	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return 0, false, fmt.Errorf("stat %s: %w", path, err)
	}
	// A directory or device here would mean the leaf is not the config install
	// wrote, so refuse rather than tighten it.
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return 0, false, fmt.Errorf("%s is not a regular file; refusing to change its mode", path)
	}

	previous := os.FileMode(st.Mode).Perm()
	// Tightening must not LOOSEN. The admin CLI accepts any mode with no group,
	// world or owner-execute bit, so 0400 already satisfies it and rewriting it
	// to 0600 would hand the owner write access it did not have. Repair only a
	// mode the CLI would actually refuse. Rollback passes false here because it
	// restores exactly what the repair found, including a mode the CLI refuses.
	if onlyWhenTooPermissive && previous&session.ConfigPermRejectMask == 0 {
		return previous, false, nil
	}
	if previous == mode.Perm() {
		return previous, false, nil
	}
	if err := syscall.Fchmod(fd, uint32(mode.Perm())); err != nil {
		return previous, false, fmt.Errorf("chmod %s: %w", path, err)
	}
	return previous, true, nil
}
