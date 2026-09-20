// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package contain

import (
	"fmt"
	"os"
	"syscall"
)

// applyAgentOwnershipNoFollow sets mode and ownership on the FILE ITSELF rather
// than on whatever its path resolves to at each call.
//
// The previous shape validated the path and then called chmod and chown on that
// path, resolving it twice more. Both files live in a directory the contained
// agent owns, so the agent could replace the leaf with a symlink between the
// validation and the chmod and redirect a privileged mode change onto any file
// on the host. Opening once with O_NOFOLLOW and operating on the descriptor
// removes the window: the open fails outright if the leaf is a symlink, and
// every subsequent operation targets the object that open returned, whatever
// the path means by then.
func applyAgentOwnershipNoFollow(path string, mode os.FileMode, uid, gid int) error {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open %s without following symlinks: %w", path, err)
	}
	defer func() { _ = syscall.Close(fd) }()

	// A directory or device here would mean the leaf is not what install wrote,
	// so refuse rather than apply agent ownership to it.
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return fmt.Errorf("%s is not a regular file; refusing to change its ownership", path)
	}
	if err := syscall.Fchmod(fd, uint32(mode.Perm())); err != nil {
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	if err := syscall.Fchown(fd, uid, gid); err != nil {
		return fmt.Errorf("chown %s: %w", path, err)
	}
	return nil
}
