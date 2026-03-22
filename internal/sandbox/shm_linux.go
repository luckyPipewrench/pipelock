// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sandbox

import "syscall"

// mountPrivateShm mounts a private tmpfs on /dev/shm so the sandboxed
// process cannot access same-user shared memory from the host. Must be
// called BEFORE Landlock so the Landlock rule for /dev/shm/ applies to
// the private mount, not the host's.
//
// Seccomp blocks mount AFTER this runs, so no seccomp exception is needed.
func mountPrivateShm() error {
	// Establish propagation barrier: make the root mount private so the
	// tmpfs mount below doesn't propagate back to the host's mount namespace.
	// Without this, systems with shared mounts (the default) would leak
	// the private /dev/shm to the host.
	if err := syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		return err
	}
	const shmSizeOpt = "size=64m,mode=1777" // 64MB, world-writable with sticky bit
	return syscall.Mount("tmpfs", "/dev/shm", "tmpfs",
		syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC,
		shmSizeOpt)
}
