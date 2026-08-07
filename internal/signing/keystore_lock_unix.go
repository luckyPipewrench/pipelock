// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

// Deliberately not the "unix" meta-tag. Go matches that for aix and hurd as
// well, and golang.org/x/sys/unix defines Flock for neither, so the build tag
// was wider than the symbol it depends on and the package failed to compile
// wherever the two disagreed. This lists exactly the platforms that have
// Flock. GOOS=ios and GOOS=android are covered by darwin and linux, and
// GOOS=illumos by solaris, because Go satisfies those tags too.

package signing

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func withAgentLock(path string, fn func() error) error {
	clean := filepath.Clean(path)
	fd, err := unix.Open(clean, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("opening agent key lock: %w", err)
	}
	f := os.NewFile(uintptr(fd), clean)
	defer func() { _ = f.Close() }()

	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fmt.Errorf("checking agent key lock: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("agent key lock is not a regular file")
	}
	if err := unix.Fchmod(fd, 0o600); err != nil {
		return fmt.Errorf("securing agent key lock: %w", err)
	}
	if err := unix.Flock(fd, unix.LOCK_EX); err != nil {
		return fmt.Errorf("acquiring agent key lock: %w", err)
	}
	defer func() { _ = unix.Flock(fd, unix.LOCK_UN) }()
	return fn()
}
