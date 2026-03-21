// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sandbox

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// Resource limit defaults for sandboxed child processes.
// These prevent fork bombs, disk fill, FD exhaustion, and core dumps.
const (
	rlimitNProc  uint64 = 1024    // max child processes (prevents fork bomb)
	rlimitNoFile uint64 = 4096    // max open file descriptors
	rlimitFSize  uint64 = 1 << 30 // 1 GB max file size (prevents disk fill)
	rlimitCore   uint64 = 0       // disable core dumps (prevents memory leak to disk)
)

// ApplyRlimits sets resource limits on the calling process. These are
// inherited by exec'd children and constrain resource consumption.
func ApplyRlimits() error {
	limits := []struct {
		resource int
		value    uint64
		name     string
	}{
		{unix.RLIMIT_NPROC, rlimitNProc, "RLIMIT_NPROC"},
		{unix.RLIMIT_NOFILE, rlimitNoFile, "RLIMIT_NOFILE"},
		{unix.RLIMIT_FSIZE, rlimitFSize, "RLIMIT_FSIZE"},
		{unix.RLIMIT_CORE, rlimitCore, "RLIMIT_CORE"},
	}

	for _, l := range limits {
		rlim := unix.Rlimit{Cur: l.value, Max: l.value}
		if err := unix.Setrlimit(l.resource, &rlim); err != nil {
			return fmt.Errorf("setting %s: %w", l.name, err)
		}
	}
	return nil
}
