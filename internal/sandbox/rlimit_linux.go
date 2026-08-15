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
	rlimitNProc  uint64 = 4096    // absolute shared-UID task ceiling
	rlimitNoFile uint64 = 4096    // max open file descriptors
	rlimitFSize  uint64 = 1 << 30 // 1 GB max file size (prevents disk fill)
	rlimitCore   uint64 = 0       // disable core dumps (prevents memory leak to disk)
)

// boundedNProcLimit keeps either inherited cap when it is already stricter;
// otherwise it applies one absolute ceiling to every process sharing this UID.
// RLIMIT_NPROC is UID-wide on Linux, so adding current usage to a per-launch
// allowance lets concurrent sandboxes ratchet the total without bound.
func boundedNProcLimit(inherited unix.Rlimit) uint64 {
	limit := rlimitNProc
	if inherited.Cur != unix.RLIM_INFINITY && inherited.Cur < limit {
		limit = inherited.Cur
	}
	if inherited.Max != unix.RLIM_INFINITY && inherited.Max < limit {
		limit = inherited.Max
	}
	return limit
}

// ApplyRlimits sets resource limits on the calling process. Linux accounts
// RLIMIT_NPROC against the real UID shared with the host even for mapped
// sandbox launches, so every mode receives the same absolute shared-UID
// ceiling. If the UID is already at that ceiling, later process creation is
// denied; failing closed avoids expanding every same-UID sandbox's allowance.
func ApplyRlimits() error {
	var inherited unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NPROC, &inherited); err != nil {
		return fmt.Errorf("getting inherited RLIMIT_NPROC: %w", err)
	}
	nprocLimit := boundedNProcLimit(inherited)

	limits := []struct {
		resource int
		value    uint64
		name     string
	}{
		{unix.RLIMIT_NPROC, nprocLimit, "RLIMIT_NPROC"},
		{unix.RLIMIT_NOFILE, rlimitNoFile, "RLIMIT_NOFILE"},
		{unix.RLIMIT_FSIZE, rlimitFSize, "RLIMIT_FSIZE"},
		{unix.RLIMIT_CORE, rlimitCore, "RLIMIT_CORE"},
	}

	for _, limit := range limits {
		rlim := unix.Rlimit{Cur: limit.value, Max: limit.value}
		if err := unix.Setrlimit(limit.resource, &rlim); err != nil {
			return fmt.Errorf("setting %s: %w", limit.name, err)
		}
	}
	return nil
}
