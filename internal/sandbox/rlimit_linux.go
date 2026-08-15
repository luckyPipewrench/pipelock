// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sandbox

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"
)

// Resource limit defaults for sandboxed child processes.
// These prevent fork bombs, disk fill, FD exhaustion, and core dumps.
const (
	rlimitNProc           uint64 = 4096    // absolute shared-UID task ceiling
	rlimitNoFile          uint64 = 4096    // max open file descriptors
	rlimitFSize           uint64 = 1 << 30 // 1 GB max file size (prevents disk fill)
	rlimitCore            uint64 = 0       // disable core dumps (prevents memory leak to disk)
	maxProcEntriesScanned        = 65536   // bound shared-UID preflight work on unusually busy hosts
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

func validateNProcHeadroom(tasks, limit uint64) error {
	if tasks >= limit {
		return fmt.Errorf("shared UID already has %d tasks at sandbox RLIMIT_NPROC ceiling %d", tasks, limit)
	}
	return nil
}

// currentUIDTaskCount counts tasks for this real UID without retaining the
// host's process table in memory. The scan is capped and fails closed if the
// procfs view is too large to inspect safely during launch.
func currentUIDTaskCount(stopAt uint64) (uint64, error) {
	procFD, err := unix.Open("/proc", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, fmt.Errorf("opening /proc: %w", err)
	}
	proc := os.NewFile(uintptr(procFD), "/proc")
	if proc == nil {
		_ = unix.Close(procFD)
		return 0, errors.New("opening /proc directory file")
	}
	defer func() { _ = proc.Close() }()

	uid := os.Getuid()
	var tasks uint64
	scanned := 0
	for {
		names, readErr := proc.Readdirnames(256)
		for _, pid := range names {
			if _, err := strconv.ParseUint(pid, 10, 64); err != nil {
				continue
			}
			scanned++
			if scanned > maxProcEntriesScanned {
				return 0, fmt.Errorf("shared UID task preflight exceeded %d process entries", maxProcEntriesScanned)
			}
			statusFile, err := openProcStatus(procFD, pid)
			if err != nil {
				if procEntryUnavailable(err) {
					continue
				}
				return 0, fmt.Errorf("opening /proc/%s/status: %w", pid, err)
			}
			status, statusErr := io.ReadAll(io.LimitReader(statusFile, 64<<10))
			_ = statusFile.Close()
			if statusErr != nil {
				if procEntryUnavailable(statusErr) {
					continue
				}
				return 0, fmt.Errorf("reading /proc/%s/status: %w", pid, statusErr)
			}
			realUID, threads, err := processUIDAndThreads(status)
			if err != nil {
				return 0, fmt.Errorf("parsing /proc/%s/status: %w", pid, err)
			}
			if realUID != uid {
				continue
			}
			if threads > math.MaxUint64-tasks {
				return 0, errors.New("shared UID task count overflows")
			}
			tasks += threads
			if tasks >= stopAt {
				return tasks, nil
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return 0, fmt.Errorf("reading /proc: %w", readErr)
		}
	}
	if tasks == 0 {
		return 0, errors.New("shared UID has no visible tasks")
	}
	return tasks, nil
}

func openProcStatus(procFD int, pid string) (*os.File, error) {
	fd, err := unix.Openat(procFD, filepath.Join(pid, "status"), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), pid+"/status"), nil
}

func procEntryUnavailable(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) ||
		errors.Is(err, unix.ESRCH) || errors.Is(err, unix.EACCES)
}

func processUIDAndThreads(status []byte) (int, uint64, error) {
	var uid int
	var threads uint64
	foundUID, foundThreads := false, false
	for len(status) > 0 {
		line, rest, _ := bytes.Cut(status, []byte{'\n'})
		status = rest
		fields := bytes.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch string(fields[0]) {
		case "Uid:":
			parsed, err := strconv.Atoi(string(fields[1]))
			if err != nil {
				return 0, 0, fmt.Errorf("real UID %q: %w", fields[1], err)
			}
			uid, foundUID = parsed, true
		case "Threads:":
			parsed, err := strconv.ParseUint(string(fields[1]), 10, 64)
			if err != nil {
				return 0, 0, fmt.Errorf("thread count %q: %w", fields[1], err)
			}
			threads, foundThreads = parsed, true
		}
		if foundUID && foundThreads {
			return uid, threads, nil
		}
	}
	return 0, 0, errors.New("uid or threads field is missing")
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
	tasks, err := currentUIDTaskCount(nprocLimit)
	if err != nil {
		return err
	}
	if err := validateNProcHeadroom(tasks, nprocLimit); err != nil {
		return err
	}

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
