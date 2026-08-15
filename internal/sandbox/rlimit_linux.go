// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sandbox

import (
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"

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

// sharedUIDNProcLimit returns a limit that leaves the sandbox process room for
// rlimitNProc additional tasks without setting a limit below tasks that already
// exist for a shared host UID. inheritedMax is the caller's existing hard cap.
func sharedUIDNProcLimit(tasks, inheritedMax uint64) (uint64, error) {
	if tasks > math.MaxUint64-rlimitNProc {
		return 0, errors.New("shared UID task count overflows RLIMIT_NPROC headroom")
	}
	limit := tasks + rlimitNProc
	if inheritedMax == unix.RLIM_INFINITY || limit <= inheritedMax {
		return limit, nil
	}
	if inheritedMax <= tasks {
		return 0, fmt.Errorf("shared UID already has %d tasks at inherited RLIMIT_NPROC hard cap %d", tasks, inheritedMax)
	}
	return inheritedMax, nil
}

// currentUIDTaskCount counts Linux tasks for the caller's real UID. It runs
// before Landlock, because fallback mode otherwise may not be allowed to read
// the host /proc entries needed to avoid a retroactively exhausted NPROC cap.
func currentUIDTaskCount() (uint64, error) {
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

	entries, err := proc.ReadDir(-1)
	if err != nil {
		return 0, fmt.Errorf("reading /proc: %w", err)
	}

	uid := os.Getuid()
	var tasks uint64
	for _, entry := range entries {
		pid := entry.Name()
		if _, err := strconv.ParseUint(pid, 10, 64); err != nil {
			continue
		}

		statusFile, err := openProcFile(procFD, filepath.Join(pid, "status"))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return 0, fmt.Errorf("reading /proc/%s/status: %w", pid, err)
		}
		status, readErr := io.ReadAll(statusFile)
		_ = statusFile.Close()
		if readErr != nil {
			return 0, fmt.Errorf("reading /proc/%s/status: %w", pid, readErr)
		}
		realUID, err := processRealUID(status)
		if err != nil {
			return 0, fmt.Errorf("parsing /proc/%s/status: %w", pid, err)
		}
		if realUID != uid {
			continue
		}

		taskDir, err := openProcFile(procFD, filepath.Join(pid, "task"))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return 0, fmt.Errorf("reading /proc/%s/task: %w", pid, err)
		}
		threadEntries, readErr := taskDir.ReadDir(-1)
		_ = taskDir.Close()
		if readErr != nil {
			return 0, fmt.Errorf("reading /proc/%s/task: %w", pid, readErr)
		}
		if uint64(len(threadEntries)) > math.MaxUint64-tasks {
			return 0, errors.New("shared UID task count overflows")
		}
		tasks += uint64(len(threadEntries))
	}
	if tasks == 0 {
		return 0, errors.New("shared UID has no visible tasks")
	}
	return tasks, nil
}

func openProcFile(procFD int, name string) (*os.File, error) {
	fd, err := unix.Openat(procFD, name, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

func processRealUID(status []byte) (int, error) {
	for _, line := range strings.Split(string(status), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "Uid:" {
			continue
		}
		uid, err := strconv.Atoi(fields[1])
		if err != nil {
			return 0, fmt.Errorf("real UID %q: %w", fields[1], err)
		}
		return uid, nil
	}
	return 0, errors.New("uid field is missing")
}

// ApplyRlimits sets resource limits on the calling process. Linux accounts
// RLIMIT_NPROC against the real UID shared with the host even for the mapped
// sandbox launches exercised here, so every mode receives current shared-UID
// usage plus 1024 tasks of headroom.
func ApplyRlimits() error {
	tasks, err := currentUIDTaskCount()
	if err != nil {
		return err
	}
	var inherited unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NPROC, &inherited); err != nil {
		return fmt.Errorf("getting inherited RLIMIT_NPROC: %w", err)
	}
	nprocLimit, err := sharedUIDNProcLimit(tasks, inherited.Max)
	if err != nil {
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

	for _, l := range limits {
		rlim := unix.Rlimit{Cur: l.value, Max: l.value}
		if err := unix.Setrlimit(l.resource, &rlim); err != nil {
			return fmt.Errorf("setting %s: %w", l.name, err)
		}
	}
	return nil
}
