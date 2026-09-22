// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package sandbox

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strconv"
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

// processGone reports whether pid no longer names a RUNNING process.
//
// Signal 0 performs the permission and existence checks without delivering
// anything, so ESRCH is one answer that matters. It is not the only one. The
// descendant under test is not a child of the test binary, so Wait cannot be
// used on it and reaping belongs to whoever inherits it. SIGKILL takes the
// shell down before it can reap its own background child, so that child
// becomes a ZOMBIE: it has exited, and kill(pid, 0) keeps succeeding until
// something reaps it. Under systemd that happens in milliseconds, which is why
// this reads as correct on a workstation. In a container whose init does not
// reap, it never happens, and treating a zombie as alive would fail a test
// whose subject has already died.
//
// A zombie is dead for this question, so it counts as gone.
func processGone(pid int) bool {
	if errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) {
		return true
	}
	return processIsZombie(pid)
}

// processIsZombie reports whether pid has exited and is only awaiting reaping.
//
// The state is the first field after the executable name in /proc/<pid>/stat.
// That name is wrapped in parentheses and may itself contain spaces and
// parentheses, so the scan starts after the LAST closing parenthesis rather
// than splitting the line on whitespace. Where /proc is absent the file simply
// fails to open and the caller keeps the signal-based answer.
func processIsZombie(pid int) bool {
	data, err := os.ReadFile(filepath.Clean("/proc/" + strconv.Itoa(pid) + "/stat"))
	if err != nil {
		return false
	}
	end := bytes.LastIndexByte(data, ')')
	if end < 0 || end+2 >= len(data) {
		return false
	}
	return data[end+2] == 'Z'
}
