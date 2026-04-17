// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package mcp

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// setPdeathsig arranges for the direct MCP child to receive SIGTERM if
// pipelock itself dies. Combined with Setpgid and the subreaper bit,
// this closes the narrow window where `timeout` (or any external
// SIGKILL-escalating signal) tears pipelock down before the post-Wait
// cleanup path can run. On those paths the kernel still reaps the
// direct child via the parent-death signal, and any grandchildren the
// subreaper had adopted become reparented to PID 1 the moment pipelock
// dies — at which point we've already lost the race, but shortening
// the direct-child's lifetime closes the common case. Linux-only.
func setPdeathsig(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Pdeathsig = syscall.SIGTERM
}

// enableSubreaper makes pipelock adopt any orphaned descendants so that
// when the direct MCP subprocess exits, any grandchildren it detached
// (via setsid, double-fork, or explicit setpgid) reparent to pipelock
// instead of PID 1. Without this, pre-tag gate-found aggressive grandchildren
// survive the pgid SIGTERM/SIGKILL backstop because their pgid differs
// from the direct child's. Idempotent and process-wide.
func enableSubreaper() error {
	return unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)
}

// killAdoptedDescendants SIGKILLs every process whose parent PID matches
// our own. Call after the direct MCP child has been waited on and the
// pgid kill has drained; anything still around at that point was either
// a double-forked orphan (reparented to us by the subreaper bit) or a
// grandchild that set its own session via setsid. Either way, it is not
// a child of the original process group and the earlier -pid SIGKILL
// would not have reached it.
//
// We don't return errors — best-effort. A process we can't signal
// (ESRCH because it already died, EPERM because of a namespace boundary)
// is handled the same way: skip and move on.
func killAdoptedDescendants() {
	pid := os.Getpid()
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		childPID, convErr := strconv.Atoi(name)
		if convErr != nil {
			continue
		}
		if childPID == pid {
			continue
		}
		statPath := filepath.Clean("/proc/" + name + "/stat")
		statBytes, readErr := os.ReadFile(statPath)
		if readErr != nil {
			continue
		}
		// /proc/[pid]/stat field 4 is ppid. Field 2 is a parenthesized
		// comm string that may contain spaces, so rather than splitting
		// on whitespace across the whole line, locate the closing ')'
		// and index from there.
		stat := string(statBytes)
		cmdEnd := strings.LastIndex(stat, ")")
		if cmdEnd < 0 || cmdEnd+2 > len(stat) {
			continue
		}
		// After "<pid> (<comm>) ", the remaining fields are space-
		// separated: state (1), ppid (2), pgrp (3), session (4), ...
		rest := strings.Fields(stat[cmdEnd+1:])
		if len(rest) < 2 {
			continue
		}
		ppid, convErr := strconv.Atoi(rest[1])
		if convErr != nil {
			continue
		}
		if ppid != pid {
			continue
		}
		// Best-effort SIGKILL — ignore errors.
		_ = syscall.Kill(childPID, syscall.SIGKILL)
	}
}
