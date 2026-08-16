// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package mcp

import (
	"os/exec"
	"syscall"
	"time"
)

// setupChildProcessGroup configures the child to start a fresh process
// group so pipelock can signal the whole subtree as a unit. Unix-only;
// Windows has no equivalent concept and the no-op stub in
// pgid_windows.go takes over on that build.
func setupChildProcessGroup(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
}

// captureChildPgid returns the process group ID of pid immediately after
// cmd.Start. Callers must finish all numeric group signaling before cmd.Wait
// reaps the leader: once a process group is empty, its numeric ID can be
// reused for an unrelated group. The caller must exclude a concurrent Wait
// beginning. Falls back to pid on Getpgid error
// (Setpgid=true guarantees pgid==pid at spawn time anyway). Returns 0 on
// Windows so downstream signal helpers become no-ops.
func captureChildPgid(pid int) int {
	if got, err := syscall.Getpgid(pid); err == nil {
		return got
	}
	return pid
}

// signalProcessGroupTerm sends SIGTERM to the given process group.
// Used by the ctx.Done watcher so cooperative descendants can exit
// cleanly before the post-Wait SIGKILL backstop fires. No-op for
// pgid <= 0 (Windows or failed capture).
func signalProcessGroupTerm(pgid int) {
	if pgid <= 0 {
		return
	}
	_ = syscall.Kill(-pgid, syscall.SIGTERM)
}

// terminateProcessGroup runs the SIGTERM + 100ms grace + SIGKILL sequence on
// the given process group before cmd.Wait reaps the group leader. Callers must
// exclude a concurrent Wait beginning: once Wait starts, the leader and its
// numeric group ID can be recycled.
func terminateProcessGroup(pgid int) {
	if pgid <= 0 {
		return
	}
	_ = syscall.Kill(-pgid, syscall.SIGTERM)
	time.Sleep(100 * time.Millisecond)
	_ = syscall.Kill(-pgid, syscall.SIGKILL)
}
