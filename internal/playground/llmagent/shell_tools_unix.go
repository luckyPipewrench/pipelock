// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build aix || android || darwin || dragonfly || freebsd || illumos || ios || linux || netbsd || openbsd || solaris

package llmagent

import (
	"errors"
	"os/exec"
	"syscall"
	"time"
)

// processGroupWaitDelay bounds how long Wait blocks after the group is killed in
// case a descendant still holds an inherited pipe open. After it elapses the I/O
// streams are force-closed and Wait returns, so a backgrounded child cannot hang
// the tool call.
const processGroupWaitDelay = 3 * time.Second

const runCommandSupported = true

// configureRunCommand makes cmd lead its own process group and, on context
// cancellation/timeout, kills that group rather than just the direct
// child. exec.CommandContext's default only signals cmd.Process, so a command
// that ordinarily forks or backgrounds work ("sleep 100 &") would outlive a
// run_command timeout. Setpgid puts the shell and ordinary descendants in one
// group; killing the negative pid (-pgid) reaps that group.
func configureRunCommand(cmd *exec.Cmd) error {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		// With Setpgid the leader's pid equals its pgid, so -pid addresses the
		// whole group. Ignore ESRCH (already gone).
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
			return err
		}
		return nil
	}
	cmd.WaitDelay = processGroupWaitDelay
	return nil
}
