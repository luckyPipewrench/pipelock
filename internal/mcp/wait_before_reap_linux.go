// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package mcp

import (
	"context"
	"os/exec"

	"golang.org/x/sys/unix"
)

// waitForCommandWithProcessGroup observes the child exit without reaping it,
// signals the original process group while its leader still owns the numeric
// PID, then lets exec.Cmd reap the child. The shared handoff also makes the
// cancellation path safe if reaping wins the race: then only cmd.Process.Kill
// may run. A deferred approval resolver is short-lived, so descendants that
// survive after their leader exits are not a valid completion state.
func waitForCommandWithProcessGroup(ctx context.Context, cmd *exec.Cmd, pgid int, handoff *processExitHandoff) error {
	if handoff == nil {
		handoff = &processExitHandoff{}
	}
	terminate := func() {
		handoff.terminate(func() { terminateProcessGroup(pgid) }, func() bool {
			return cmd.Process != nil && cmd.Process.Kill() == nil
		})
	}
	exited := make(chan error, 1)
	go func() {
		exited <- unix.Waitid(unix.P_PID, cmd.Process.Pid, nil, unix.WEXITED|unix.WNOWAIT, nil)
	}()

	select {
	case err := <-exited:
		if err != nil {
			return err
		}
	case <-ctx.Done():
		terminate()
		if err := <-exited; err != nil {
			return err
		}
	}

	terminate()
	return handoff.wait(cmd.Wait)
}
