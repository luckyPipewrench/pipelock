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
// may run. This helper terminates the original process group; it cannot assign
// process-wide adopted children to a resolver. Callers must bound inherited
// output waits separately, and proxy teardown owns adopted-child cleanup.
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

	var observeErr error
	select {
	case observeErr = <-exited:
	case <-ctx.Done():
		terminate()
		observeErr = <-exited
	}

	// A failed observation must not skip the reap. Waitid only watches the
	// child exit without consuming it, so returning here would leave a live or
	// zombie child behind with nothing left to reap it, and the caller would
	// read the error as a completed teardown. Terminate and reap regardless,
	// and report the reap failure ahead of the observation failure because the
	// reap is the part that had to happen.
	terminate()
	if err := handoff.wait(cmd.Wait); err != nil {
		return err
	}
	return observeErr
}
