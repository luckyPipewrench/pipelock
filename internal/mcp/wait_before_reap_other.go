// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package mcp

import (
	"context"
	"os/exec"
)

// waitForCommandWithProcessGroup waits for the direct child where the platform
// cannot observe exit without reaping it. Do not signal a numeric process
// group after Wait: that identifier may already name unrelated work.
//
// Cancellation still has to terminate the direct child. Without that, Wait
// blocks until a server decides to exit on its own, so a canceled resolver
// keeps running and the caller waits on it indefinitely. Termination goes
// through the handoff's stable process handle rather than a numeric group,
// which is the only identifier that stays safe once reaping has begun.
//
// Descendants the child spawned are a known limitation here, not something
// this path can close: without a subreaper there is no portable way to reach a
// grandchild that has left the child's group. On Linux the subreaper covers
// them; elsewhere they can outlive cancellation.
func waitForCommandWithProcessGroup(ctx context.Context, cmd *exec.Cmd, _ int, handoff *processExitHandoff) error {
	if handoff == nil {
		handoff = &processExitHandoff{}
	}
	if ctx == nil {
		return handoff.wait(cmd.Wait)
	}

	reaped := make(chan error, 1)
	go func() { reaped <- handoff.wait(cmd.Wait) }()

	select {
	case err := <-reaped:
		return err
	case <-ctx.Done():
	}

	// No numeric group teardown is available before reaping on this platform,
	// so both branches of the handoff resolve to the same stable handle.
	kill := func() bool { return cmd.Process != nil && cmd.Process.Kill() == nil }
	handoff.terminate(func() { _ = kill() }, kill)
	return <-reaped
}
