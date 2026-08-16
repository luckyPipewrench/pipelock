// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package mcp

import (
	"context"
	"os/exec"
	"testing"
	"time"
)

func TestWaitForCommandWithProcessGroup_CancellationAfterReapingUsesStableHandle(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cmd := exec.Command("/bin/sh", "-c", "umask 077; while :; do :; done")
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting resolver command: %v", err)
	}
	reaped := false

	// Model cmd.Wait winning the race. pgid is deliberately zero: a stale
	// numeric-group path is a no-op here, so only the stable process handle can
	// release the still-running command and let the helper return.
	handoff := &processExitHandoff{}
	handoff.beginReaping()
	done := make(chan error, 1)
	go func() {
		done <- waitForCommandWithProcessGroup(ctx, cmd, 0, handoff)
	}()
	t.Cleanup(func() {
		if reaped {
			return
		}
		_ = cmd.Process.Kill()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	})

	select {
	case err := <-done:
		reaped = true
		if err == nil {
			t.Fatal("resolver command exited cleanly after forced teardown")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("resolver teardown did not use the stable process handle after reaping began")
	}
}
