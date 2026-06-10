// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package mcp

import (
	"context"
	"errors"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

func TestKillAdoptedDescendants_PreservesProtectedDirectChild(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting protected child: %v", err)
	}

	waitDone := make(chan error, 1)
	go func() { waitDone <- cmd.Wait() }()

	unregister := registerProtectedDirectPID(cmd.Process.Pid)
	defer unregister()

	killAdoptedDescendants()

	select {
	case err := <-waitDone:
		if err == nil {
			t.Fatal("protected direct child exited during adopted-descendant cleanup")
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ProcessState.Sys().(syscall.WaitStatus).Signaled() {
			t.Fatalf("protected direct child was signaled during adopted-descendant cleanup: %v", err)
		}
		t.Fatalf("protected direct child exited during adopted-descendant cleanup: %v", err)
	default:
	}

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("signaling protected child after cleanup: %v", err)
	}
	select {
	case <-waitDone:
	case <-time.After(5 * time.Second):
		t.Fatal("protected child did not exit after test cleanup SIGTERM")
	}
}
