// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package runtime

import (
	"syscall"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
)

// syncBuffer is defined in helpers_test.go (no build constraint).

func TestRegisterKillSwitchSignal(t *testing.T) {
	cfg := config.Defaults()
	ks := killswitch.New(cfg)
	buf := &syncBuffer{}
	cmd := &cobra.Command{}
	cmd.SetErr(buf)

	cleanup := RegisterKillSwitchSignal(ks, cmd)
	defer cleanup()

	// Send SIGUSR1 to toggle kill switch ON.
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGUSR1); err != nil {
		t.Fatalf("failed to send SIGUSR1: %v", err)
	}

	// Wait for the goroutine to process the signal.
	time.Sleep(200 * time.Millisecond)

	if !buf.contains("ACTIVATED") {
		t.Error("expected ACTIVATED message after first SIGUSR1")
	}

	// Send SIGUSR1 again to toggle OFF.
	buf.reset()
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGUSR1); err != nil {
		t.Fatalf("failed to send second SIGUSR1: %v", err)
	}

	time.Sleep(200 * time.Millisecond)

	if !buf.contains("DEACTIVATED") {
		t.Error("expected DEACTIVATED message after second SIGUSR1")
	}
}

func TestReloadSignalHint(t *testing.T) {
	hint := ReloadSignalHint()
	if hint != ", SIGHUP to reload" {
		t.Errorf("unexpected hint: %s", hint)
	}
}
