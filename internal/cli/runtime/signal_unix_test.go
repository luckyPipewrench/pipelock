// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package runtime

import (
	"syscall"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

// syncBuffer is defined in helpers_test.go (no build constraint).

func TestRegisterKillSwitchSignal(t *testing.T) {
	cfg := config.Defaults()
	ks := killswitch.New(cfg)
	buf := &syncBuffer{}

	cleanup := RegisterKillSwitchSignal(ks, buf)
	defer cleanup()

	// Send SIGUSR1 to toggle kill switch ON.
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGUSR1); err != nil {
		t.Fatalf("failed to send SIGUSR1: %v", err)
	}

	testwait.For(t, 2*time.Second, func() bool {
		return buf.contains("ACTIVATED")
	}, "ACTIVATED message after first SIGUSR1")

	// Send SIGUSR1 again to toggle OFF.
	buf.reset()
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGUSR1); err != nil {
		t.Fatalf("failed to send second SIGUSR1: %v", err)
	}

	testwait.For(t, 2*time.Second, func() bool {
		return buf.contains("DEACTIVATED")
	}, "DEACTIVATED message after second SIGUSR1")
}

func TestReloadSignalHint(t *testing.T) {
	hint := ReloadSignalHint()
	if hint != ", SIGHUP to reload" {
		t.Errorf("unexpected hint: %s", hint)
	}
}
