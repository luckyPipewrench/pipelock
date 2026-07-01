// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package config

import (
	"context"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func signalUntilReload(t *testing.T, r *Reloader, mode string) *Config {
	t.Helper()
	deadline := time.After(3 * time.Second)
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := syscall.Kill(syscall.Getpid(), syscall.SIGHUP); err != nil {
			t.Fatalf("failed to send SIGHUP: %v", err)
		}
		select {
		case cfg, ok := <-r.Changes():
			if !ok {
				t.Fatal("changes channel closed before SIGHUP-based reload")
			}
			if cfg.Mode == mode {
				return cfg
			}
			t.Fatalf("expected mode %s after SIGHUP, got %s", mode, cfg.Mode)
		case <-ticker.C:
		case <-deadline:
			t.Fatalf("timed out waiting for SIGHUP-based reload to mode %s", mode)
		}
	}
}

func TestReloader_SIGHUPReload(t *testing.T) {
	// Keep SIGHUP caught for the whole test. The test sends a real process
	// signal; if delivery races with reloader signal cleanup, the default
	// SIGHUP action can terminate the test binary instead of failing the test.
	guard := make(chan os.Signal, 1)
	signal.Notify(guard, syscall.SIGHUP)
	defer signal.Stop(guard)

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "pipelock.yaml")
	writeTestConfig(t, cfgPath, "balanced")

	r := NewReloader(cfgPath)
	defer r.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		if err := r.Start(ctx); err != nil {
			t.Errorf("reloader error: %v", err)
		}
	}()

	waitForReloaderReady(t, r)

	// Update config file (SIGHUP reloads from disk, so the file must change)
	writeTestConfig(t, cfgPath, ModeAudit)

	signalUntilReload(t, r, ModeAudit)
}
