//go:build !windows

package config

import (
	"context"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestReloader_SIGHUPReload(t *testing.T) {
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

	// Give watcher time to start
	time.Sleep(200 * time.Millisecond)

	// Update config file (SIGHUP reloads from disk, so the file must change)
	writeTestConfig(t, cfgPath, ModeAudit)

	// Small delay so the file is written before signal
	time.Sleep(50 * time.Millisecond)

	// Send SIGHUP to ourselves
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatalf("failed to send SIGHUP: %v", err)
	}

	select {
	case cfg := <-r.Changes():
		if cfg.Mode != ModeAudit {
			t.Errorf("expected mode audit after SIGHUP, got %s", cfg.Mode)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for SIGHUP-based reload")
	}
}
