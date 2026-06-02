// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeTestConfig(t *testing.T, path, mode string) {
	t.Helper()
	content := []byte("version: 1\nmode: " + mode + "\n")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
}

func waitForReloaderReady(t *testing.T, r *Reloader) {
	t.Helper()
	select {
	case <-r.ready:
	case <-time.After(2 * time.Second):
		t.Fatal("reloader did not become ready")
	}
}

func waitForReload(t *testing.T, r *Reloader, mode string) *Config {
	t.Helper()
	select {
	case cfg, ok := <-r.Changes():
		if !ok {
			t.Fatal("changes channel closed before config reload")
		}
		if cfg.Mode != mode {
			t.Fatalf("expected mode %s, got %s", mode, cfg.Mode)
		}
		return cfg
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for config reload to mode %s", mode)
	}
	return nil
}

func writeAndWaitForReload(t *testing.T, r *Reloader, path, mode string) {
	t.Helper()
	writeTestConfig(t, path, mode)
	waitForReload(t, r, mode)
}

func renameUntilReload(t *testing.T, r *Reloader, dir, cfgPath, mode string) *Config {
	t.Helper()
	tmpPath := filepath.Join(dir, "pipelock.yaml.tmp")
	writeTestConfig(t, tmpPath, mode)
	if err := os.Rename(tmpPath, cfgPath); err != nil {
		t.Fatal(err)
	}
	return waitForReload(t, r, mode)
}

func TestReloader_FileChange(t *testing.T) {
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
	writeAndWaitForReload(t, r, cfgPath, ModeAudit)
}

// TestReloader_CoalesceKeepsLatest proves the reload buffer coalesces to the
// LATEST config when the consumer is slow, instead of dropping the new config
// and stranding the proxy on a stale pending one. Two reloads fire before the
// single-slot buffer is drained; the drained value must be the second
// (stronger) config, not the first. Before the fix, the second send was dropped
// non-blocking and the consumer would have applied the first config.
func TestReloader_CoalesceKeepsLatest(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "pipelock.yaml")

	r := NewReloader(cfgPath)
	defer r.Close()

	// First reload: balanced. Lands in the single-slot buffer, undrained.
	// (Both modes here are valid without extra config - strict would fail
	// validation for lack of api_allowlist and never reach the buffer.)
	writeTestConfig(t, cfgPath, ModeBalanced)
	r.tryReload()

	// Second reload: audit. Buffer is full, so the fix must discard the stale
	// balanced config and enqueue audit rather than dropping audit.
	writeTestConfig(t, cfgPath, ModeAudit)
	r.tryReload()

	select {
	case cfg := <-r.Changes():
		if cfg.Mode != ModeAudit {
			t.Fatalf("coalesce kept stale config: got mode %q, want %q (the latest reload)", cfg.Mode, ModeAudit)
		}
	default:
		t.Fatal("expected a coalesced config in the buffer, got none")
	}

	// Only one slot: after draining the latest there must be nothing stale left.
	select {
	case cfg := <-r.Changes():
		t.Fatalf("expected empty buffer after draining latest, got stale mode %q", cfg.Mode)
	default:
	}
}

func TestReloader_InvalidConfig(t *testing.T) {
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
	writeAndWaitForReload(t, r, cfgPath, ModeAudit)

	// Write invalid config
	if err := os.WriteFile(cfgPath, []byte("mode: invalid_mode\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Should NOT receive a config (invalid configs are dropped)
	select {
	case cfg := <-r.Changes():
		t.Fatalf("expected no config for invalid file, got mode=%s", cfg.Mode)
	case <-time.After(500 * time.Millisecond):
		// Expected: no config emitted for invalid file
	}
}

func TestReloader_CloseStopsStart(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "pipelock.yaml")
	writeTestConfig(t, cfgPath, "balanced")

	r := NewReloader(cfgPath)

	done := make(chan struct{})
	go func() {
		_ = r.Start(context.Background())
		close(done)
	}()

	waitForReloaderReady(t, r)
	r.Close()

	select {
	case <-done:
		// Start returned after Close
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after Close")
	}
}

func TestReloader_CloseIdempotent(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "pipelock.yaml")
	writeTestConfig(t, cfgPath, "balanced")

	r := NewReloader(cfgPath)
	r.Close()
	r.Close() // should not panic
}

func TestReloader_ContextCancellation(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "pipelock.yaml")
	writeTestConfig(t, cfgPath, "balanced")

	r := NewReloader(cfgPath)
	defer r.Close()

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		_ = r.Start(ctx)
		close(done)
	}()

	waitForReloaderReady(t, r)
	cancel()

	select {
	case <-done:
		// Start returned after context cancelled
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after context cancellation")
	}
}

func TestReloader_StartIsOneShot(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "pipelock.yaml")
	writeTestConfig(t, cfgPath, "balanced")

	r := NewReloader(cfgPath)
	defer r.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- r.Start(ctx)
	}()

	waitForReloaderReady(t, r)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("first Start returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first Start did not return after context cancellation")
	}

	if err := r.Start(context.Background()); err == nil {
		t.Fatal("second Start succeeded; expected one-shot error")
	}
}

func TestReloader_NonMatchingFileIgnored(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "pipelock.yaml")
	writeTestConfig(t, cfgPath, "balanced")

	r := NewReloader(cfgPath)
	defer r.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	go func() {
		if err := r.Start(ctx); err != nil {
			t.Errorf("reloader error: %v", err)
		}
	}()

	waitForReloaderReady(t, r)
	writeAndWaitForReload(t, r, cfgPath, ModeAudit)

	// Write a different file in the same directory - should be ignored
	otherPath := filepath.Join(dir, "other.yaml")
	if err := os.WriteFile(otherPath, []byte("version: 1\nmode: strict\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Should NOT receive a config reload
	select {
	case cfg := <-r.Changes():
		t.Fatalf("expected no config for non-matching file, got mode=%s", cfg.Mode)
	case <-time.After(500 * time.Millisecond):
		// Expected: non-matching file name ignored
	}
}

func TestReloader_ChangesClosedAfterStart(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "pipelock.yaml")
	writeTestConfig(t, cfgPath, "balanced")

	r := NewReloader(cfgPath)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		_ = r.Start(ctx)
		close(done)
	}()

	waitForReloaderReady(t, r)
	cancel()

	<-done

	// After Start returns, the onChange channel should be closed
	_, ok := <-r.Changes()
	if ok {
		t.Error("expected Changes() channel to be closed after Start returns")
	}
}

func TestReloader_RenameReload(t *testing.T) {
	// Simulate vim-style save: write temp file, rename over original
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
	renameUntilReload(t, r, dir, cfgPath, ModeAudit)
}
