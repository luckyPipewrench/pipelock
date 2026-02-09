package config

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
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

	// Give watcher time to start
	time.Sleep(200 * time.Millisecond)

	// Modify config
	writeTestConfig(t, cfgPath, "audit")

	select {
	case cfg := <-r.Changes():
		if cfg.Mode != "audit" { //nolint:goconst // test values
			t.Errorf("expected mode audit, got %s", cfg.Mode)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for config reload")
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

	time.Sleep(200 * time.Millisecond)

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

	time.Sleep(100 * time.Millisecond)
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

	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// Start returned after context cancelled
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after context cancellation")
	}
}

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
	writeTestConfig(t, cfgPath, "audit")

	// Small delay so the file is written before signal
	time.Sleep(50 * time.Millisecond)

	// Send SIGHUP to ourselves
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatalf("failed to send SIGHUP: %v", err)
	}

	select {
	case cfg := <-r.Changes():
		if cfg.Mode != "audit" { //nolint:goconst // test value
			t.Errorf("expected mode audit after SIGHUP, got %s", cfg.Mode)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for SIGHUP-based reload")
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

	// Give watcher time to start
	time.Sleep(200 * time.Millisecond)

	// Write a different file in the same directory — should be ignored
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

	time.Sleep(100 * time.Millisecond)
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

	time.Sleep(200 * time.Millisecond)

	// Write to temp, then rename (vim pattern)
	tmpPath := filepath.Join(dir, "pipelock.yaml.tmp")
	writeTestConfig(t, tmpPath, "audit")
	if err := os.Rename(tmpPath, cfgPath); err != nil {
		t.Fatal(err)
	}

	select {
	case cfg := <-r.Changes():
		if cfg.Mode != "audit" { //nolint:goconst // test values
			t.Errorf("expected mode audit, got %s", cfg.Mode)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for rename-based reload")
	}
}
