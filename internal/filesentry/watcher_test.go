// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package filesentry

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func ptrBool(b bool) *bool { return &b }

// armAndStart arms the watcher synchronously, then starts the event loop
// in a goroutine. Returns after watches are installed.
func armAndStart(t *testing.T, w Watcher, ctx context.Context) {
	t.Helper()
	if err := w.Arm(); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	go func() {
		if err := w.Start(ctx); err != nil {
			t.Errorf("Start: %v", err)
		}
	}()
}

func TestWatcher_DetectsSecretWrite(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.FileSentry{
		Enabled:     true,
		WatchPaths:  []string{dir},
		ScanContent: ptrBool(true),
	}

	// Use real scanner with default DLP patterns.
	defaults := config.Defaults()
	defaults.Internal = nil // no SSRF checks in tests
	sc := scanner.New(defaults)
	defer sc.Close()

	w, err := NewWatcher(cfg, sc, nil)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	defer func() { _ = w.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	armAndStart(t, w, ctx)

	// Write a file containing a fake Anthropic API key.
	// Build at runtime to avoid gosec G101.
	secret := "sk-ant-" + "api03-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
	if err := os.WriteFile(filepath.Join(dir, "data.json"), []byte(secret), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	select {
	case f := <-w.Findings():
		if f.PatternName == "" {
			t.Error("expected DLP pattern match, got empty PatternName")
		}
		if f.Path != filepath.Join(dir, "data.json") {
			t.Errorf("expected path %q, got %q", filepath.Join(dir, "data.json"), f.Path)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for finding")
	}
}

func TestWatcher_CleanFileNoFinding(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.FileSentry{
		Enabled:     true,
		WatchPaths:  []string{dir},
		ScanContent: ptrBool(true),
	}

	defaults := config.Defaults()
	defaults.Internal = nil
	sc := scanner.New(defaults)
	defer sc.Close()

	w, err := NewWatcher(cfg, sc, nil)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	defer func() { _ = w.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	armAndStart(t, w, ctx)

	// Write a file with no secrets.
	if err := os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("hello world"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Wait past the debounce window. No finding should appear.
	select {
	case f := <-w.Findings():
		t.Errorf("expected no finding for clean file, got %+v", f)
	case <-time.After(300 * time.Millisecond):
		// Good — no finding emitted.
	}
}

func TestWatcher_IgnoredPatterns(t *testing.T) {
	dir := t.TempDir()

	// Create a "node_modules" subdirectory before starting the watcher.
	nmDir := filepath.Join(dir, "node_modules")
	if err := os.MkdirAll(nmDir, 0o750); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	cfg := &config.FileSentry{
		Enabled:        true,
		WatchPaths:     []string{dir},
		ScanContent:    ptrBool(true),
		IgnorePatterns: []string{"node_modules/**"},
	}

	defaults := config.Defaults()
	defaults.Internal = nil
	sc := scanner.New(defaults)
	defer sc.Close()

	w, err := NewWatcher(cfg, sc, nil)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	defer func() { _ = w.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	armAndStart(t, w, ctx)

	// Write a secret inside the ignored directory.
	secret := "sk-ant-" + "api03-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
	if err := os.WriteFile(filepath.Join(nmDir, "leaked.txt"), []byte(secret), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	select {
	case f := <-w.Findings():
		t.Errorf("expected no finding for ignored path, got %+v", f)
	case <-time.After(300 * time.Millisecond):
		// Good — ignored path was not scanned.
	}
}

func TestWatcher_SubdirCreation(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.FileSentry{
		Enabled:     true,
		WatchPaths:  []string{dir},
		ScanContent: ptrBool(true),
	}

	defaults := config.Defaults()
	defaults.Internal = nil
	sc := scanner.New(defaults)
	defer sc.Close()

	w, err := NewWatcher(cfg, sc, nil)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	defer func() { _ = w.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	armAndStart(t, w, ctx)

	// Create a new subdirectory, then write a secret inside it.
	subDir := filepath.Join(dir, "newdir")
	if err := os.MkdirAll(subDir, 0o750); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	// Small delay for the Create event to register the new watch.
	time.Sleep(100 * time.Millisecond)

	secret := "sk-ant-" + "api03-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
	if err := os.WriteFile(filepath.Join(subDir, "secret.txt"), []byte(secret), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	select {
	case f := <-w.Findings():
		if f.PatternName == "" {
			t.Error("expected DLP pattern match in new subdirectory")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout — new subdirectory write was not detected")
	}
}

func TestWatcher_ScanContentDisabled(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.FileSentry{
		Enabled:     true,
		WatchPaths:  []string{dir},
		ScanContent: ptrBool(false),
	}

	defaults := config.Defaults()
	defaults.Internal = nil
	sc := scanner.New(defaults)
	defer sc.Close()

	w, err := NewWatcher(cfg, sc, nil)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	defer func() { _ = w.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	armAndStart(t, w, ctx)

	// Write a secret — should NOT be scanned because scan_content is false.
	secret := "sk-ant-" + "api03-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
	if err := os.WriteFile(filepath.Join(dir, "data.json"), []byte(secret), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	select {
	case f := <-w.Findings():
		t.Errorf("expected no finding with scan_content=false, got %+v", f)
	case <-time.After(300 * time.Millisecond):
		// Good.
	}
}

func TestWatcher_CloseIdempotent(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.FileSentry{
		Enabled:     true,
		WatchPaths:  []string{dir},
		ScanContent: ptrBool(true),
	}

	defaults := config.Defaults()
	defaults.Internal = nil
	sc := scanner.New(defaults)
	defer sc.Close()

	w, err := NewWatcher(cfg, sc, nil)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}

	if err := w.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

func TestWatcher_OversizedFileSkipped(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.FileSentry{
		Enabled:     true,
		WatchPaths:  []string{dir},
		ScanContent: ptrBool(true),
	}

	defaults := config.Defaults()
	defaults.Internal = nil
	sc := scanner.New(defaults)
	defer sc.Close()

	w, err := NewWatcher(cfg, sc, nil)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	defer func() { _ = w.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	armAndStart(t, w, ctx)

	// Write a file larger than maxFileSize (10MB). Use a sparse approach:
	// write a small secret then pad with zeros to exceed the limit.
	hugePath := filepath.Join(dir, "huge.bin")
	f, err := os.Create(filepath.Clean(hugePath))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	secret := "sk-ant-" + "api03-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
	_, _ = f.WriteString(secret)
	// Seek past 10MB to make the file large without writing all bytes.
	if _, err := f.Seek(11*1024*1024, 0); err != nil {
		t.Fatalf("Seek: %v", err)
	}
	_, _ = f.Write([]byte{0})
	_ = f.Close()

	select {
	case finding := <-w.Findings():
		t.Errorf("expected no finding for oversized file, got %+v", finding)
	case <-time.After(300 * time.Millisecond):
		// Good — oversized file was skipped.
	}
}

func TestWatcher_EmptyFileSkipped(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.FileSentry{
		Enabled:     true,
		WatchPaths:  []string{dir},
		ScanContent: ptrBool(true),
	}

	defaults := config.Defaults()
	defaults.Internal = nil
	sc := scanner.New(defaults)
	defer sc.Close()

	w, err := NewWatcher(cfg, sc, nil)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	defer func() { _ = w.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	armAndStart(t, w, ctx)

	// Write an empty file.
	if err := os.WriteFile(filepath.Join(dir, "empty.txt"), []byte{}, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	select {
	case finding := <-w.Findings():
		t.Errorf("expected no finding for empty file, got %+v", finding)
	case <-time.After(300 * time.Millisecond):
		// Good.
	}
}

func TestWatcher_WithLineageAttribution(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.FileSentry{
		Enabled:     true,
		WatchPaths:  []string{dir},
		ScanContent: ptrBool(true),
	}

	defaults := config.Defaults()
	defaults.Internal = nil
	sc := scanner.New(defaults)
	defer sc.Close()

	// Use a mock lineage that always reports the file as open by an agent process.
	lin := &mockLineage{hasFileOpen: true}

	w, err := NewWatcher(cfg, sc, lin)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	defer func() { _ = w.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	armAndStart(t, w, ctx)

	secret := "sk-ant-" + "api03-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
	if err := os.WriteFile(filepath.Join(dir, "agent-leak.json"), []byte(secret), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	select {
	case f := <-w.Findings():
		if !f.IsAgent {
			t.Error("expected IsAgent=true when lineage reports file is open")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for finding")
	}
}

// mockLineage is a test double for the Lineage interface.
type mockLineage struct {
	hasFileOpen bool
}

func (m *mockLineage) EnableSubreaper() error    { return nil }
func (m *mockLineage) TrackPID(_ int)            {}
func (m *mockLineage) IsDescendant(_ int) bool   { return false }
func (m *mockLineage) HasFileOpen(_ string) bool { return m.hasFileOpen }

func TestWatcher_ArmNonexistentPath(t *testing.T) {
	cfg := &config.FileSentry{
		Enabled:     true,
		WatchPaths:  []string{"/nonexistent/path/that/does/not/exist"},
		ScanContent: ptrBool(true),
	}

	defaults := config.Defaults()
	defaults.Internal = nil
	sc := scanner.New(defaults)
	defer sc.Close()

	w, err := NewWatcher(cfg, sc, nil)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	defer func() { _ = w.Close() }()

	if err := w.Arm(); err == nil {
		t.Error("expected error for nonexistent watch path")
	}
}

func TestWatcher_ArmRejectsFilePath(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "not-a-dir.txt")
	if err := os.WriteFile(filePath, []byte("hi"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg := &config.FileSentry{
		Enabled:     true,
		WatchPaths:  []string{filePath},
		ScanContent: ptrBool(true),
	}

	defaults := config.Defaults()
	defaults.Internal = nil
	sc := scanner.New(defaults)
	defer sc.Close()

	w, err := NewWatcher(cfg, sc, nil)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	defer func() { _ = w.Close() }()

	if err := w.Arm(); err == nil {
		t.Error("expected error when watch_path is a file, not a directory")
	}
}

func TestWatcher_RenameIntoPlace(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.FileSentry{
		Enabled:     true,
		WatchPaths:  []string{dir},
		ScanContent: ptrBool(true),
	}

	defaults := config.Defaults()
	defaults.Internal = nil
	sc := scanner.New(defaults)
	defer sc.Close()

	w, err := NewWatcher(cfg, sc, nil)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	defer func() { _ = w.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	armAndStart(t, w, ctx)

	// Write a secret to a temp file OUTSIDE the watched directory,
	// then rename it into the watched directory. This must still be detected.
	tmpFile := filepath.Join(t.TempDir(), "staged.txt")
	secret := "sk-ant-" + "api03-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
	if err := os.WriteFile(tmpFile, []byte(secret), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	dest := filepath.Join(dir, "renamed-secret.txt")
	if err := os.Rename(tmpFile, dest); err != nil {
		t.Fatalf("Rename: %v", err)
	}

	select {
	case f := <-w.Findings():
		if f.PatternName == "" {
			t.Error("expected DLP pattern match for renamed-in file")
		}
		if f.Path != dest {
			t.Errorf("expected path %q, got %q", dest, f.Path)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout — rename-into-place write was not detected")
	}
}

func TestIsIgnored(t *testing.T) {
	tests := []struct {
		name     string
		patterns []string
		path     string
		want     bool
	}{
		{
			name:     "exact match",
			patterns: []string{"*.o"},
			path:     "/tmp/test/main.o",
			want:     true,
		},
		{
			name:     "no match",
			patterns: []string{"*.o"},
			path:     "/tmp/test/main.go",
			want:     false,
		},
		{
			name:     "directory pattern",
			patterns: []string{"node_modules/**"},
			path:     "/tmp/project/node_modules",
			want:     true,
		},
		{
			name:     "git directory",
			patterns: []string{".git/**"},
			path:     "/tmp/project/.git",
			want:     true,
		},
		{
			name:     "so extension",
			patterns: []string{"*.so"},
			path:     "/tmp/lib/libfoo.so",
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &fsWatcher{
				cfg: &config.FileSentry{IgnorePatterns: tt.patterns},
			}
			if got := w.isIgnored(tt.path); got != tt.want {
				t.Errorf("isIgnored(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}
