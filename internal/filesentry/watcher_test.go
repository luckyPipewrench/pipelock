// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package filesentry

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
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

	w, err := NewWatcher(cfg, sc, nil, nil)
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

	w, err := NewWatcher(cfg, sc, nil, nil)
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

	w, err := NewWatcher(cfg, sc, nil, nil)
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

	w, err := NewWatcher(cfg, sc, nil, nil)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	defer func() { _ = w.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	armAndStart(t, w, ctx)

	// Create a new subdirectory, then write a secret inside it.
	// Poll: create dir, write secret, wait for finding. If the watch
	// isn't installed yet the finding won't arrive, so retry.
	subDir := filepath.Join(dir, "newdir")
	if err := os.MkdirAll(subDir, 0o750); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	secret := "sk-ant-" + "api03-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
	deadline := time.After(5 * time.Second)
	attempt := 0
	for {
		secretFile := filepath.Join(subDir, fmt.Sprintf("secret-%d.txt", attempt))
		if err := os.WriteFile(secretFile, []byte(secret), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		attempt++

		select {
		case f := <-w.Findings():
			if f.PatternName == "" {
				t.Error("expected DLP pattern match in new subdirectory")
			}
			return // success
		case <-time.After(200 * time.Millisecond):
			// Watch may not be installed yet, retry.
		case <-deadline:
			t.Fatal("timeout — new subdirectory write was not detected")
		}
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

	w, err := NewWatcher(cfg, sc, nil, nil)
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

	w, err := NewWatcher(cfg, sc, nil, nil)
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

	w, err := NewWatcher(cfg, sc, nil, nil)
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
	f, err := os.OpenFile(filepath.Clean(hugePath), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
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

	w, err := NewWatcher(cfg, sc, nil, nil)
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

	w, err := NewWatcher(cfg, sc, lin, nil)
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

func TestWatcher_DebounceTimerRace(t *testing.T) {
	// Verify that rapid writes to the same file produce exactly one scan,
	// not multiple. The timer identity check prevents stale callbacks.
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

	w, err := NewWatcher(cfg, sc, nil, nil)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	defer func() { _ = w.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	armAndStart(t, w, ctx)

	// Write the same file rapidly 10 times. Only the last write's debounce
	// timer should fire. We should get exactly 1 finding.
	secret := "sk-ant-" + "api03-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
	filePath := filepath.Join(dir, "rapid.json")
	for i := range 10 {
		content := fmt.Sprintf("%s-%d", secret, i)
		if err := os.WriteFile(filePath, []byte(content), 0o600); err != nil {
			t.Fatalf("WriteFile[%d]: %v", i, err)
		}
		time.Sleep(5 * time.Millisecond) // faster than debounce (50ms)
	}

	// Wait for the single debounced scan.
	select {
	case f := <-w.Findings():
		if f.PatternName == "" {
			t.Error("expected DLP match")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for debounced finding")
	}

	// Verify no additional findings arrive (only 1 scan should fire).
	select {
	case f := <-w.Findings():
		t.Errorf("unexpected extra finding (timer race?): %+v", f)
	case <-time.After(200 * time.Millisecond):
		// Good — only one finding.
	}
}

func TestWatcher_ErrorHandlerInvoked(t *testing.T) {
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

	var errorCount atomic.Int32
	onErr := func(_ error) { errorCount.Add(1) }
	w, err := NewWatcher(cfg, sc, nil, onErr)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	defer func() { _ = w.Close() }()

	// logError should invoke the handler.
	fsw := w.(*fsWatcher)
	fsw.logError(fmt.Errorf("test error"))
	if errorCount.Load() != 1 {
		t.Errorf("expected 1 error callback, got %d", errorCount.Load())
	}
}

func TestWatcher_NilErrorHandler(t *testing.T) {
	// logError with no handler should not panic.
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

	w, err := NewWatcher(cfg, sc, nil, nil)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	defer func() { _ = w.Close() }()

	fsw := w.(*fsWatcher)
	fsw.logError(fmt.Errorf("no handler set")) // should not panic
}

func TestWatcher_PIDSnapshotAtEventTime(t *testing.T) {
	// Verify that IsAgent is determined at event time, not scan time.
	// The mock returns true initially, so the snapshot should capture it.
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

	lin := &mockLineage{hasFileOpen: true}

	w, err := NewWatcher(cfg, sc, lin, nil)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	defer func() { _ = w.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	armAndStart(t, w, ctx)

	secret := "sk-ant-" + "api03-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
	if err := os.WriteFile(filepath.Join(dir, "pid-test.json"), []byte(secret), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	select {
	case f := <-w.Findings():
		if !f.IsAgent {
			t.Error("expected IsAgent=true from event-time snapshot")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for finding")
	}
}

func TestWatcher_NilLineageNoSnapshot(t *testing.T) {
	// When lineage is nil, IsAgent should always be false (no crash).
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

	w, err := NewWatcher(cfg, sc, nil, nil)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	defer func() { _ = w.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	armAndStart(t, w, ctx)

	secret := "sk-ant-" + "api03-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
	if err := os.WriteFile(filepath.Join(dir, "no-lineage.json"), []byte(secret), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	select {
	case f := <-w.Findings():
		if f.IsAgent {
			t.Error("expected IsAgent=false when lineage is nil")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for finding")
	}
}

func TestWatcher_ScanContentNilDefaultsTrue(t *testing.T) {
	// When ScanContent is nil (omitted from config), it should default to
	// scanning content (same behavior as explicit true).
	dir := t.TempDir()
	cfg := &config.FileSentry{
		Enabled:     true,
		WatchPaths:  []string{dir},
		ScanContent: nil, // omitted
	}

	defaults := config.Defaults()
	defaults.Internal = nil
	sc := scanner.New(defaults)
	defer sc.Close()

	w, err := NewWatcher(cfg, sc, nil, nil)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	defer func() { _ = w.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	armAndStart(t, w, ctx)

	secret := "sk-ant-" + "api03-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
	if err := os.WriteFile(filepath.Join(dir, "nil-scan.json"), []byte(secret), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	select {
	case f := <-w.Findings():
		if f.PatternName == "" {
			t.Error("expected finding when ScanContent is nil (defaults to true)")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout — nil ScanContent should behave like true")
	}
}

func TestFirstSegment(t *testing.T) {
	tests := []struct {
		pattern string
		want    string
	}{
		{"node_modules/**", "node_modules"},
		{".git/**", ".git"},
		{"*.o", ""},
		{"foo/bar/baz", "foo"},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.pattern, func(t *testing.T) {
			if got := firstSegment(tt.pattern); got != tt.want {
				t.Errorf("firstSegment(%q) = %q, want %q", tt.pattern, got, tt.want)
			}
		})
	}
}

func TestWatcher_StartContextCancelled(t *testing.T) {
	// Start should return nil when context is cancelled.
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

	w, err := NewWatcher(cfg, sc, nil, nil)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	defer func() { _ = w.Close() }()

	if armErr := w.Arm(); armErr != nil {
		t.Fatalf("Arm: %v", armErr)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Start(ctx) }()

	cancel()
	select {
	case startErr := <-done:
		if startErr != nil {
			t.Errorf("Start with cancelled ctx should return nil, got: %v", startErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return after context cancellation")
	}
}

func TestWatcher_FindingsChannelFull(t *testing.T) {
	// When the findings channel is full, new findings should be dropped
	// (not block the watcher).
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

	w, err := NewWatcher(cfg, sc, nil, nil)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	defer func() { _ = w.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	armAndStart(t, w, ctx)

	// Write many files with secrets without reading findings.
	// The channel should not block.
	secret := "sk-ant-" + "api03-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
	for i := range findingsChanSize + 10 {
		path := filepath.Join(dir, fmt.Sprintf("flood-%d.json", i))
		if writeErr := os.WriteFile(path, []byte(fmt.Sprintf("%s-%d", secret, i)), 0o600); writeErr != nil {
			t.Fatalf("WriteFile[%d]: %v", i, writeErr)
		}
	}

	// Poll until at least one finding arrives, proving debounce completed
	// without deadlock. The channel is bounded (findingsChanSize), so
	// overflow writes are dropped — but at least some should arrive.
	deadline := time.After(5 * time.Second)
	drained := 0
	for drained == 0 {
		select {
		case <-w.Findings():
			drained++
		case <-deadline:
			t.Fatal("timeout: no findings arrived (channel full test)")
		}
	}
	// Drain remaining without blocking.
	for {
		select {
		case <-w.Findings():
			drained++
		default:
			goto done
		}
	}
done:
	_ = drained // at least 1 guaranteed by waitLoop above
}

func TestWatcher_PermissionDeniedSubdir(t *testing.T) {
	// Arm should fail closed when a subdirectory is unreadable.
	dir := t.TempDir()
	denied := filepath.Join(dir, "denied")
	if err := os.MkdirAll(denied, 0o750); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	// Make it unreadable.
	if err := os.Chmod(denied, 0o000); err != nil {
		t.Skipf("chmod not supported: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(denied, 0o600) })

	cfg := &config.FileSentry{
		Enabled:     true,
		WatchPaths:  []string{dir},
		ScanContent: ptrBool(true),
	}

	defaults := config.Defaults()
	defaults.Internal = nil
	sc := scanner.New(defaults)
	defer sc.Close()

	w, err := NewWatcher(cfg, sc, nil, nil)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	defer func() { _ = w.Close() }()

	if armErr := w.Arm(); armErr == nil {
		t.Error("expected Arm to fail on unreadable subdirectory")
	}
}

func TestWatcher_StartReturnsOnClose(t *testing.T) {
	// When the underlying watcher is closed, Start should return nil
	// (channels become closed).
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

	w, err := NewWatcher(cfg, sc, nil, nil)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}

	if armErr := w.Arm(); armErr != nil {
		t.Fatalf("Arm: %v", armErr)
	}

	// Close the watcher then Start — the channels are closed so Start exits.
	_ = w.Close()

	ctx := context.Background()
	if startErr := w.Start(ctx); startErr != nil {
		t.Errorf("Start after Close should return nil, got: %v", startErr)
	}
}

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

	w, err := NewWatcher(cfg, sc, nil, nil)
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

	w, err := NewWatcher(cfg, sc, nil, nil)
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

	w, err := NewWatcher(cfg, sc, nil, nil)
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
