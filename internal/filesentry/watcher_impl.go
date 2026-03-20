// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package filesentry

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

// debounceDelay is the quiet period after the last write event before scanning.
// fsnotify fires Write on each write syscall, not on close. 50ms avoids
// scanning partial writes while keeping detection latency low.
const debounceDelay = 50 * time.Millisecond

// findingsChanSize is the buffer size for the findings channel.
// Large enough to avoid blocking the watcher goroutine under burst writes.
const findingsChanSize = 64

// maxFileSize is the maximum file size to scan. Files larger than this are
// skipped to avoid unbounded memory use from scanning large binaries.
const maxFileSize = 10 * 1024 * 1024 // 10MB

// fsWatcher implements Watcher using fsnotify for cross-platform file watching.
type fsWatcher struct {
	cfg      *config.FileSentry
	scanner  DLPScanner
	lineage  Lineage
	watcher  *fsnotify.Watcher
	findings chan Finding
	onError  func(error) // optional callback for non-fatal errors (e.g. runtime watch failures)
	mu       sync.Mutex
	timers   map[string]*time.Timer // per-path debounce timers
	pidSnap  map[string]bool        // per-path agent attribution snapshot at event time
	closed   bool
}

// NewWatcher creates a file watcher that monitors configured directories for
// writes and scans file content for DLP pattern matches. Lineage may be nil
// (PID attribution will be unavailable). onError is called for non-fatal
// runtime errors (e.g. failing to watch a newly created directory); it may
// be nil.
func NewWatcher(cfg *config.FileSentry, sc DLPScanner, lin Lineage, onError func(error)) (Watcher, error) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("filesentry: create watcher: %w", err)
	}
	return &fsWatcher{
		cfg:      cfg,
		scanner:  sc,
		lineage:  lin,
		watcher:  w,
		findings: make(chan Finding, findingsChanSize),
		timers:   make(map[string]*time.Timer),
		pidSnap:  make(map[string]bool),
		onError:  onError,
	}, nil
}

// logError invokes the error handler if one is registered.
func (w *fsWatcher) logError(err error) {
	if w.onError != nil {
		w.onError(err)
	}
}

// Arm installs watches on all configured directories synchronously.
// Call this before launching the child process to ensure no writes
// are missed during the startup window.
func (w *fsWatcher) Arm() error {
	for _, p := range w.cfg.WatchPaths {
		abs, err := filepath.Abs(p)
		if err != nil {
			return fmt.Errorf("filesentry: resolve path %q: %w", p, err)
		}
		if err := w.addRecursive(abs); err != nil {
			return fmt.Errorf("filesentry: watch %q: %w", abs, err)
		}
	}
	return nil
}

// Start processes filesystem events until ctx is cancelled. Blocks until done.
// Call Arm() first to install watches before starting the child process.
func (w *fsWatcher) Start(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case ev, ok := <-w.watcher.Events:
			if !ok {
				return nil
			}
			w.handleEvent(ctx, ev)
		case err, ok := <-w.watcher.Errors:
			if !ok {
				return nil
			}
			// Backend error from fsnotify (e.g. inotify queue overflow).
			// Fail closed: return the error so the caller can handle it
			// (log, cancel context, restart). Silently continuing would
			// leave the watcher partially broken with no signal to the operator.
			return fmt.Errorf("fsnotify backend error: %w", err)
		}
	}
}

// Findings returns the channel that receives DLP findings.
func (w *fsWatcher) Findings() <-chan Finding {
	return w.findings
}

// Close stops the watcher, drains pending timers, and closes the findings
// channel so consumer goroutines exit their range loops.
func (w *fsWatcher) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	for _, t := range w.timers {
		t.Stop()
	}
	close(w.findings)
	return w.watcher.Close()
}

// addRecursive walks a directory tree and adds an fsnotify watch on every
// subdirectory. Files themselves don't need watches — directory watches
// catch all file events within them.
func (w *fsWatcher) addRecursive(root string) error {
	// Verify root exists and is a directory. WalkDir silently returns nil
	// for nonexistent paths, which would leave us watching nothing.
	// Files are rejected — inotify watches directories, not individual files.
	info, err := os.Stat(root)
	if err != nil {
		return fmt.Errorf("watch root: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("watch root %q is a file, not a directory", root)
	}
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// Fail closed: permission errors on watched subdirectories mean
			// we can't monitor them. Return the error so Arm() fails.
			return fmt.Errorf("inaccessible path %q: %w", path, err)
		}
		if !d.IsDir() {
			return nil
		}
		if w.isIgnored(path) {
			return filepath.SkipDir
		}
		return w.watcher.Add(path)
	})
}

// handleEvent processes a single fsnotify event.
func (w *fsWatcher) handleEvent(ctx context.Context, ev fsnotify.Event) {
	// New directory created — add a recursive watch so we catch writes inside it.
	// Errors here are non-fatal: the initial Arm() call fail-closes on watch
	// failures, but runtime directory creation is best-effort. We log failures
	// so the operator can see the gap.
	if ev.Has(fsnotify.Create) {
		if info, err := os.Stat(ev.Name); err == nil && info.IsDir() {
			if !w.isIgnored(ev.Name) {
				if addErr := w.addRecursive(ev.Name); addErr != nil {
					w.logError(fmt.Errorf("failed to watch new directory %q: %w", ev.Name, addErr))
				}
			}
		}
	}

	// Scan on Write, Create, and Rename events. A secret written to a temp
	// file outside the watch tree and rename(2)d in produces Create/Rename
	// at the destination, not Write. Scanning only Write is a bypass vector.
	isWriteEvent := ev.Has(fsnotify.Write) || ev.Has(fsnotify.Create) || ev.Has(fsnotify.Rename)
	if !isWriteEvent {
		return
	}

	// Skip directories — we only scan file content.
	if info, err := os.Stat(ev.Name); err != nil || info.IsDir() {
		return
	}

	if w.isIgnored(ev.Name) {
		return
	}

	// Snapshot PID attribution at event time, not after the debounce delay.
	// Short-lived writers may close their FD within the 50ms debounce window.
	// Checking /proc at event time catches more writers than checking after
	// the quiet period. The snapshot is consumed by scanFile after debounce.
	if w.lineage != nil {
		w.mu.Lock()
		w.pidSnap[ev.Name] = w.lineage.HasFileOpen(ev.Name)
		w.mu.Unlock()
	}

	// Debounce: reset the timer for this path. The scan fires only after
	// debounceDelay of quiet (no more writes to this path).
	//
	// Timer identity check: capture the timer pointer in the closure.
	// If a second write replaces this timer before the callback fires,
	// the old callback sees its pointer differs from the map entry and
	// does nothing. Without this, the old callback would delete the new
	// timer's map entry, causing the new callback to scan without cleanup.
	w.mu.Lock()
	if existing, ok := w.timers[ev.Name]; ok {
		existing.Stop()
	}
	path := ev.Name
	// Declare timer before AfterFunc so the closure can capture it.
	// The closure uses timer identity to detect stale callbacks.
	var timer *time.Timer
	timer = time.AfterFunc(debounceDelay, func() {
		w.mu.Lock()
		// Only proceed if this timer is still the active one for this path.
		if current, ok := w.timers[path]; !ok || current != timer {
			w.mu.Unlock()
			return
		}
		delete(w.timers, path)
		// Consume the PID snapshot (take the cached value, then clean up).
		isAgent := w.pidSnap[path]
		delete(w.pidSnap, path)
		w.mu.Unlock()
		w.scanFile(ctx, path, isAgent)
	})
	w.timers[path] = timer
	w.mu.Unlock()
}

// scanFile reads a file and runs DLP scanning on its content.
// isAgent is the PID attribution result snapshotted at event time.
func (w *fsWatcher) scanFile(ctx context.Context, path string, isAgent bool) {
	if w.cfg.ScanContent != nil && !*w.cfg.ScanContent {
		return
	}

	// Open once and use the fd for both size check and read. This avoids
	// a TOCTOU window between Stat and ReadFile where a rename/symlink
	// swap could change what we read.
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil || info.IsDir() || info.Size() == 0 {
		return
	}
	if info.Size() > maxFileSize {
		return
	}

	data, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err != nil || len(data) == 0 {
		return
	}

	result := w.scanner.ScanTextForDLP(ctx, string(data))
	if result.Clean {
		return
	}

	for _, m := range result.Matches {
		f := Finding{
			Path:        path,
			PatternName: m.PatternName,
			Severity:    m.Severity,
			Encoded:     m.Encoded,
			IsAgent:     isAgent,
		}
		// Hold the lock across the closed check AND the send. Without this,
		// Close() can close w.findings between the check and the send.
		w.mu.Lock()
		if w.closed {
			w.mu.Unlock()
			return
		}
		select {
		case w.findings <- f:
		default:
			// Channel full — drop finding rather than blocking the watcher.
		}
		w.mu.Unlock()
	}
}

// isIgnored checks if a path matches any configured ignore pattern.
func (w *fsWatcher) isIgnored(path string) bool {
	for _, pattern := range w.cfg.IgnorePatterns {
		if matched, _ := filepath.Match(pattern, filepath.Base(path)); matched {
			return true
		}
		// Also try matching against the relative path for patterns like "node_modules/**".
		// filepath.Match doesn't support **, so check if the base directory name matches
		// the first segment of the pattern.
		if dir := firstSegment(pattern); dir != "" {
			if filepath.Base(path) == dir {
				return true
			}
		}
	}
	return false
}

// firstSegment returns the first path segment of a glob pattern, or "" if
// the pattern has no separators.
func firstSegment(pattern string) string {
	for i, c := range pattern {
		if c == '/' || c == filepath.Separator {
			return pattern[:i]
		}
	}
	return ""
}
