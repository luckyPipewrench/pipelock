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
	mu       sync.Mutex
	timers   map[string]*time.Timer // per-path debounce timers
	closed   bool
}

// NewWatcher creates a file watcher that monitors configured directories for
// writes and scans file content for DLP pattern matches. Lineage may be nil
// (PID attribution will be unavailable).
func NewWatcher(cfg *config.FileSentry, sc DLPScanner, lin Lineage) (Watcher, error) {
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
	}, nil
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
			// Log but don't stop — partial watching is better than none.
			_ = err
		}
	}
}

// Findings returns the channel that receives DLP findings.
func (w *fsWatcher) Findings() <-chan Finding {
	return w.findings
}

// Close stops the watcher and drains pending timers.
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
	if ev.Has(fsnotify.Create) {
		if info, err := os.Stat(ev.Name); err == nil && info.IsDir() {
			if !w.isIgnored(ev.Name) {
				_ = w.addRecursive(ev.Name)
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

	// Debounce: reset the timer for this path. The scan fires only after
	// debounceDelay of quiet (no more writes to this path).
	w.mu.Lock()
	if t, ok := w.timers[ev.Name]; ok {
		t.Stop()
	}
	w.timers[ev.Name] = time.AfterFunc(debounceDelay, func() {
		w.scanFile(ctx, ev.Name)
		w.mu.Lock()
		delete(w.timers, ev.Name)
		w.mu.Unlock()
	})
	w.mu.Unlock()
}

// scanFile reads a file and runs DLP scanning on its content.
func (w *fsWatcher) scanFile(ctx context.Context, path string) {
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
		}
		// Attempt PID attribution if lineage is available.
		if w.lineage != nil {
			if w.lineage.HasFileOpen(path) {
				f.IsAgent = true
			}
		}
		select {
		case w.findings <- f:
		default:
			// Channel full — drop finding rather than blocking the watcher.
		}
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
