// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/filesentry"
)

// fileSentryCloseBackstop converts a deadlocked stop path into a fast, clear
// failure instead of letting it ride out the whole-package deadline. Close
// ends Start in microseconds on a healthy run; this ceiling is generous so
// heavy -race load never trips it.
const fileSentryCloseBackstop = 10 * time.Second

func TestPreferFileSentryRuntimeError(t *testing.T) {
	startupErr := errors.New("bind failed")
	fileSentryErr := errors.New("watch backend failed")

	tests := []struct {
		name     string
		startErr error
		wantErr  error
	}{
		{name: "nil early return", wantErr: fileSentryErr},
		{name: "direct cancellation", startErr: context.Canceled, wantErr: fileSentryErr},
		{name: "wrapped cancellation", startErr: fmt.Errorf("listener startup: %w", context.Canceled), wantErr: fileSentryErr},
		{name: "unrelated startup failure", startErr: startupErr, wantErr: startupErr},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := preferFileSentryRuntimeError(tt.startErr, fileSentryErr)
			if !errors.Is(got, tt.wantErr) {
				t.Fatalf("preferFileSentryRuntimeError() = %v, want %v", got, tt.wantErr)
			}
		})
	}
}

// TestFileSentryWatcherCloseUnblocksStartWithLiveContext pins the one
// production assumption the gated fake below encodes but cannot validate: that
// Close alone ends Start, and ends it CLEANLY.
//
// Both stop paths depend on it against a live, never-cancelled context.
// `pipelock mcp proxy` calls stop after the wrapped child exits on its own, and
// `pipelock run` calls stop after the proxy returns from Server.Shutdown. In
// neither case has anything cancelled the watcher context, so the fsnotify
// backend closing its Events/Errors channels is the only thing that returns
// Start.
//
// Both failure directions are load-bearing and both are silent in a fake:
// a Start that does not return deadlocks every clean shutdown, and a Start that
// returns non-nil makes every clean run record a file-sentry runtime failure and
// exit nonzero, which is the availability direction that gets a security control
// switched off. The fake decides its own answer here by construction, so this
// case is driven against the real watcher.
func TestFileSentryWatcherCloseUnblocksStartWithLiveContext(t *testing.T) {
	scanContent := false
	cfg := &config.FileSentry{
		Enabled:     true,
		WatchPaths:  []config.WatchPath{{Path: t.TempDir()}},
		ScanContent: &scanContent,
	}
	watcher, err := filesentry.NewWatcher(cfg, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	if armErr := watcher.Arm(); armErr != nil {
		t.Fatalf("Arm: %v", armErr)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- watcher.Start(ctx) }()

	if closeErr := watcher.Close(); closeErr != nil {
		t.Fatalf("Close: %v", closeErr)
	}

	select {
	case startErr := <-done:
		if startErr != nil {
			t.Fatalf("Start after Close on a live context = %v, want nil; a non-nil return here reports a file sentry runtime failure on every clean shutdown", startErr)
		}
	case <-time.After(fileSentryCloseBackstop):
		t.Fatalf("Start did not return within %s of Close on a live context; the stop path deadlocks on every clean shutdown", fileSentryCloseBackstop)
	}
}

// gatedFileSentryWatcher lets runtime tests release a backend failure only
// after the production path has started the watcher. It avoids timing-based
// tests while still exercising the asynchronous lifecycle boundary.
type gatedFileSentryWatcher struct {
	err     error
	started chan struct{}
	release chan struct{}
	stopped chan struct{}

	findings  chan filesentry.Finding
	overflow  chan filesentry.Finding
	closeOnce sync.Once
}

func newGatedFileSentryWatcher(err error) *gatedFileSentryWatcher {
	return &gatedFileSentryWatcher{
		err:      err,
		started:  make(chan struct{}),
		release:  make(chan struct{}),
		stopped:  make(chan struct{}),
		findings: make(chan filesentry.Finding),
		overflow: make(chan filesentry.Finding),
	}
}

func (w *gatedFileSentryWatcher) Arm() error { return nil }

func (w *gatedFileSentryWatcher) Start(ctx context.Context) error {
	close(w.started)
	select {
	case <-w.release:
		return w.err
	case <-w.stopped:
		return nil
	case <-ctx.Done():
		return nil
	}
}

func (w *gatedFileSentryWatcher) Findings() <-chan filesentry.Finding { return w.findings }

func (w *gatedFileSentryWatcher) OverflowFindings() <-chan filesentry.Finding { return w.overflow }

func (w *gatedFileSentryWatcher) DegradedPaths() []filesentry.DegradedPath { return nil }

func (w *gatedFileSentryWatcher) DegradedPathCount() int { return 0 }

func (w *gatedFileSentryWatcher) Close() error {
	w.closeOnce.Do(func() {
		close(w.stopped)
		close(w.findings)
		close(w.overflow)
	})
	return nil
}

func installGatedFileSentryWatcher(t *testing.T, watcher *gatedFileSentryWatcher) {
	t.Helper()
	old := newFileSentryWatcher
	newFileSentryWatcher = func(*config.FileSentry, filesentry.DLPScanner, filesentry.Lineage, func(error)) (filesentry.Watcher, error) {
		return watcher, nil
	}
	t.Cleanup(func() { newFileSentryWatcher = old })
}
