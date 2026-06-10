// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// Reloader watches a config file for changes and emits new validated
// configs on a channel. It supports fsnotify file watching and
// signal-based reload (SIGHUP on Unix).
type Reloader struct {
	path      string
	onChange  chan *Config
	done      chan struct{}
	ready     chan struct{}
	readyOnce sync.Once
	closeOnce sync.Once
	startMu   sync.Mutex
	started   bool
}

// NewReloader creates a config reloader that watches path for changes.
// Start must be called to begin watching.
func NewReloader(path string) *Reloader {
	return &Reloader{
		path:     path,
		onChange: make(chan *Config, 1),
		done:     make(chan struct{}),
		ready:    make(chan struct{}),
	}
}

// Changes returns a channel that receives new configs on successful reload.
func (r *Reloader) Changes() <-chan *Config {
	return r.onChange
}

// Ready returns a channel closed once the file watch is established (or once
// Start has exited without establishing it, so a waiter never deadlocks on a
// watcher-setup failure). Callers that mutate the config after observing the
// process as live should wait on this first: otherwise an edit made in the
// window before the watch is active is silently missed until the next write.
func (r *Reloader) Ready() <-chan struct{} {
	return r.ready
}

// Start watches the config file and listens for reload signals (SIGHUP on Unix). It blocks until
// ctx is cancelled or Close is called. When Start returns, the onChange
// channel is closed. Reload failures are logged to stderr via tryReload;
// the old config remains active.
func (r *Reloader) Start(ctx context.Context) error {
	r.startMu.Lock()
	if r.started {
		r.startMu.Unlock()
		return fmt.Errorf("config reloader already started")
	}
	r.started = true
	r.startMu.Unlock()

	defer close(r.onChange)
	// Guarantee Ready() resolves on every exit path. The success path closes it
	// below once watcher.Add succeeds; this backstop closes it if Start returns
	// first (e.g. watcher creation/Add failure) so a Ready() waiter cannot
	// deadlock when the watch never came up. Idempotent via readyOnce.
	defer r.readyOnce.Do(func() { close(r.ready) })

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("creating file watcher: %w", err)
	}
	defer func() { _ = watcher.Close() }()

	// Watch the directory (not the file) so we catch editors that
	// write-to-temp-then-rename (vim, sed -i, etc.).
	dir := filepath.Dir(r.path)
	if err := watcher.Add(dir); err != nil {
		return fmt.Errorf("watching directory %s: %w", dir, err)
	}

	sigCh := make(chan os.Signal, 1)
	notifyReloadSignal(sigCh) // SIGHUP on Unix, no-op on Windows
	defer signal.Stop(sigCh)
	// Readiness signaling is idempotent. Start itself is one-shot because it
	// closes Changes() on return and rejects later calls before touching
	// watcher/channel state.
	r.readyOnce.Do(func() { close(r.ready) })

	baseName := filepath.Base(r.path)

	// Debounce: editors may fire multiple events in quick succession.
	var debounce <-chan time.Time

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-r.done:
			return nil
		case event, ok := <-watcher.Events:
			if !ok {
				return nil
			}
			// Only react to writes/creates/renames of our config file.
			if filepath.Base(event.Name) != baseName {
				continue
			}
			if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) || event.Has(fsnotify.Rename) {
				debounce = time.After(100 * time.Millisecond)
			}
		case <-debounce:
			r.tryReload()
			debounce = nil
		case <-sigCh:
			r.tryReload()
		case _, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			// Watcher errors are non-fatal; keep watching.
		}
	}
}

// tryReload attempts to load and validate the config, sending it to the
// onChange channel on success. On failure it logs to stderr and keeps the
// old config.
func (r *Reloader) tryReload() {
	cfg, err := Load(r.path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pipelock: config reload failed: %v\n", err)
		return
	}

	// Coalesce-to-latest: the buffer holds one pending config. If the consumer
	// has not drained the previous reload, replace it with this fresher one
	// rather than dropping the new config. Dropping the NEW config would strand
	// the proxy on a STALE pending config - e.g. write a weak config, then
	// quickly write a stronger one before the slow reload (scanner rebuild)
	// drains: the strong config would be lost and the weak one applied. Always
	// keeping the latest Load() result avoids that security-relevant inversion.
	//
	// Safe because Start() is the sole sender (debounce + SIGHUP share one
	// select loop), so there is no competing producer between the drain and the
	// re-send. The drain itself is non-blocking: if the consumer drained in the
	// meantime, the buffer is empty and we just enqueue.
	for {
		select {
		case r.onChange <- cfg:
			return
		default:
			// Buffer full: discard the stale pending config and retry. The
			// discarded value is older than cfg by construction.
			select {
			case <-r.onChange:
			default:
			}
		}
	}
}

// Close stops the reloader. Safe to call multiple times.
func (r *Reloader) Close() {
	r.closeOnce.Do(func() {
		close(r.done)
	})
}
