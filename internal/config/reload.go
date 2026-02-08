package config

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
)

// Reloader watches a config file for changes and emits new validated
// configs on a channel. It supports both fsnotify file watching and
// SIGHUP signal-based reload.
type Reloader struct {
	path      string
	onChange  chan *Config
	done      chan struct{}
	closeOnce sync.Once
}

// NewReloader creates a config reloader that watches path for changes.
// Start must be called to begin watching.
func NewReloader(path string) *Reloader {
	return &Reloader{
		path:     path,
		onChange: make(chan *Config, 1),
		done:     make(chan struct{}),
	}
}

// Changes returns a channel that receives new configs on successful reload.
func (r *Reloader) Changes() <-chan *Config {
	return r.onChange
}

// Start watches the config file and listens for SIGHUP. It blocks until
// ctx is cancelled or Close is called. When Start returns, the onChange
// channel is closed. Reload failures are logged to stderr via tryReload;
// the old config remains active.
func (r *Reloader) Start(ctx context.Context) error {
	defer close(r.onChange)

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
	signal.Notify(sigCh, syscall.SIGHUP)
	defer signal.Stop(sigCh)

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

	// Non-blocking send: if the consumer hasn't drained the last reload,
	// drop this one (it will be superseded by the next change anyway).
	select {
	case r.onChange <- cfg:
	default:
	}
}

// Close stops the reloader. Safe to call multiple times.
func (r *Reloader) Close() {
	r.closeOnce.Do(func() {
		close(r.done)
	})
}
