// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type errCollector struct {
	mu   sync.Mutex
	errs []error
}

func TestLoader_StartWatch_RestartWaitsForCatchUp(t *testing.T) {
	fixture := newRosterFixture(t)
	storeDir := filepath.Join(fixture.Root(), "store")
	env := testLoaderEnv()
	writeSignedActiveStore(t, fixture, storeDir, 1, "sha256:genesis", env)
	loader, err := NewLoader(loaderOptions(fixture, storeDir, env), nil)
	if err != nil {
		t.Fatal(err)
	}
	stop, err := loader.StartWatch(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	stop()
	loader.reloadMu.Lock()
	returned := make(chan struct{})
	var restartStop func()
	var restartErr error
	go func() {
		restartStop, restartErr = loader.StartWatch(context.Background(), nil)
		close(returned)
	}()
	var premature bool
	select {
	case <-returned:
		premature = true
	case <-time.After(100 * time.Millisecond):
	}
	loader.reloadMu.Unlock()
	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("restart did not finish after catch-up was released")
	}
	if restartStop != nil {
		restartStop()
	}
	if restartErr != nil {
		t.Fatal(restartErr)
	}
	if premature {
		t.Fatal("restarted watch reported ready before its catch-up reload completed")
	}
}

func (c *errCollector) add(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.errs = append(c.errs, err)
}

func (c *errCollector) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.errs)
}

func TestLoader_StartWatch_PromotionAppliesWithoutRestart(t *testing.T) {
	t.Parallel()
	fixture := newRosterFixture(t)
	storeDir := filepath.Join(fixture.Root(), "store")
	env := testLoaderEnv()
	writeSignedActiveStore(t, fixture, storeDir, 1, "sha256:genesis", env)
	loader, err := NewLoader(loaderOptions(fixture, storeDir, env), nil)
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	prior := loader.Current().ManifestHash()

	stop, err := loader.StartWatch(context.Background(), nil)
	if err != nil {
		t.Fatalf("StartWatch: %v", err)
	}
	t.Cleanup(stop)

	writeSignedActiveStore(t, fixture, storeDir, 2, prior, env)
	if !waitFor(func() bool { s := loader.Current(); return s != nil && s.Generation() == 2 }) {
		t.Fatalf("generation 2 not applied live; current = %+v", loader.Current())
	}
}

func TestLoader_StartWatch_PromoteBeforeArmingIsNotMissed(t *testing.T) {
	t.Parallel()
	fixture := newRosterFixture(t)
	storeDir := filepath.Join(fixture.Root(), "store")
	env := testLoaderEnv()
	writeSignedActiveStore(t, fixture, storeDir, 1, "sha256:genesis", env)
	loader, err := NewLoader(loaderOptions(fixture, storeDir, env), nil)
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	// Promote after the loader's construction read but before any watcher
	// exists: no fsnotify event will ever describe this change.
	writeSignedActiveStore(t, fixture, storeDir, 2, loader.Current().ManifestHash(), env)

	stop, err := loader.StartWatch(context.Background(), nil)
	if err != nil {
		t.Fatalf("StartWatch: %v", err)
	}
	t.Cleanup(stop)
	if !waitFor(func() bool { s := loader.Current(); return s != nil && s.Generation() == 2 }) {
		t.Fatalf("promote during the arming gap was missed; current = %+v", loader.Current())
	}
}

func TestLoader_StartWatch_CorruptPromoteKeepsLastGoodAndReports(t *testing.T) {
	t.Parallel()
	fixture := newRosterFixture(t)
	storeDir := filepath.Join(fixture.Root(), "store")
	env := testLoaderEnv()
	writeSignedActiveStore(t, fixture, storeDir, 1, "sha256:genesis", env)
	loader, err := NewLoader(loaderOptions(fixture, storeDir, env), nil)
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	good := loader.Current()

	var errs errCollector
	stop, err := loader.StartWatch(context.Background(), errs.add)
	if err != nil {
		t.Fatalf("StartWatch: %v", err)
	}
	t.Cleanup(stop)

	for name, content := range map[string]string{
		"garbage": "{not json",
		"empty":   "",
	} {
		before := errs.count()
		if err := os.WriteFile(filepath.Join(storeDir, "active.json"), []byte(content), 0o600); err != nil {
			t.Fatalf("%s: write: %v", name, err)
		}
		if !waitFor(func() bool { return errs.count() > before }) {
			t.Fatalf("%s: rejected reload was not reported", name)
		}
		if loader.Current() != good {
			t.Fatalf("%s: corrupt promote replaced the last accepted contract", name)
		}
	}
	if loader.Current() == nil {
		t.Fatal("enforcement dropped to no-contract after corrupt manifest")
	}
}

func TestLoader_StartWatch_StopIsIdempotentAndHaltsWatcher(t *testing.T) {
	t.Parallel()
	fixture := newRosterFixture(t)
	storeDir := filepath.Join(fixture.Root(), "store")
	env := testLoaderEnv()
	writeSignedActiveStore(t, fixture, storeDir, 1, "sha256:genesis", env)
	loader, err := NewLoader(loaderOptions(fixture, storeDir, env), nil)
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	stop, err := loader.StartWatch(context.Background(), nil)
	if err != nil {
		t.Fatalf("StartWatch: %v", err)
	}
	prior := loader.Current().ManifestHash()
	stop()
	stop() // second call must not block or panic

	// A stopped loader still serves its last accepted set and Reload keeps
	// working by hand.
	if loader.Current() == nil {
		t.Fatal("stop dropped the active set")
	}

	// The watcher is gone: a promote is not picked up on its own...
	writeSignedActiveStore(t, fixture, storeDir, 2, prior, env)
	if waitFor(func() bool { return loader.Current().Generation() == 2 }) {
		t.Fatal("a promote applied after stop, so the watcher is still running")
	}
	// ...but an explicit Reload still applies it.
	if err := loader.Reload(); err != nil {
		t.Fatalf("Reload after stop: %v", err)
	}
	if got := loader.Current().Generation(); got != 2 {
		t.Fatalf("generation after manual Reload = %d, want 2", got)
	}
}

func TestLoader_StartWatch_ContextCancelStopsWatcher(t *testing.T) {
	t.Parallel()
	fixture := newRosterFixture(t)
	storeDir := filepath.Join(fixture.Root(), "store")
	env := testLoaderEnv()
	writeSignedActiveStore(t, fixture, storeDir, 1, "sha256:genesis", env)
	loader, err := NewLoader(loaderOptions(fixture, storeDir, env), nil)
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	stop, err := loader.StartWatch(ctx, nil)
	if err != nil {
		t.Fatalf("StartWatch: %v", err)
	}
	cancel()
	stop() // waits for the goroutine to exit; must return after ctx cancel
}

func TestLoader_StartWatch_UnwatchableStoreReturnsError(t *testing.T) {
	t.Parallel()
	fixture := newRosterFixture(t)
	storeDir := filepath.Join(fixture.Root(), "missing-store")
	loader, err := NewLoader(loaderOptions(fixture, storeDir, testLoaderEnv()), nil)
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	if err := os.RemoveAll(storeDir); err != nil {
		t.Fatalf("remove store: %v", err)
	}
	stop, err := loader.StartWatch(context.Background(), nil)
	if err == nil {
		t.Fatal("StartWatch on a missing store directory returned nil error")
	}
	if stop == nil {
		t.Fatal("stop must be non-nil even on error")
	}
	stop()
}

func TestLoader_StartWatch_NilLoader(t *testing.T) {
	t.Parallel()
	var l *Loader
	if _, err := l.StartWatch(context.Background(), nil); err == nil {
		t.Fatal("nil loader StartWatch returned nil error")
	}
}

func TestLoader_StartWatch_StoreRemovalIsReportedAndKeepsContract(t *testing.T) {
	t.Parallel()
	fixture := newRosterFixture(t)
	storeDir := filepath.Join(fixture.Root(), "store")
	env := testLoaderEnv()
	writeSignedActiveStore(t, fixture, storeDir, 1, "sha256:genesis", env)
	loader, err := NewLoader(loaderOptions(fixture, storeDir, env), nil)
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	good := loader.Current()
	var errs errCollector
	stop, err := loader.StartWatch(context.Background(), errs.add)
	if err != nil {
		t.Fatalf("StartWatch: %v", err)
	}
	t.Cleanup(stop)
	if err := os.RemoveAll(storeDir); err != nil {
		t.Fatalf("remove store: %v", err)
	}
	if !waitFor(func() bool { return errs.count() > 0 }) {
		t.Fatal("watcher loss was not reported")
	}
	if loader.Current() != good {
		t.Fatal("watcher loss dropped the last accepted contract")
	}
}

// A caller that gives up before the watch finishes its catch-up must get an
// error, never a stop function for a watcher that is not running.
func TestLoader_StartWatch_CancelBeforeArmedReturnsError(t *testing.T) {
	fixture := newRosterFixture(t)
	storeDir := filepath.Join(fixture.Root(), "store")
	env := testLoaderEnv()
	writeSignedActiveStore(t, fixture, storeDir, 1, "sha256:genesis", env)
	loader, err := NewLoader(loaderOptions(fixture, storeDir, env), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	loader.reloadMu.Lock()
	returned := make(chan error, 1)
	go func() {
		_, startErr := loader.StartWatch(ctx, nil)
		returned <- startErr
	}()
	cancel()
	loader.reloadMu.Unlock()
	select {
	case startErr := <-returned:
		if startErr == nil {
			t.Fatal("StartWatch reported success after its context was cancelled before the watch armed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("StartWatch did not return after cancellation")
	}
}
