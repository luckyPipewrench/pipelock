// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/atomicfile"
	"github.com/luckyPipewrench/pipelock/internal/contract"
	"github.com/luckyPipewrench/pipelock/internal/contract/runtime/contractruntimetest"
	contractstore "github.com/luckyPipewrench/pipelock/internal/contract/store"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

func TestNewLoader_RejectsMissingFields(t *testing.T) {
	t.Parallel()
	const validFP = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	validEnv := testLoaderEnv()
	cases := []struct {
		name string
		opts LoaderOptions
		want string
	}{
		{
			name: "missing store_dir",
			opts: LoaderOptions{RosterPath: testRJSONPath, PinnedRootFingerprint: validFP, Environment: validEnv, MinSignatures: 1, Mode: ModeShadow},
			want: "store_dir required",
		},
		{
			name: "missing roster_path",
			opts: LoaderOptions{StoreDir: testSPath, PinnedRootFingerprint: validFP, Environment: validEnv, MinSignatures: 1, Mode: ModeShadow},
			want: "roster_path required",
		},
		{
			name: "missing fingerprint",
			opts: LoaderOptions{StoreDir: testSPath, RosterPath: testRJSONPath, Environment: validEnv, MinSignatures: 1, Mode: ModeShadow},
			want: "pinned_root_fingerprint required",
		},
		{
			name: "missing environment",
			opts: LoaderOptions{StoreDir: testSPath, RosterPath: testRJSONPath, PinnedRootFingerprint: validFP, MinSignatures: 1, Mode: ModeShadow},
			want: "environment required",
		},
		{
			name: "zero min_signatures",
			opts: LoaderOptions{StoreDir: testSPath, RosterPath: testRJSONPath, PinnedRootFingerprint: validFP, Environment: validEnv, MinSignatures: 0, Mode: ModeShadow},
			want: "min_signatures must be >= 1",
		},
		{
			name: "empty mode",
			opts: LoaderOptions{StoreDir: testSPath, RosterPath: testRJSONPath, PinnedRootFingerprint: validFP, Environment: validEnv, MinSignatures: 1},
			want: "mode",
		},
		{
			name: "unknown mode",
			opts: LoaderOptions{StoreDir: testSPath, RosterPath: testRJSONPath, PinnedRootFingerprint: validFP, Environment: validEnv, MinSignatures: 1, Mode: Mode("preview")},
			want: "mode",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewLoader(tc.opts, nil)
			if err == nil {
				t.Fatalf("%s: expected error, got nil", tc.name)
			}
			if !errors.Is(err, ErrInvalidDecisionInput) {
				t.Fatalf("%s: err = %v, want ErrInvalidDecisionInput", tc.name, err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("%s: err = %q, want to contain %q", tc.name, err.Error(), tc.want)
			}
		})
	}
}

func TestNewLoader_RejectsMissingRosterFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, err := NewLoader(LoaderOptions{
		StoreDir:              filepath.Join(dir, "store"),
		RosterPath:            filepath.Join(dir, "does-not-exist.json"),
		PinnedRootFingerprint: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Environment:           testLoaderEnv(),
		MinSignatures:         1,
		Mode:                  ModeShadow,
	}, nil)
	if err == nil {
		t.Fatal("missing roster file: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "load roster") {
		t.Fatalf("err = %v, want load roster wrap", err)
	}
}

func TestNewLoader_NoActiveManifest_ReturnsNilCurrent(t *testing.T) {
	t.Parallel()
	fixture := newRosterFixture(t)
	storeDir := filepath.Join(fixture.Root(), "store")
	if err := os.MkdirAll(storeDir, 0o750); err != nil {
		t.Fatalf("mkdir store: %v", err)
	}

	metrics := &captureMetrics{}
	loader, err := NewLoader(LoaderOptions{
		StoreDir:              storeDir,
		RosterPath:            fixture.RosterPath(),
		PinnedRootFingerprint: fixture.RootFingerprint(),
		Environment:           testLoaderEnv(),
		MinSignatures:         1,
		Mode:                  ModeShadow,
		Now:                   func() time.Time { return time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC) },
	}, metrics)
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}

	if loader.Current() != nil {
		t.Fatalf("Current() = %v, want nil for empty store", loader.Current())
	}
	if loader.Mode() != ModeShadow {
		t.Fatalf("Mode() = %q, want shadow", loader.Mode())
	}
	if metrics.outcomes["no_active"] != 1 {
		t.Fatalf("expected one no_active reload outcome, got %v", metrics.outcomes)
	}
	if metrics.lastGeneration != 0 {
		t.Fatalf("expected generation 0 for empty store, got %d", metrics.lastGeneration)
	}
}

func TestLoader_ReloadAcceptsSameHashWithoutError(t *testing.T) {
	t.Parallel()
	fixture := newRosterFixture(t)
	storeDir := filepath.Join(fixture.Root(), "store")
	writeSignedActiveStore(t, fixture, storeDir, 1, "sha256:genesis", testLoaderEnv())

	metrics := &captureMetrics{}
	loader, err := NewLoader(loaderOptions(fixture, storeDir, testLoaderEnv()), metrics)
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	current := loader.Current()
	if current == nil {
		t.Fatal("Current() = nil, want active set")
	}

	if err := loader.Reload(); err != nil {
		t.Fatalf("Reload same hash: %v", err)
	}
	if loader.Current() != current {
		t.Fatal("same-hash reload should preserve active set pointer")
	}
	if metrics.outcomes["same_hash"] != 1 {
		t.Fatalf("same_hash metrics = %v, want one same_hash", metrics.outcomes)
	}
}

func TestLoader_ReloadRejectsMissingActiveAfterCurrent(t *testing.T) {
	t.Parallel()
	fixture := newRosterFixture(t)
	storeDir := filepath.Join(fixture.Root(), "store")
	writeSignedActiveStore(t, fixture, storeDir, 1, "sha256:genesis", testLoaderEnv())

	metrics := &captureMetrics{}
	loader, err := NewLoader(loaderOptions(fixture, storeDir, testLoaderEnv()), metrics)
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	current := loader.Current()
	if current == nil {
		t.Fatal("Current() = nil, want active set")
	}
	if err := os.Remove(filepath.Join(storeDir, "active.json")); err != nil {
		t.Fatalf("remove active.json: %v", err)
	}

	if err := loader.Reload(); err == nil {
		t.Fatal("Reload after active.json deletion returned nil error")
	}
	if loader.Current() != current {
		t.Fatal("missing active.json after a current manifest must preserve previous active set")
	}
	if metrics.outcomes["rejected"] != 1 {
		t.Fatalf("metrics = %v, want one rejected outcome", metrics.outcomes)
	}
}

func TestLoader_ReloadRejectsEnvironmentMismatchAndKeepsCurrent(t *testing.T) {
	t.Parallel()
	fixture := newRosterFixture(t)
	storeDir := filepath.Join(fixture.Root(), "store")
	env := testLoaderEnv()
	writeSignedActiveStore(t, fixture, storeDir, 1, "sha256:genesis", env)

	metrics := &captureMetrics{}
	loader, err := NewLoader(loaderOptions(fixture, storeDir, env), metrics)
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	current := loader.Current()
	otherEnv := contract.Environment{ID: "staging", Tenant: env.Tenant, DeploymentID: env.DeploymentID}
	writeSignedActiveStore(t, fixture, storeDir, 2, current.ManifestHash(), otherEnv)

	if err := loader.Reload(); err == nil {
		t.Fatal("Reload environment mismatch returned nil error")
	}
	if loader.Current() != current {
		t.Fatal("environment mismatch must preserve previous active set")
	}
	if metrics.outcomes["rejected"] != 1 {
		t.Fatalf("metrics = %v, want one rejected outcome", metrics.outcomes)
	}
}

func TestLoader_ReloadRejectsGenerationDowngradeAndKeepsCurrent(t *testing.T) {
	t.Parallel()
	fixture := newRosterFixture(t)
	storeDir := filepath.Join(fixture.Root(), "store")
	env := testLoaderEnv()
	writeSignedActiveStore(t, fixture, storeDir, 2, "sha256:genesis", env)

	metrics := &captureMetrics{}
	loader, err := NewLoader(loaderOptions(fixture, storeDir, env), metrics)
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	current := loader.Current()
	writeSignedActiveStore(t, fixture, storeDir, 1, "sha256:older", env)

	if err := loader.Reload(); err == nil {
		t.Fatal("Reload generation downgrade returned nil error")
	}
	if loader.Current() != current {
		t.Fatal("generation downgrade must preserve previous active set")
	}
	if metrics.outcomes["rejected"] != 1 {
		t.Fatalf("metrics = %v, want one rejected outcome", metrics.outcomes)
	}
}

func TestLoader_NilReceiverAccessorsAreSafe(t *testing.T) {
	t.Parallel()
	// Defensive guard: a misconfigured caller that passes nil through to
	// Current() or Mode() must not panic. The proxy hot path calls these
	// on every request, and a nil-deref there would blackhole traffic.
	var l *Loader
	if got := l.Current(); got != nil {
		t.Fatalf("nil-loader Current() = %v, want nil", got)
	}
	if got := l.Mode(); got != "" {
		t.Fatalf("nil-loader Mode() = %q, want empty", got)
	}
	if err := l.Reload(); err == nil {
		t.Fatal("nil-loader Reload() returned nil error")
	}
}

func TestLoader_NilMetricsExercisesNoopImpl(t *testing.T) {
	t.Parallel()
	// Constructing a Loader with metrics=nil must wire the noopMetrics
	// implementation so all reload-outcome and generation calls land on
	// real method receivers. Coverage proves no panic and no nil-deref
	// from production code paths that assume metrics is always set.
	fixture := newRosterFixture(t)
	storeDir := filepath.Join(fixture.Root(), "store")
	if err := os.MkdirAll(storeDir, 0o750); err != nil {
		t.Fatalf("mkdir store: %v", err)
	}
	loader, err := NewLoader(loaderOptions(fixture, storeDir, testLoaderEnv()), nil)
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	if loader.Current() != nil {
		t.Fatalf("Current() = %v, want nil for empty store", loader.Current())
	}
	// Reload again to confirm noopMetrics handles a same-no-active path
	// without surfacing an error.
	if err := loader.Reload(); err != nil {
		t.Fatalf("Reload with nil metrics: %v", err)
	}
}

func TestLoader_ReloadAdoptsAcceptedActiveAfterMissedIntermediate(t *testing.T) {
	t.Parallel()
	fixture := newRosterFixture(t)
	storeDir := filepath.Join(fixture.Root(), "store")
	env := testLoaderEnv()
	writeSignedActiveStore(t, fixture, storeDir, 1, "sha256:genesis", env)

	metrics := &captureMetrics{}
	loader, err := NewLoader(loaderOptions(fixture, storeDir, env), metrics)
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	current := loader.Current()
	if current == nil {
		t.Fatal("Current() = nil, want active set")
	}

	// Simulate two valid promotions landing before the runtime watcher gets
	// a debounce tick. Both manifests have already been accepted into the
	// immutable store history by the promotion path, but the runtime loader
	// still has generation 1 in memory.
	hash2 := writeAcceptedActiveStore(t, fixture, storeDir, 2, current.ManifestHash(), current.Generation(), env)
	hash3 := writeAcceptedActiveStore(t, fixture, storeDir, 3, hash2, 2, env)

	if err := loader.Reload(); err != nil {
		t.Fatalf("Reload after skipped intermediate accepted manifest: %v", err)
	}
	set := loader.Current()
	if set == nil || set.Generation() != 3 || set.ManifestHash() != hash3 {
		t.Fatalf("Current() = %+v, want generation 3 hash %s", set, hash3)
	}
	if metrics.outcome("accepted") != 2 {
		t.Fatalf("accepted outcomes = %d, want 2 (initial + recovery)", metrics.outcome("accepted"))
	}
	journalPath := filepath.Clean(filepath.Join(storeDir, ".activation_journal.jsonl"))
	journal, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatalf("read activation journal: %v", err)
	}
	if strings.Contains(string(journal), `"outcome":"rejected"`) {
		t.Fatalf("recovered accepted active should not add a rejected journal entry: %s", journal)
	}
}

func TestLoader_ReloadRejectsSkippedActiveWithoutAcceptedHistory(t *testing.T) {
	t.Parallel()
	fixture := newRosterFixture(t)
	storeDir := filepath.Join(fixture.Root(), "store")
	env := testLoaderEnv()
	writeSignedActiveStore(t, fixture, storeDir, 1, "sha256:genesis", env)

	metrics := &captureMetrics{}
	loader, err := NewLoader(loaderOptions(fixture, storeDir, env), metrics)
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	current := loader.Current()
	if current == nil {
		t.Fatal("Current() = nil, want active set")
	}

	hash2 := writeAcceptedActiveStore(t, fixture, storeDir, 2, current.ManifestHash(), current.Generation(), env)
	writeSignedActiveStore(t, fixture, storeDir, 3, hash2, env)

	if err := loader.Reload(); err == nil {
		t.Fatal("Reload accepted skipped active manifest without immutable accepted history")
	}
	if loader.Current() != current {
		t.Fatal("skipped active without accepted history must preserve previous active set")
	}
	if metrics.outcome("rejected") != 1 {
		t.Fatalf("rejected outcomes = %d, want 1", metrics.outcome("rejected"))
	}
}

func TestLoader_Watch_CancelExitsCleanly(t *testing.T) {
	t.Parallel()
	fixture := newRosterFixture(t)
	storeDir := filepath.Join(fixture.Root(), "store")
	if err := os.MkdirAll(storeDir, 0o750); err != nil {
		t.Fatalf("mkdir store: %v", err)
	}

	loader, err := NewLoader(loaderOptions(fixture, storeDir, testLoaderEnv()), nil)
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- loader.Watch(ctx) }()

	waitForLoaderReady(t, loader)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Watch on cancel: %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Watch did not return after cancel")
	}
}

func TestLoader_Watch_FileReplacementTriggersReload(t *testing.T) {
	t.Parallel()
	fixture := newRosterFixture(t)
	storeDir := filepath.Join(fixture.Root(), "store")
	env := testLoaderEnv()
	writeSignedActiveStore(t, fixture, storeDir, 1, "sha256:genesis", env)

	metrics := &captureMetrics{}
	loader, err := NewLoader(loaderOptions(fixture, storeDir, env), metrics)
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	priorHash := loader.Current().ManifestHash()
	if loader.Current().Generation() != 1 {
		t.Fatalf("initial generation = %d, want 1", loader.Current().Generation())
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- loader.Watch(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	waitForLoaderReady(t, loader)

	// Promote generation 2 with the correct prior-hash chain.
	writeSignedActiveStore(t, fixture, storeDir, 2, priorHash, env)

	if !waitFor(func() bool {
		set := loader.Current()
		return set != nil && set.Generation() == 2
	}) {
		t.Fatalf("generation 2 not loaded; current = %+v, metrics = %v", loader.Current(), snapshotOutcomes(metrics))
	}
}

func TestLoader_Watch_DebounceCoalescesBurstAndSameHashIsNoop(t *testing.T) {
	t.Parallel()
	fixture := newRosterFixture(t)
	storeDir := filepath.Join(fixture.Root(), "store")
	env := testLoaderEnv()
	writeSignedActiveStore(t, fixture, storeDir, 1, "sha256:genesis", env)

	metrics := &captureMetrics{}
	loader, err := NewLoader(loaderOptions(fixture, storeDir, env), metrics)
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	if metrics.outcome("accepted") != 1 {
		t.Fatalf("initial load accepted = %d, want 1", metrics.outcome("accepted"))
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- loader.Watch(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	waitForLoaderReady(t, loader)

	// Fire a burst of WRITEs against the same content. fsnotify will emit
	// multiple events; the 100ms debounce window should coalesce them
	// into a single Reload, which the same-hash short-circuit then turns
	// into one same_hash outcome (no swap, no rejection).
	//
	// atomicfile.Write mirrors the production promote path (temp +
	// rename). os.WriteFile truncates in place and races with Reload's
	// read under -race CI load, surfacing parse-error outcomes that
	// would break the error == 0 assertion below for the wrong reason.
	activePath := filepath.Clean(filepath.Join(storeDir, activeFilename))
	raw, err := os.ReadFile(activePath)
	if err != nil {
		t.Fatalf("read active.json: %v", err)
	}
	for i := 0; i < 5; i++ {
		if err := atomicfile.Write(activePath, raw, 0o600); err != nil {
			t.Fatalf("rewrite active.json: %v", err)
		}
	}

	// Wait for at least one debounce window plus a small Reload margin,
	// then poll until the same_hash counter increments at least once.
	if !waitFor(func() bool {
		return metrics.outcome("same_hash") >= 1
	}) {
		t.Fatalf("same_hash never observed; metrics = %v", snapshotOutcomes(metrics))
	}

	// Drain any trailing event for a hair longer than the debounce window
	// so a coalesced second pass would have already fired.
	quiet := time.NewTimer(reloadDebounceWindow + 100*time.Millisecond)
	ticker := time.NewTicker(10 * time.Millisecond)
	for {
		select {
		case <-quiet.C:
			ticker.Stop()
			goto quietDone
		case <-ticker.C:
			if got := metrics.outcome("same_hash"); got > 2 {
				ticker.Stop()
				if !quiet.Stop() {
					<-quiet.C
				}
				t.Fatalf("same_hash = %d, want <= 2 (5-event burst should coalesce)", got)
			}
		}
	}
quietDone:

	// 5 burst writes should coalesce; tolerate up to 2 same_hash outcomes
	// in case the OS spreads the burst across two debounce windows under
	// load. More than 2 indicates the debounce window is broken.
	if got := metrics.outcome("same_hash"); got > 2 {
		t.Fatalf("same_hash = %d, want <= 2 (5-event burst should coalesce)", got)
	}
	// No rejected or error outcomes should have fired.
	if got := metrics.outcome("rejected"); got != 0 {
		t.Fatalf("rejected = %d, want 0 for same-hash burst", got)
	}
	if got := metrics.outcome("error"); got != 0 {
		t.Fatalf("error = %d, want 0 for same-hash burst", got)
	}
}

func TestLoader_Watch_RejectedReloadKeepsWatcherAlive(t *testing.T) {
	t.Parallel()
	fixture := newRosterFixture(t)
	storeDir := filepath.Join(fixture.Root(), "store")
	env := testLoaderEnv()
	writeSignedActiveStore(t, fixture, storeDir, 2, "sha256:genesis", env)

	metrics := &captureMetrics{}
	loader, err := NewLoader(loaderOptions(fixture, storeDir, env), metrics)
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	current := loader.Current()
	if current == nil {
		t.Fatal("expected initial active set")
	}
	priorHash := current.ManifestHash()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- loader.Watch(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	waitForLoaderReady(t, loader)

	// Generation downgrade: write generation 1 over generation 2.
	writeSignedActiveStore(t, fixture, storeDir, 1, "sha256:older", env)
	if !waitFor(func() bool {
		return metrics.outcome("rejected") >= 1
	}) {
		t.Fatalf("rejected outcome never observed; metrics = %v", snapshotOutcomes(metrics))
	}
	if loader.Current() != current {
		t.Fatal("rejected reload must preserve previous active set")
	}

	// Write a valid generation 3 to prove the watcher still triggers
	// Reload after the prior rejection.
	writeSignedActiveStore(t, fixture, storeDir, 3, priorHash, env)
	if !waitFor(func() bool {
		set := loader.Current()
		return set != nil && set.Generation() == 3
	}) {
		t.Fatalf("recovery to generation 3 never landed; metrics = %v", snapshotOutcomes(metrics))
	}
}

func TestLoader_Watch_NilReceiverReturnsError(t *testing.T) {
	t.Parallel()
	var l *Loader
	err := l.Watch(context.Background())
	if err == nil {
		t.Fatal("Watch on nil loader returned nil")
	}
	if !strings.Contains(err.Error(), "nil loader") {
		t.Fatalf("err = %v, want nil-loader error", err)
	}
}

func TestLoader_Watch_DebounceMaxWaitFlushesUnderSustainedWrites(t *testing.T) {
	t.Parallel()
	fixture := newRosterFixture(t)
	storeDir := filepath.Join(fixture.Root(), "store")
	env := testLoaderEnv()
	writeSignedActiveStore(t, fixture, storeDir, 1, "sha256:genesis", env)

	metrics := &captureMetrics{}
	loader, err := NewLoader(loaderOptions(fixture, storeDir, env), metrics)
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	if metrics.outcome("accepted") != 1 {
		t.Fatalf("initial accepted = %d, want 1", metrics.outcome("accepted"))
	}

	ctx, cancel := context.WithCancel(context.Background())
	stop := make(chan struct{})
	done := make(chan error, 1)
	// producerDone is closed when the file-rewriting goroutine below has
	// returned. Cleanup must wait on it before t.TempDir's RemoveAll runs,
	// otherwise a mid-rename temp file in storeDir can break the cleanup
	// with "directory not empty".
	producerDone := make(chan struct{})
	go func() { done <- loader.Watch(ctx) }()
	t.Cleanup(func() {
		close(stop)
		<-producerDone
		cancel()
		<-done
	})
	waitForLoaderReady(t, loader)

	// Producer that rewrites the same content every 40ms (well below
	// the 100ms debounce window). Without the maxDebounceWait cap, the
	// debounce timer would reset on every write and Reload would never
	// fire. With the cap, Reload fires within roughly maxDebounceWait
	// after the first write.
	//
	// Use atomicfile.Write (temp + rename) so the producer mirrors how
	// real promotes write the active manifest. os.WriteFile truncates
	// in place, which under -race CI load races with Reload's read and
	// produces parse errors instead of same_hash outcomes; the assertion
	// below would then never fire even though the maxDebounceWait code
	// path is working as intended.
	activePath := filepath.Clean(filepath.Join(storeDir, activeFilename))
	raw, err := os.ReadFile(activePath)
	if err != nil {
		t.Fatalf("read active.json: %v", err)
	}
	go func() {
		defer close(producerDone)
		ticker := time.NewTicker(40 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				_ = atomicfile.Write(activePath, raw, 0o600)
			}
		}
	}()

	// Allow up to maxDebounceWait + a generous grace for OS scheduling
	// jitter. The forced flush fires through the same code path as a
	// normal debounce tick, so the resulting outcome is "same_hash"
	// (content unchanged). Grace is intentionally large because
	// GitHub Actions runners under -race load schedule the timer
	// significantly later than the local desktop; 1.5s reproducibly
	// flaked on CI while local runs always saw the flush within
	// 200ms past maxDebounceWait. Five seconds keeps the test
	// well under the package timeout.
	testwait.For(t, maxDebounceWait+5*time.Second, func() bool {
		return metrics.outcome("same_hash") >= 1
	}, "debounce flush under sustained writes; metrics = %v", snapshotOutcomes(metrics))
}

func TestLoader_Watch_RemoveEventTriggersReload(t *testing.T) {
	t.Parallel()
	// fsnotify.Remove on active.json must trigger Reload. Atomic rename
	// can fire IN_DELETE for the displaced inode on some kernels, and
	// an explicit operator unlink fires Remove cleanly. Without Remove
	// in the trigger predicate the loader would sit on stale state.
	fixture := newRosterFixture(t)
	storeDir := filepath.Join(fixture.Root(), "store")
	env := testLoaderEnv()
	writeSignedActiveStore(t, fixture, storeDir, 1, "sha256:genesis", env)

	metrics := &captureMetrics{}
	loader, err := NewLoader(loaderOptions(fixture, storeDir, env), metrics)
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	current := loader.Current()
	if current == nil {
		t.Fatal("expected initial active set")
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- loader.Watch(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	waitForLoaderReady(t, loader)

	// Remove active.json directly. The watcher should see Remove and
	// trigger a Reload through the debounce. Reload then rejects the
	// missing-file-after-current path and preserves the previous set.
	activePath := filepath.Clean(filepath.Join(storeDir, activeFilename))
	if err := os.Remove(activePath); err != nil {
		t.Fatalf("remove active.json: %v", err)
	}

	if !waitFor(func() bool {
		return metrics.outcome("rejected") >= 1
	}) {
		t.Fatalf("rejected outcome never observed after Remove; metrics = %v", snapshotOutcomes(metrics))
	}
	if loader.Current() != current {
		t.Fatal("missing active.json after current must preserve previous active set")
	}
}

func TestLoader_ReloadRejectsRecoveryChainBreak(t *testing.T) {
	t.Parallel()
	// Recovery walks the accepted-history chain back from the current
	// active to the loader's prev. If a generation in that chain is
	// missing from accepted history, the walk fails and the rejection
	// stands. This exercises acceptedChainReachesCurrent's break path.
	fixture := newRosterFixture(t)
	storeDir := filepath.Join(fixture.Root(), "store")
	env := testLoaderEnv()
	writeSignedActiveStore(t, fixture, storeDir, 1, "sha256:genesis", env)

	metrics := &captureMetrics{}
	loader, err := NewLoader(loaderOptions(fixture, storeDir, env), metrics)
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	current := loader.Current()
	if current == nil {
		t.Fatal("expected initial active set")
	}

	// Promote gen 2 properly into accepted history, then write gen 4
	// claiming gen 2 as its prior. Gen 3 is missing from history so
	// the chain walk from gen 4 cannot reach gen 1.
	hash2 := writeAcceptedActiveStore(t, fixture, storeDir, 2, current.ManifestHash(), current.Generation(), env)
	writeSignedActiveStore(t, fixture, storeDir, 4, hash2, env)

	if err := loader.Reload(); err == nil {
		t.Fatal("Reload accepted skipped chain without intermediate accepted history")
	}
	if loader.Current() != current {
		t.Fatal("broken recovery chain must preserve previous active set")
	}
	if metrics.outcome("rejected") != 1 {
		t.Fatalf("rejected outcomes = %d, want 1", metrics.outcome("rejected"))
	}
}

func TestRejectionOutcomeMapsErrorClasses(t *testing.T) {
	t.Parallel()
	// Sentinel errors that map to the "rejected" label vs the "error"
	// label have to stay separated so operators alerting on rejections
	// (signature failure, env mismatch, generation downgrade, prior CAS)
	// do not see flapping I/O drown out a real promote rejection.
	rejected := []error{
		contractstore.ErrStructural,
		contractstore.ErrSignature,
		contractstore.ErrContractSignature,
		contractstore.ErrDualControl,
		contractstore.ErrEnvironmentMismatch,
		contractstore.ErrGeneration,
		contractstore.ErrPriorManifest,
		contractstore.ErrContractHistory,
	}
	for _, err := range rejected {
		err := err
		t.Run("rejected_"+err.Error(), func(t *testing.T) {
			t.Parallel()
			if got := rejectionOutcome(err); got != "rejected" {
				t.Fatalf("rejectionOutcome(%v) = %q, want rejected", err, got)
			}
		})
	}
	errs := []error{
		contractstore.ErrDecode,
		contractstore.ErrWriteOnceConflict,
		errors.New("synthetic transient io"),
	}
	for _, err := range errs {
		err := err
		t.Run("error_"+err.Error(), func(t *testing.T) {
			t.Parallel()
			if got := rejectionOutcome(err); got != "error" {
				t.Fatalf("rejectionOutcome(%v) = %q, want error", err, got)
			}
		})
	}
}

func TestNewLoader_FailsOnMalformedActiveManifest(t *testing.T) {
	t.Parallel()
	// NewLoader is fail-closed: a present-but-invalid active.json must
	// surface an error so the supervisor refuses to start with a broken
	// lock. The store rejects the parse before signature/CAS gates even
	// fire, so this exercises the initial-reload error path that maps to
	// the wrapped initial reload error.
	fixture := newRosterFixture(t)
	storeDir := filepath.Join(fixture.Root(), "store")
	if err := os.MkdirAll(storeDir, 0o750); err != nil {
		t.Fatalf("mkdir store: %v", err)
	}
	if err := os.WriteFile(filepath.Join(storeDir, activeFilename), []byte("{not valid json"), 0o600); err != nil {
		t.Fatalf("write malformed active.json: %v", err)
	}
	if _, err := NewLoader(loaderOptions(fixture, storeDir, testLoaderEnv()), nil); err == nil {
		t.Fatal("NewLoader accepted a malformed active.json")
	} else if !strings.Contains(err.Error(), "initial reload") {
		t.Fatalf("err = %v, want initial-reload wrap", err)
	}
}

func TestNewLoader_RejectsActiveManifestSymlink(t *testing.T) {
	t.Parallel()
	fixture := newRosterFixture(t)
	storeDir := filepath.Join(fixture.Root(), "store")
	env := testLoaderEnv()
	externalDir := t.TempDir()
	writeSignedActiveStore(t, fixture, externalDir, 1, "sha256:genesis", env)
	if err := os.MkdirAll(storeDir, 0o750); err != nil {
		t.Fatalf("mkdir store: %v", err)
	}
	if err := os.Symlink(filepath.Join(externalDir, activeFilename), filepath.Join(storeDir, activeFilename)); err != nil {
		t.Fatalf("symlink active.json: %v", err)
	}

	_, err := NewLoader(loaderOptions(fixture, storeDir, env), nil)
	if err == nil {
		t.Fatal("NewLoader accepted active.json symlink")
	}
	if !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("err = %v, want regular-file rejection", err)
	}
}

func TestLoader_ReloadRejectsActiveManifestSymlinkAndKeepsCurrent(t *testing.T) {
	t.Parallel()
	fixture := newRosterFixture(t)
	storeDir := filepath.Join(fixture.Root(), "store")
	env := testLoaderEnv()
	writeSignedActiveStore(t, fixture, storeDir, 1, "sha256:genesis", env)

	metrics := &captureMetrics{}
	loader, err := NewLoader(loaderOptions(fixture, storeDir, env), metrics)
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	current := loader.Current()
	if current == nil {
		t.Fatal("expected initial active set")
	}

	externalDir := t.TempDir()
	writeSignedActiveStore(t, fixture, externalDir, 2, current.ManifestHash(), env)
	activePath := filepath.Join(storeDir, activeFilename)
	if err := os.Remove(activePath); err != nil {
		t.Fatalf("remove active.json: %v", err)
	}
	if err := os.Symlink(filepath.Join(externalDir, activeFilename), activePath); err != nil {
		t.Fatalf("symlink active.json: %v", err)
	}

	err = loader.Reload()
	if err == nil {
		t.Fatal("Reload accepted active.json symlink")
	}
	if !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("err = %v, want regular-file rejection", err)
	}
	if loader.Current() != current {
		t.Fatal("symlink rejection must preserve previous active set")
	}
	if metrics.outcome("rejected") != 1 {
		t.Fatalf("rejected outcomes = %d, want 1", metrics.outcome("rejected"))
	}
}

func TestLoader_Watch_FailsOnMissingStoreDir(t *testing.T) {
	t.Parallel()
	// Watch wires fsnotify.Add against the store directory at startup. A
	// missing directory at watch-setup time surfaces an error to the
	// caller so the supervisor knows the lock runtime is unhealthy
	// instead of silently looping.
	fixture := newRosterFixture(t)
	storeDir := filepath.Join(fixture.Root(), "store")
	writeSignedActiveStore(t, fixture, storeDir, 1, "sha256:genesis", testLoaderEnv())
	loader, err := NewLoader(loaderOptions(fixture, storeDir, testLoaderEnv()), nil)
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	// Drop the store directory before Watch starts so fsnotify.Add fails.
	if err := os.RemoveAll(storeDir); err != nil {
		t.Fatalf("remove store dir: %v", err)
	}
	err = loader.Watch(context.Background())
	if err == nil {
		t.Fatal("Watch returned nil on missing store directory")
	}
	if !strings.Contains(err.Error(), "watch ") {
		t.Fatalf("err = %v, want watcher.Add wrap", err)
	}
}

func TestRecoverAcceptedActiveRejectsNilPrev(t *testing.T) {
	t.Parallel()
	// Defensive guard: a caller threading nil prev into recovery must
	// not crash. Reload always passes a non-nil prev when invoking
	// recovery, so this test exists to keep the guard wired.
	fixture := newRosterFixture(t)
	storeDir := filepath.Join(fixture.Root(), "store")
	writeSignedActiveStore(t, fixture, storeDir, 1, "sha256:genesis", testLoaderEnv())
	loader, err := NewLoader(loaderOptions(fixture, storeDir, testLoaderEnv()), nil)
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	if _, err := loader.recoverAcceptedActive(contractstore.State{}, nil); err == nil {
		t.Fatal("recoverAcceptedActive accepted nil prev")
	}
}

func TestLoader_Watch_DirectoryDeletionEndsWatcher(t *testing.T) {
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
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- loader.Watch(ctx) }()
	waitForLoaderReady(t, loader)

	// Drop the entire store directory. fsnotify fires a Remove event on
	// the watched directory; Watch surfaces the loss to the caller so
	// the supervisor can decide what to do (re-construct, alert, exit).
	if err := os.RemoveAll(storeDir); err != nil {
		t.Fatalf("remove store dir: %v", err)
	}

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Watch returned nil after directory deletion")
		}
		// Depending on scheduler timing, the deletion can race with
		// watcher.Add. Both paths are fail-closed: either Watch observes the
		// watched directory removal after Add, or Add itself reports
		// os.ErrNotExist because the directory was already gone.
		if !strings.Contains(err.Error(), "store directory removed") && !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("err = %v, want store-directory-removed or os.ErrNotExist", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Watch did not return within 2s after directory deletion")
	}
}

// watchTestTimeout caps how long Watch tests poll for an expected
// outcome before failing. Generous enough to absorb slow CI runners,
// tight enough that a stuck watcher fails fast.
const watchTestTimeout = 2 * time.Second

func waitForLoaderReady(t *testing.T, loader *Loader) {
	t.Helper()
	select {
	case <-loader.ready:
	case <-time.After(watchTestTimeout):
		t.Fatal("loader watcher did not report ready")
	}
}

// waitFor polls cond until it returns true or watchTestTimeout elapses.
// Returns true on success, false on timeout. Used by Watch tests where
// the signal is the watcher goroutine landing a Reload outcome: poll
// the metric to increment rather than guess a fixed sleep.
func waitFor(cond func() bool) bool {
	timer := time.NewTimer(watchTestTimeout)
	defer timer.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if cond() {
			return true
		}
		select {
		case <-timer.C:
			return cond()
		case <-ticker.C:
		}
	}
}

// snapshotOutcomes returns a copy of the current outcome counters for
// inclusion in test failure messages. Acquires m.mu so it is safe to
// call from the test goroutine while the watcher goroutine fires its
// own metric increments.
func snapshotOutcomes(m *captureMetrics) map[string]int {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]int, len(m.outcomes))
	for k, v := range m.outcomes {
		out[k] = v
	}
	return out
}

// rosterFixture aliases the shared contractruntimetest.Fixture so the
// existing test helpers in this file continue to compile. The fixture
// was extracted into a reusable package so the forward-proxy contract
// gate tests can build the same signed-roster shape without copying
// 100+ lines of signing scaffolding.
type rosterFixture = contractruntimetest.Fixture

func newRosterFixture(t *testing.T) rosterFixture {
	t.Helper()
	return contractruntimetest.NewFixture(t)
}

func loaderOptions(fixture rosterFixture, storeDir string, env contract.Environment) LoaderOptions {
	return LoaderOptions{
		StoreDir:              storeDir,
		RosterPath:            fixture.RosterPath(),
		PinnedRootFingerprint: fixture.RootFingerprint(),
		Environment:           env,
		MinSignatures:         1,
		Mode:                  ModeShadow,
		Now:                   func() time.Time { return time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC) },
	}
}

func testLoaderEnv() contract.Environment {
	return contractruntimetest.Env()
}

func writeSignedActiveStore(t *testing.T, fixture rosterFixture, storeDir string, generation uint64, prior string, env contract.Environment) {
	t.Helper()
	contractruntimetest.WriteSignedActiveStore(t, fixture, storeDir, contractruntimetest.ActiveStoreOptions{
		Generation:  generation,
		PriorHash:   prior,
		Environment: env,
	})
}

// writeAcceptedActiveStore funnels the missed-intermediate recovery
// tests through the shared helper so the store-CAS path stays in one
// place. Returns the manifest hash so callers can chain prior hashes.
func writeAcceptedActiveStore(t *testing.T, fixture rosterFixture, storeDir string, generation uint64, prior string, previousGeneration uint64, env contract.Environment) string {
	t.Helper()
	return contractruntimetest.WriteAcceptedActiveStore(t, fixture, storeDir, contractruntimetest.ActiveStoreOptions{
		Generation:         generation,
		PriorHash:          prior,
		PreviousGeneration: previousGeneration,
		Environment:        env,
	})
}

// captureMetrics records LoaderMetrics calls for assertion in tests. The
// mutex matters once Watch tests fire updates from the watcher goroutine
// while the test goroutine reads outcomes for assertions.
type captureMetrics struct {
	mu             sync.Mutex
	outcomes       map[string]int
	lastGeneration uint64
	watcherErrors  int
}

func (m *captureMetrics) IncReload(outcome string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.outcomes == nil {
		m.outcomes = map[string]int{}
	}
	m.outcomes[outcome]++
}

func (m *captureMetrics) SetGeneration(generation uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastGeneration = generation
}

func (m *captureMetrics) IncWatcherError() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.watcherErrors++
}

// outcome returns the count for a specific outcome label. Safe for
// concurrent reads while Watch fires updates.
func (m *captureMetrics) outcome(label string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.outcomes[label]
}
