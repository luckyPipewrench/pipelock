// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/contract"
	contractstore "github.com/luckyPipewrench/pipelock/internal/contract/store"
	"github.com/luckyPipewrench/pipelock/internal/signing"
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
			opts: LoaderOptions{RosterPath: "/tmp/r.json", PinnedRootFingerprint: validFP, Environment: validEnv, MinSignatures: 1, Mode: ModeShadow},
			want: "store_dir required",
		},
		{
			name: "missing roster_path",
			opts: LoaderOptions{StoreDir: "/tmp/s", PinnedRootFingerprint: validFP, Environment: validEnv, MinSignatures: 1, Mode: ModeShadow},
			want: "roster_path required",
		},
		{
			name: "missing fingerprint",
			opts: LoaderOptions{StoreDir: "/tmp/s", RosterPath: "/tmp/r.json", Environment: validEnv, MinSignatures: 1, Mode: ModeShadow},
			want: "pinned_root_fingerprint required",
		},
		{
			name: "missing environment",
			opts: LoaderOptions{StoreDir: "/tmp/s", RosterPath: "/tmp/r.json", PinnedRootFingerprint: validFP, MinSignatures: 1, Mode: ModeShadow},
			want: "environment required",
		},
		{
			name: "zero min_signatures",
			opts: LoaderOptions{StoreDir: "/tmp/s", RosterPath: "/tmp/r.json", PinnedRootFingerprint: validFP, Environment: validEnv, MinSignatures: 0, Mode: ModeShadow},
			want: "min_signatures must be >= 1",
		},
		{
			name: "empty mode",
			opts: LoaderOptions{StoreDir: "/tmp/s", RosterPath: "/tmp/r.json", PinnedRootFingerprint: validFP, Environment: validEnv, MinSignatures: 1},
			want: "mode",
		},
		{
			name: "unknown mode",
			opts: LoaderOptions{StoreDir: "/tmp/s", RosterPath: "/tmp/r.json", PinnedRootFingerprint: validFP, Environment: validEnv, MinSignatures: 1, Mode: Mode("preview")},
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
	storeDir := filepath.Join(fixture.root, "store")
	if err := os.MkdirAll(storeDir, 0o750); err != nil {
		t.Fatalf("mkdir store: %v", err)
	}

	metrics := &captureMetrics{}
	loader, err := NewLoader(LoaderOptions{
		StoreDir:              storeDir,
		RosterPath:            fixture.rosterPath,
		PinnedRootFingerprint: fixture.rootFingerprint,
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
	storeDir := filepath.Join(fixture.root, "store")
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
	storeDir := filepath.Join(fixture.root, "store")
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
	storeDir := filepath.Join(fixture.root, "store")
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
	storeDir := filepath.Join(fixture.root, "store")
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
	storeDir := filepath.Join(fixture.root, "store")
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

func TestLoader_Watch_CancelExitsCleanly(t *testing.T) {
	t.Parallel()
	fixture := newRosterFixture(t)
	storeDir := filepath.Join(fixture.root, "store")
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

	// Give Watch enough time to call fsnotify.NewWatcher + Add.
	time.Sleep(50 * time.Millisecond)
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
	storeDir := filepath.Join(fixture.root, "store")
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
	time.Sleep(80 * time.Millisecond) // let watcher.Add complete

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
	storeDir := filepath.Join(fixture.root, "store")
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
	time.Sleep(80 * time.Millisecond)

	// Fire a burst of WRITEs against the same content. fsnotify will emit
	// multiple events; the 100ms debounce window should coalesce them
	// into a single Reload, which the same-hash short-circuit then turns
	// into one same_hash outcome (no swap, no rejection).
	activePath := filepath.Clean(filepath.Join(storeDir, activeFilename))
	raw, err := os.ReadFile(activePath)
	if err != nil {
		t.Fatalf("read active.json: %v", err)
	}
	for i := 0; i < 5; i++ {
		if err := os.WriteFile(activePath, raw, 0o600); err != nil {
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
	time.Sleep(reloadDebounceWindow + 100*time.Millisecond)

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
	storeDir := filepath.Join(fixture.root, "store")
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
	time.Sleep(80 * time.Millisecond)

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

func TestLoader_Watch_DirectoryDeletionEndsWatcher(t *testing.T) {
	t.Parallel()
	fixture := newRosterFixture(t)
	storeDir := filepath.Join(fixture.root, "store")
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
	time.Sleep(80 * time.Millisecond)

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
		if !strings.Contains(err.Error(), "store directory removed") {
			t.Fatalf("err = %v, want store-directory-removed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Watch did not return within 2s after directory deletion")
	}
}

// watchTestTimeout caps how long Watch tests poll for an expected
// outcome before failing. Generous enough to absorb slow CI runners,
// tight enough that a stuck watcher fails fast.
const watchTestTimeout = 2 * time.Second

// waitFor polls cond until it returns true or watchTestTimeout elapses.
// Returns true on success, false on timeout. Used by Watch tests where
// the signal is the watcher goroutine landing a Reload outcome: poll
// the metric to increment rather than guess a fixed sleep.
func waitFor(cond func() bool) bool {
	deadline := time.Now().Add(watchTestTimeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return cond()
}

// snapshotOutcomes returns a copy of the current outcome counters for
// inclusion in test failure messages without holding the lock.
func snapshotOutcomes(m *captureMetrics) map[string]int {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]int, len(m.outcomes))
	for k, v := range m.outcomes {
		out[k] = v
	}
	return out
}

// rosterFixture is the minimum fixture the Loader needs at construction
// time: a real Ed25519 root key, a real activation-signing key, and a
// roster file on disk that signing.LoadRoster can verify. Tests that
// build a real signed active.json reuse this fixture and add the
// manifest-side scaffolding on top in F3c.
type rosterFixture struct {
	root            string
	rosterPath      string
	rootFingerprint string
	rootPriv        ed25519.PrivateKey
	activationPub   ed25519.PublicKey
	activationPriv  ed25519.PrivateKey
	compilePub      ed25519.PublicKey
	compilePriv     ed25519.PrivateKey
}

func newRosterFixture(t *testing.T) rosterFixture {
	t.Helper()
	root := t.TempDir()
	keystoreDir := filepath.Join(root, "keys")
	ks := signing.NewKeystore(keystoreDir)

	rootPub, err := ks.GenerateAgent("roster-root")
	if err != nil {
		t.Fatalf("generate root: %v", err)
	}
	rootPriv, err := ks.LoadPrivateKey("roster-root")
	if err != nil {
		t.Fatalf("load root priv: %v", err)
	}
	activationPub, err := ks.GenerateAgent("activation-primary")
	if err != nil {
		t.Fatalf("generate activation: %v", err)
	}
	activationPriv, err := ks.LoadPrivateKey("activation-primary")
	if err != nil {
		t.Fatalf("load activation priv: %v", err)
	}
	compilePub, err := ks.GenerateAgent("compile-primary")
	if err != nil {
		t.Fatalf("generate compile: %v", err)
	}
	compilePriv, err := ks.LoadPrivateKey("compile-primary")
	if err != nil {
		t.Fatalf("load compile priv: %v", err)
	}

	rootFingerprint, err := signing.Fingerprint(rootPub)
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}

	body := contract.KeyRoster{
		SchemaVersion:  1,
		RosterSignedBy: "roster-root",
		DataClassRoot:  string(contract.DataClassInternal),
		Keys: []contract.KeyInfo{
			rosterKey("roster-root", signing.PurposeRosterRoot, rootPub, contract.KeyStatusRoot, "root"),
			rosterKey("activation-primary", signing.PurposeContractActivationSigning, activationPub, contract.KeyStatusActive, "operator"),
			rosterKey("compile-primary", signing.PurposeContractCompileSigning, compilePub, contract.KeyStatusActive, "compiler"),
		},
	}
	preimage, err := body.SignablePreimage()
	if err != nil {
		t.Fatalf("roster preimage: %v", err)
	}
	envelope := contract.RosterEnvelope{
		Body:      body,
		Signature: "ed25519:" + hex.EncodeToString(ed25519.Sign(rootPriv, preimage)),
	}
	rosterPath := filepath.Join(root, "roster.json")
	rosterBytes, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("marshal roster: %v", err)
	}
	if err := os.WriteFile(rosterPath, append(rosterBytes, '\n'), 0o600); err != nil {
		t.Fatalf("write roster: %v", err)
	}
	if _, err := signing.LoadRoster(rosterPath, rootFingerprint); err != nil {
		t.Fatalf("verify roster fixture: %v", err)
	}

	return rosterFixture{
		root:            root,
		rosterPath:      rosterPath,
		rootFingerprint: rootFingerprint,
		rootPriv:        rootPriv,
		activationPub:   activationPub,
		activationPriv:  activationPriv,
		compilePub:      compilePub,
		compilePriv:     compilePriv,
	}
}

func loaderOptions(fixture rosterFixture, storeDir string, env contract.Environment) LoaderOptions {
	return LoaderOptions{
		StoreDir:              storeDir,
		RosterPath:            fixture.rosterPath,
		PinnedRootFingerprint: fixture.rootFingerprint,
		Environment:           env,
		MinSignatures:         1,
		Mode:                  ModeShadow,
		Now:                   func() time.Time { return time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC) },
	}
}

func testLoaderEnv() contract.Environment {
	return contract.Environment{ID: "prod", Tenant: "tenant-a", DeploymentID: "deploy-a"}
}

func writeSignedActiveStore(t *testing.T, fixture rosterFixture, storeDir string, generation uint64, prior string, env contract.Environment) {
	t.Helper()
	st := contractstore.New(storeDir)
	contractHash := putSignedLoaderContract(t, st, fixture)
	active := signedLoaderManifest(t, contractHash, generation, prior, env, fixture)
	raw, err := json.Marshal(active)
	if err != nil {
		t.Fatalf("marshal active manifest: %v", err)
	}
	if err := os.MkdirAll(storeDir, 0o750); err != nil {
		t.Fatalf("mkdir store: %v", err)
	}
	if err := os.WriteFile(filepath.Join(storeDir, "active.json"), append(raw, '\n'), 0o600); err != nil {
		t.Fatalf("write active.json: %v", err)
	}
}

func putSignedLoaderContract(t *testing.T, st contractstore.Store, fixture rosterFixture) string {
	t.Helper()
	body := contract.Contract{
		SchemaVersion:    contract.SchemaVersionContract,
		ContractKind:     contract.ContractKind,
		SignerKeyID:      "compile-primary",
		KeyPurpose:       signing.PurposeContractCompileSigning.String(),
		DataClassRoot:    string(contract.DataClassInternal),
		FieldDataClasses: map[string]string{},
		Selector:         contract.Selector{Agent: "agent-a", SelectorID: "sha256:selector"},
	}
	hash, err := contractstore.ContractHash(body)
	if err != nil {
		t.Fatalf("contract hash: %v", err)
	}
	body.ContractHash = hash
	preimage, err := body.SignablePreimage()
	if err != nil {
		t.Fatalf("contract preimage: %v", err)
	}
	env := contract.ContractEnvelope{
		Body:      body,
		Signature: "ed25519:" + hex.EncodeToString(ed25519.Sign(fixture.compilePriv, preimage)),
	}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal contract: %v", err)
	}
	loadedRoster, err := signing.LoadRoster(fixture.rosterPath, fixture.rootFingerprint)
	if err != nil {
		t.Fatalf("load roster: %v", err)
	}
	if got, err := st.PutHistoryContract(raw, contractstore.Options{
		Roster:        loadedRoster,
		MinSignatures: 1,
		Now:           func() time.Time { return time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC) },
	}); err != nil {
		t.Fatalf("PutHistoryContract: %v", err)
	} else if got != hash {
		t.Fatalf("PutHistoryContract hash = %q, want %q", got, hash)
	}
	return hash
}

func signedLoaderManifest(t *testing.T, contractHash string, generation uint64, prior string, env contract.Environment, fixture rosterFixture) contract.ActiveManifestEnvelope {
	t.Helper()
	selector := contract.ManifestSelector{Agent: "agent-a", ContractHash: contractHash}
	selectorID, err := selector.ComputeSelectorID()
	if err != nil {
		t.Fatalf("ComputeSelectorID: %v", err)
	}
	selector.SelectorID = selectorID
	selectorSetHash, err := contract.ComputeSelectorSetHash([]contract.ManifestSelector{selector})
	if err != nil {
		t.Fatalf("ComputeSelectorSetHash: %v", err)
	}
	body := contract.ActiveManifest{
		SchemaVersion:     1,
		ManifestKind:      contract.ManifestKindActivation,
		Generation:        generation,
		PriorManifestHash: prior,
		SelectorSetHash:   selectorSetHash,
		Environment:       env,
		Selectors:         []contract.ManifestSelector{selector},
		HistoryRoot:       "contracts/history/",
		SignedAt:          time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
	}
	preimage, err := body.SignablePreimage()
	if err != nil {
		t.Fatalf("manifest preimage: %v", err)
	}
	return contract.ActiveManifestEnvelope{
		Body: body,
		Signatures: []contract.ManifestSignature{{
			KeyID:      "activation-primary",
			Principal:  "operator",
			KeyPurpose: signing.PurposeContractActivationSigning.String(),
			Algorithm:  "ed25519",
			Signature:  "ed25519:" + hex.EncodeToString(ed25519.Sign(fixture.activationPriv, preimage)),
		}},
	}
}

func rosterKey(keyID string, purpose signing.KeyPurpose, pub ed25519.PublicKey, status, principal string) contract.KeyInfo {
	return contract.KeyInfo{
		KeyID:        keyID,
		KeyPurpose:   purpose.String(),
		PublicKeyHex: hex.EncodeToString(pub),
		ValidFrom:    time.Date(2026, 4, 29, 0, 0, 0, 0, time.UTC).Format(time.RFC3339),
		Status:       status,
		Principal:    principal,
	}
}

// captureMetrics records LoaderMetrics calls for assertion in tests. The
// mutex matters once Watch tests fire updates from the watcher goroutine
// while the test goroutine reads outcomes for assertions.
type captureMetrics struct {
	mu             sync.Mutex
	outcomes       map[string]int
	lastGeneration uint64
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

// outcome returns the count for a specific outcome label. Safe for
// concurrent reads while Watch fires updates.
func (m *captureMetrics) outcome(label string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.outcomes[label]
}
