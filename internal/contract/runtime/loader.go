// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/luckyPipewrench/pipelock/internal/contract"
	"github.com/luckyPipewrench/pipelock/internal/contract/store"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// activeFilename is the active-manifest filename inside StoreDir. It mirrors
// the unexported constant in internal/contract/store; redeclared here so the
// watcher can filter directory events without importing private store state.
const activeFilename = "active.json"

// reloadDebounceWindow coalesces an fsnotify burst (CREATE + RENAME + WRITE
// emitted on a single atomic active.json swap) into one Reload. Matches the
// existing config hot-reload window so operator expectations stay consistent.
const reloadDebounceWindow = 100 * time.Millisecond

// maxDebounceWait caps how long the debounce timer can be reset by a
// continuous burst of events before Reload fires anyway. Without a cap,
// a producer (operator script, runaway CI) writing active.json faster
// than reloadDebounceWindow indefinitely starves the debounce timer:
// every event resets the 100ms wait, and Reload never runs. Two seconds
// is well above any legitimate atomic-promote burst (which completes in
// milliseconds) and short enough that a runaway producer cannot delay a
// real promote indefinitely.
const maxDebounceWait = 2 * time.Second

// Reload outcome labels passed to LoaderMetrics.IncReload. Operators
// alert on these strings so the values are part of the public surface
// even though the metric interface is internal.
const (
	outcomeAccepted = "accepted"
	outcomeSameHash = "same_hash"
	outcomeNoActive = "no_active"
	outcomeRejected = "rejected"
	outcomeError    = "error"
)

// LoaderOptions configures a Loader. Every field is required when the
// caller intends the lock runtime to gate decisions; partial inputs are
// rejected at NewLoader time so a half-wired loader never silently
// degrades to scanner-only.
type LoaderOptions struct {
	// StoreDir is the absolute path to the contract store rooted at
	// active.json + history/.
	StoreDir string
	// RosterPath is the absolute path to the deployment-level roster JSON.
	RosterPath string
	// PinnedRootFingerprint is the hex-encoded sha256 of the trust roster
	// root key: "sha256:" followed by 64 lowercase hex characters. Roster
	// mismatch fails-closed at construction.
	PinnedRootFingerprint string
	// Environment binds the loader to a specific deployment environment.
	// Active manifests whose env field does not match are rejected by
	// the store on Reload. A zero environment is rejected so callers cannot
	// accidentally disable the store's environment pin.
	Environment contract.Environment
	// MinSignatures is the minimum number of valid manifest signatures
	// required to accept an active.json. Must be >= 1.
	MinSignatures int
	// Mode is the enforcement mode applied by EvaluateHTTP/EvaluateMCP
	// for callers that pass Loader.Mode() as their EvaluateOptions.Mode.
	Mode Mode
	// Now is an optional clock injection point used by store validation
	// (manifest envelope expiry, journal timestamps). Defaults to
	// time.Now when nil.
	Now func() time.Time
}

// LoaderMetrics is the minimal Prometheus-friendly counter surface a
// caller can register against the loader. It is an interface so tests
// can stub it without dragging the prometheus package into this file
// and so production callers can wire whatever registry they keep.
type LoaderMetrics interface {
	// IncReload records the outcome of a single Reload attempt. Outcomes:
	//   - "accepted"     : new manifest accepted; ActiveSet swapped
	//   - "same_hash"    : reload returned the same manifest hash; no-op
	//   - "no_active"    : store has no active.json; Current() stays nil
	//   - "rejected"     : store rejected the manifest (signature, env,
	//                      generation downgrade, prior_manifest_hash CAS)
	//   - "error"        : I/O or other transient error; previous
	//                      ActiveSet preserved
	IncReload(outcome string)
	// SetGeneration records the currently-active manifest generation.
	// Zero means no active manifest.
	SetGeneration(generation uint64)
	// IncWatcherError records a non-fatal error from the fsnotify
	// channel. The most operationally significant case is an inotify
	// queue overflow, which silently drops events. Watch responds to
	// every watcher error by triggering a defensive Reload on the next
	// debounce tick so a missed promote event still lands eventually,
	// but the counter exists so operators can alert on the underlying
	// kernel pressure.
	IncWatcherError()
}

// noopMetrics is the default LoaderMetrics when the caller passes nil.
type noopMetrics struct{}

func (noopMetrics) IncReload(string)     {}
func (noopMetrics) SetGeneration(uint64) {}
func (noopMetrics) IncWatcherError()     {}

// Loader watches an active manifest file and serves the latest ActiveSet
// to the proxy decision path.
//
// Initial load is fail-closed: if the roster cannot be loaded or the
// store rejects the existing active.json, NewLoader returns an error so
// the caller refuses to start. A store with no active.json is NOT an
// error - that's the legitimate "lock enabled but nothing promoted yet"
// state and Current() returns nil for it; the proxy path treats nil as
// "no contract resolved" and falls through to scanner-only.
//
// After construction, subsequent Reload calls (driven by an fsnotify
// watcher in F3c) are fail-soft: a rejected reload keeps the previous
// ActiveSet so a botched promote does not blackhole production traffic.
// Operators see the rejection in the store's journal and via metrics.
//
// Loader is safe for concurrent use. Current() reads through
// atomic.Pointer so the proxy hot path never blocks on Reload.
type Loader struct {
	store     store.Store
	storeDir  string
	storeOpts store.Options
	reloadMu  sync.Mutex
	current   atomic.Pointer[ActiveSet]
	ready     chan struct{}
	readyOnce sync.Once
	mode      Mode
	metrics   LoaderMetrics
	now       func() time.Time
}

// NewLoader builds a Loader and runs an initial Reload. The metrics
// argument is optional; nil means no metrics.
func NewLoader(opts LoaderOptions, metrics LoaderMetrics) (*Loader, error) {
	if opts.StoreDir == "" {
		return nil, fmt.Errorf("%w: store_dir required", ErrInvalidDecisionInput)
	}
	if opts.RosterPath == "" {
		return nil, fmt.Errorf("%w: roster_path required", ErrInvalidDecisionInput)
	}
	if opts.PinnedRootFingerprint == "" {
		return nil, fmt.Errorf("%w: pinned_root_fingerprint required", ErrInvalidDecisionInput)
	}
	if opts.Environment == (contract.Environment{}) {
		return nil, fmt.Errorf("%w: environment required", ErrInvalidDecisionInput)
	}
	if opts.MinSignatures < 1 {
		return nil, fmt.Errorf("%w: min_signatures must be >= 1, got %d", ErrInvalidDecisionInput, opts.MinSignatures)
	}
	if !validMode(opts.Mode) {
		return nil, fmt.Errorf("%w: mode %q", ErrInvalidDecisionInput, opts.Mode)
	}
	if metrics == nil {
		metrics = noopMetrics{}
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}

	roster, err := signing.LoadRoster(opts.RosterPath, opts.PinnedRootFingerprint)
	if err != nil {
		return nil, fmt.Errorf("contract runtime: load roster: %w", err)
	}

	l := &Loader{
		store:    store.New(opts.StoreDir),
		storeDir: filepath.Clean(opts.StoreDir),
		ready:    make(chan struct{}),
		mode:     opts.Mode,
		metrics:  metrics,
		now:      now,
		storeOpts: store.Options{
			Environment:   opts.Environment,
			Roster:        roster,
			MinSignatures: opts.MinSignatures,
			Now:           now,
		},
	}
	if err := l.Reload(); err != nil {
		return nil, fmt.Errorf("contract runtime: initial reload: %w", err)
	}
	return l, nil
}

// Current returns the latest ActiveSet, or nil if no manifest is active.
// Safe for concurrent use; readers see a consistent snapshot.
func (l *Loader) Current() *ActiveSet {
	if l == nil {
		return nil
	}
	return l.current.Load()
}

// Mode returns the loader's enforcement mode.
func (l *Loader) Mode() Mode {
	if l == nil {
		return ""
	}
	return l.mode
}

// Reload re-reads active.json and swaps the in-memory ActiveSet if the
// manifest has changed. Same-hash reloads are no-ops. Rejected reloads
// keep the previous ActiveSet and increment metrics.
//
// The store enforces generation monotonicity and prior-manifest-hash CAS
// internally; this method threads PreviousHash and PreviousGeneration
// through so a rollback attempt is rejected with ErrGeneration / ErrPriorManifest.
func (l *Loader) Reload() error {
	if l == nil {
		return errors.New("contract runtime: nil loader")
	}
	l.reloadMu.Lock()
	defer l.reloadMu.Unlock()

	prev := l.current.Load()
	opts := l.storeOpts
	var activeState store.State
	if err := l.validateActivePath(); err != nil {
		l.metrics.IncReload(rejectionOutcome(err))
		return fmt.Errorf("contract runtime: active manifest path: %w", err)
	}
	if prev != nil {
		var err error
		activeState, err = l.validateActiveReadOnly()
		if err == nil && activeState.ManifestHash == prev.ManifestHash() {
			l.metrics.IncReload(outcomeSameHash)
			return nil
		}
		if err == nil && activeState.Envelope.Body.PriorManifestHash != prev.ManifestHash() {
			if recovered, recoverErr := l.recoverAcceptedActive(activeState, prev); recoverErr == nil {
				return l.acceptState(recovered)
			}
		}
		opts.PreviousHash = prev.ManifestHash()
		opts.PreviousGeneration = prev.Generation()
	}

	state, err := l.store.Reload(opts)
	if err != nil {
		if prev != nil && errors.Is(err, store.ErrPriorManifest) {
			if latestActive, activeErr := l.validateActiveReadOnly(); activeErr == nil {
				if recovered, recoverErr := l.recoverAcceptedActive(latestActive, prev); recoverErr == nil {
					return l.acceptState(recovered)
				}
			}
			if recovered, recoverErr := l.recoverAcceptedActive(activeState, prev); recoverErr == nil {
				return l.acceptState(recovered)
			}
		}
		if errors.Is(err, store.ErrNoActiveManifest) {
			if prev != nil {
				l.metrics.IncReload(outcomeRejected)
				return fmt.Errorf("contract runtime: active manifest disappeared after generation %d: %w", prev.Generation(), err)
			}
			// Store has no active.json - legitimate "nothing promoted"
			// state during initial/never-active startup. Current() stays nil.
			l.current.Store(nil)
			l.metrics.IncReload(outcomeNoActive)
			l.metrics.SetGeneration(0)
			return nil
		}
		l.metrics.IncReload(rejectionOutcome(err))
		return fmt.Errorf("contract runtime: store reload: %w", err)
	}

	// Same-hash short circuit for first accepted reload after an empty
	// loader. Once prev is non-nil, store.Reload rejects an unchanged
	// generation before returning state because generation monotonicity is
	// part of the active-manifest CAS contract.
	if prev != nil && state.ManifestHash == prev.ManifestHash() {
		l.metrics.IncReload(outcomeSameHash)
		return nil
	}

	return l.acceptState(state)
}

func (l *Loader) acceptState(state store.State) error {
	next, err := NewActiveSet(state)
	if err != nil {
		l.metrics.IncReload(outcomeRejected)
		return fmt.Errorf("contract runtime: build active set: %w", err)
	}
	l.current.Store(next)
	l.metrics.IncReload(outcomeAccepted)
	l.metrics.SetGeneration(next.Generation())
	return nil
}

func (l *Loader) recoverAcceptedActive(activeState store.State, prev *ActiveSet) (store.State, error) {
	if prev == nil {
		return store.State{}, errors.New("contract runtime: no previous active set")
	}
	if activeState.Envelope.Body.Generation <= prev.Generation() {
		return store.State{}, fmt.Errorf("contract runtime: accepted active generation %d does not advance current generation %d",
			activeState.Envelope.Body.Generation, prev.Generation())
	}

	opts := l.storeOpts
	opts.PreviousHash = ""
	opts.PreviousGeneration = 0
	accepted, err := l.store.Accepted(activeState.ManifestHash, opts)
	if err != nil {
		return store.State{}, fmt.Errorf("contract runtime: active manifest is not accepted history: %w", err)
	}
	if accepted.ManifestHash != activeState.ManifestHash {
		return store.State{}, fmt.Errorf("contract runtime: accepted active hash mismatch: got %s want %s", accepted.ManifestHash, activeState.ManifestHash)
	}
	if !l.acceptedChainReachesCurrent(accepted, prev, opts) {
		return store.State{}, fmt.Errorf("contract runtime: accepted active chain does not reach current manifest %s", prev.ManifestHash())
	}
	return accepted, nil
}

func (l *Loader) acceptedChainReachesCurrent(state store.State, prev *ActiveSet, opts store.Options) bool {
	for {
		if state.ManifestHash == prev.ManifestHash() {
			return true
		}
		if state.Envelope.Body.Generation <= prev.Generation() {
			return false
		}
		prior := state.Envelope.Body.PriorManifestHash
		if prior == "" || prior == "sha256:genesis" {
			return false
		}
		next, err := l.store.AcceptedHistory(prior, opts)
		if err != nil {
			return false
		}
		state = next
	}
}

// Watch runs an fsnotify watcher on the store directory until ctx is
// cancelled. CREATE, RENAME, and WRITE events on active.json trigger a
// debounced Reload (single window matches the config hot-reload window
// so an atomic active.json swap that fires multiple events coalesces to
// one Reload call).
//
// Watch is fail-soft for reload errors: a rejected reload (bad signature,
// generation downgrade, env mismatch, prior-manifest CAS) leaves the
// previous ActiveSet in place and the watcher keeps running so the next
// promote attempt succeeds.
//
// Watch returns nil on graceful ctx cancel. It returns a non-nil error
// only when the watched directory is removed (the loader cannot recover
// from that without re-construction) or when fsnotify itself fails to
// initialize.
//
// Caller is responsible for goroutine lifecycle. Watch blocks until
// return; spawn it in a goroutine if the caller wants background
// behaviour.
func (l *Loader) Watch(ctx context.Context) error {
	if l == nil {
		return errors.New("contract runtime: nil loader")
	}
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("contract runtime: create file watcher: %w", err)
	}
	defer func() { _ = watcher.Close() }()

	if err := watcher.Add(l.storeDir); err != nil {
		return fmt.Errorf("contract runtime: watch %s: %w", l.storeDir, err)
	}
	l.readyOnce.Do(func() { close(l.ready) })

	// debounce is reset on every relevant event. When it fires, a single
	// Reload runs and debounce resets to nil so a quiescent loop does not
	// keep selecting on a closed channel. burstStart is the timestamp of
	// the first event in a still-active burst; once time.Since(burstStart)
	// exceeds maxDebounceWait, the next event triggers an immediate
	// Reload instead of resetting the timer, capping the worst-case
	// reload latency at roughly maxDebounceWait under sustained writes.
	var (
		debounce   <-chan time.Time
		burstStart time.Time
	)

	for {
		select {
		case <-ctx.Done():
			return nil

		case event, ok := <-watcher.Events:
			if !ok {
				return nil
			}
			// Watched directory removed out from under us. fsnotify keeps
			// the inotify slot allocated even after the inode is gone, but
			// the loader has no path forward without operator intervention
			// so we surface this to the caller.
			if event.Name == l.storeDir && (event.Has(fsnotify.Remove) || event.Has(fsnotify.Rename)) {
				return fmt.Errorf("contract runtime: store directory removed: %s", l.storeDir)
			}
			// Filter to active.json events. The store atomically replaces
			// active.json on every accepted promote, which fires CREATE +
			// RENAME on the new path and (sometimes) REMOVE on the old.
			// Treat all three as a reload trigger; debounce coalesces the
			// burst.
			if filepath.Base(event.Name) != activeFilename {
				continue
			}
			isReloadTrigger := event.Has(fsnotify.Write) ||
				event.Has(fsnotify.Create) ||
				event.Has(fsnotify.Rename) ||
				event.Has(fsnotify.Remove)
			if !isReloadTrigger {
				continue
			}
			now := time.Now()
			if debounce == nil {
				burstStart = now
			} else if now.Sub(burstStart) >= maxDebounceWait {
				// Sustained burst exceeded the cap. Force a Reload now
				// instead of resetting the debounce window again, so a
				// runaway producer cannot starve a real promote.
				debounce = nil
				_ = l.Reload()
				burstStart = time.Time{}
				continue
			}
			debounce = time.After(reloadDebounceWindow)

		case <-debounce:
			debounce = nil
			burstStart = time.Time{}
			// Reload's own metrics record outcome (accepted, same_hash,
			// rejected, error). Error return is informational; a rejected
			// reload is fail-soft and the watcher keeps running so the
			// next event is another opportunity.
			_ = l.Reload()

		case _, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			// fsnotify surfaces non-fatal errors here. The most
			// operationally significant case is an inotify kernel queue
			// overflow (ErrEventOverflow): events that were in the queue
			// at overflow time are dropped. If the dropped event was a
			// real promote, the watcher would silently miss it without
			// a defensive trigger. Schedule a Reload on the next
			// debounce tick so the same-hash short-circuit absorbs the
			// no-change case and a real change still lands. The metrics
			// counter lets operators alert on the underlying kernel
			// pressure separately from the reload outcome.
			l.metrics.IncWatcherError()
			now := time.Now()
			if debounce == nil {
				burstStart = now
			} else if now.Sub(burstStart) >= maxDebounceWait {
				// Sustained watcher-error pressure (e.g., repeated
				// inotify queue overflow) was resetting the debounce
				// window without ever firing the defensive Reload.
				// Force the flush when the burst exceeds the cap, so
				// the recovery path lands under exactly the conditions
				// it was added for.
				debounce = nil
				_ = l.Reload()
				burstStart = time.Time{}
				continue
			}
			debounce = time.After(reloadDebounceWindow)
		}
	}
}

// rejectionOutcome maps a store reload error to a metrics-friendly
// outcome label. Validation errors collapse to "rejected"; transient
// I/O collapses to "error" so an operator can distinguish a botched
// promote from a flaky disk.
func rejectionOutcome(err error) string {
	switch {
	case errors.Is(err, store.ErrStructural),
		errors.Is(err, store.ErrSignature),
		errors.Is(err, store.ErrContractSignature),
		errors.Is(err, store.ErrDualControl),
		errors.Is(err, store.ErrEnvironmentMismatch),
		errors.Is(err, store.ErrGeneration),
		errors.Is(err, store.ErrPriorManifest),
		errors.Is(err, store.ErrContractHistory):
		return outcomeRejected
	case errors.Is(err, store.ErrDecode),
		errors.Is(err, store.ErrWriteOnceConflict):
		return outcomeError
	default:
		return outcomeError
	}
}

// validateActivePath rejects active manifest paths whose Lstat is anything
// other than a regular file or absent. Symlinks, FIFOs, and device nodes
// are refused so a hostile object planted at <storeDir>/active.json cannot
// redirect the loader's read to attacker-controlled bytes.
//
// Threat-model assumption: the store directory is owner-only (0o700) on
// the filesystem layer. A check-then-read race exists between this Lstat
// and the subsequent manifest read; an attacker who can replace the regular
// file with a symlink in that window could still redirect the read. Mitigation
// lives in the operator runbook (chmod 0o700 the store dir owned by the
// pipelock UID); a future O_NOFOLLOW + fstat path here closes the race
// entirely. Tracked as a v2.4.1 hardening item.
func (l *Loader) validateActivePath() error {
	activePath := filepath.Clean(filepath.Join(l.storeDir, activeFilename))
	info, err := os.Lstat(activePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("%w: stat active manifest: %w", store.ErrDecode, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%w: active manifest %s must be a regular file (mode=%s)", store.ErrStructural, activePath, info.Mode())
	}
	return nil
}

func (l *Loader) validateActiveReadOnly() (store.State, error) {
	if err := l.validateActivePath(); err != nil {
		return store.State{}, err
	}
	activePath := filepath.Clean(filepath.Join(l.storeDir, activeFilename))
	raw, err := os.ReadFile(activePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return store.State{}, fmt.Errorf("%w: %w", store.ErrNoActiveManifest, err)
		}
		return store.State{}, fmt.Errorf("%w: read active manifest: %w", store.ErrDecode, err)
	}
	opts := l.storeOpts
	opts.PreviousHash = ""
	opts.PreviousGeneration = 0
	opts.ReadOnly = true
	return l.store.ValidateEnvelope(raw, opts)
}
