// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/contract"
	"github.com/luckyPipewrench/pipelock/internal/contract/store"
	"github.com/luckyPipewrench/pipelock/internal/signing"
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
	//   - "accepted"     — new manifest accepted; ActiveSet swapped
	//   - "same_hash"    — reload returned the same manifest hash; no-op
	//   - "no_active"    — store has no active.json; Current() stays nil
	//   - "rejected"     — store rejected the manifest (signature, env,
	//                      generation downgrade, prior_manifest_hash CAS)
	//   - "error"        — I/O or other transient error; previous
	//                      ActiveSet preserved
	IncReload(outcome string)
	// SetGeneration records the currently-active manifest generation.
	// Zero means no active manifest.
	SetGeneration(generation uint64)
}

// noopMetrics is the default LoaderMetrics when the caller passes nil.
type noopMetrics struct{}

func (noopMetrics) IncReload(string)     {}
func (noopMetrics) SetGeneration(uint64) {}

// Loader watches an active manifest file and serves the latest ActiveSet
// to the proxy decision path.
//
// Initial load is fail-closed: if the roster cannot be loaded or the
// store rejects the existing active.json, NewLoader returns an error so
// the caller refuses to start. A store with no active.json is NOT an
// error — that's the legitimate "lock enabled but nothing promoted yet"
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
	current   atomic.Pointer[ActiveSet]
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
	prev := l.current.Load()
	opts := l.storeOpts
	if prev != nil {
		activeState, err := l.validateActiveReadOnly()
		if err == nil && activeState.ManifestHash == prev.ManifestHash() {
			l.metrics.IncReload("same_hash")
			return nil
		}
		opts.PreviousHash = prev.ManifestHash()
		opts.PreviousGeneration = prev.Generation()
	}

	state, err := l.store.Reload(opts)
	if err != nil {
		if errors.Is(err, store.ErrNoActiveManifest) {
			if prev != nil {
				l.metrics.IncReload("rejected")
				return fmt.Errorf("contract runtime: active manifest disappeared after generation %d: %w", prev.Generation(), err)
			}
			// Store has no active.json — legitimate "nothing promoted"
			// state during initial/never-active startup. Current() stays nil.
			l.current.Store(nil)
			l.metrics.IncReload("no_active")
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
		l.metrics.IncReload("same_hash")
		return nil
	}

	next, err := NewActiveSet(state)
	if err != nil {
		l.metrics.IncReload("rejected")
		return fmt.Errorf("contract runtime: build active set: %w", err)
	}
	l.current.Store(next)
	l.metrics.IncReload("accepted")
	l.metrics.SetGeneration(next.Generation())
	return nil
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
		return "rejected"
	case errors.Is(err, store.ErrDecode),
		errors.Is(err, store.ErrWriteOnceConflict):
		return "error"
	default:
		return "error"
	}
}

func (l *Loader) validateActiveReadOnly() (store.State, error) {
	activePath := filepath.Clean(filepath.Join(l.storeDir, "active.json"))
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
