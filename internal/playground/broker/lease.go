// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/luckyPipewrench/pipelock/internal/playground/livechat"
)

// ErrAtCapacity is returned when the concurrency cap (the number of live
// per-visitor machines) is reached. The broker maps it to a 503 + queue message.
var ErrAtCapacity = errors.New("broker: at machine capacity")

// ErrDuplicateLease is returned when a lease already exists for the session key.
// The broker generates unique keys, so this is a guard against a double-lease
// minting a second machine for one session.
var ErrDuplicateLease = errors.New("broker: lease already exists for session")

// LeaseConfig configures the LeaseManager.
type LeaseConfig struct {
	// Provider leases the actual microVMs.
	Provider MachineProvider
	// Concurrency caps the number of simultaneously live machines. Required: a
	// nil limiter means an unbounded machine pool, which is a cost/abuse hole, so
	// NewLeaseManager rejects it.
	Concurrency *livechat.ConcurrencyLimiter
	// Image is the playground image every leased VM boots.
	Image string
	// Region / MemoryMB / CPUs / InternalPort size and place each VM.
	Region       string
	MemoryMB     int
	CPUs         int
	InternalPort int
	// BaseEnv is the environment common to every VM (PLAYGROUND_* config and the
	// shared secrets). Per-session values are layered on top at Lease time and
	// override BaseEnv. Never logged.
	BaseEnv map[string]string
}

// Lease is one active per-visitor VM held by the broker.
type Lease struct {
	// SessionKey is the broker's identifier for the visitor session this VM
	// serves.
	SessionKey string
	// Machine is the leased VM (its ID for teardown, PrivateIP for routing).
	Machine *Machine
	release func()
}

// LeaseManager owns the lifecycle of per-visitor VMs and the concurrency cap. It
// is safe for concurrent use.
type LeaseManager struct {
	cfg    LeaseConfig
	mu     sync.Mutex
	leases map[string]*Lease
}

// NewLeaseManager validates cfg and returns a LeaseManager. It rejects a missing
// provider, concurrency limiter, or image: each is a fail-open hole if absent.
func NewLeaseManager(cfg LeaseConfig) (*LeaseManager, error) {
	if cfg.Provider == nil {
		return nil, errors.New("broker: LeaseConfig.Provider is required")
	}
	if cfg.Concurrency == nil {
		return nil, errors.New("broker: LeaseConfig.Concurrency is required (an unbounded machine pool is an abuse hole)")
	}
	if cfg.Image == "" {
		return nil, errors.New("broker: LeaseConfig.Image is required")
	}
	return &LeaseManager{cfg: cfg, leases: make(map[string]*Lease)}, nil
}

// Lease provisions one VM for sessionKey. It acquires a concurrency slot, creates
// the machine, waits for it to be ready, and registers the lease. It is
// fail-closed: if creation or readiness fails, the slot is released and any
// created machine is destroyed before returning the error, so a failed lease
// never leaks a machine or a slot. sessionEnv is layered over BaseEnv (overriding
// it) — used for the per-session invite code, model key, and orchestrator key.
func (lm *LeaseManager) Lease(ctx context.Context, sessionKey string, sessionEnv map[string]string) (*Lease, error) {
	if sessionKey == "" {
		return nil, errors.New("broker: empty session key")
	}

	lm.mu.Lock()
	if _, exists := lm.leases[sessionKey]; exists {
		lm.mu.Unlock()
		return nil, ErrDuplicateLease
	}
	lm.mu.Unlock()

	release, ok := lm.cfg.Concurrency.Acquire()
	if !ok {
		return nil, ErrAtCapacity
	}

	spec := MachineSpec{
		Image:        lm.cfg.Image,
		Env:          mergeEnv(lm.cfg.BaseEnv, sessionEnv),
		Region:       lm.cfg.Region,
		MemoryMB:     lm.cfg.MemoryMB,
		CPUs:         lm.cfg.CPUs,
		InternalPort: lm.cfg.InternalPort,
	}

	m, err := lm.cfg.Provider.CreateMachine(ctx, spec)
	if err != nil {
		release()
		return nil, fmt.Errorf("broker: create machine: %w", err)
	}

	if werr := lm.cfg.Provider.WaitReady(ctx, m.ID); werr != nil {
		// Fail-closed: the machine never became usable. Tear it down (best
		// effort) and free the slot rather than returning a half-started VM.
		_ = lm.cfg.Provider.DestroyMachine(context.WithoutCancel(ctx), m.ID)
		release()
		return nil, fmt.Errorf("broker: machine %s not ready: %w", m.ID, werr)
	}

	lease := &Lease{SessionKey: sessionKey, Machine: m, release: release}

	lm.mu.Lock()
	if _, exists := lm.leases[sessionKey]; exists {
		// Lost a race to another Lease(sessionKey): destroy ours, free the slot.
		lm.mu.Unlock()
		_ = lm.cfg.Provider.DestroyMachine(context.WithoutCancel(ctx), m.ID)
		release()
		return nil, ErrDuplicateLease
	}
	lm.leases[sessionKey] = lease
	lm.mu.Unlock()
	return lease, nil
}

// Release destroys the VM for sessionKey and frees its concurrency slot. It is
// idempotent: an unknown or already-released session key is a no-op. Teardown
// never wedges because DestroyMachine is idempotent and the slot is always freed.
func (lm *LeaseManager) Release(ctx context.Context, sessionKey string) {
	lm.mu.Lock()
	lease, ok := lm.leases[sessionKey]
	if ok {
		delete(lm.leases, sessionKey)
	}
	lm.mu.Unlock()
	if !ok {
		return
	}
	_ = lm.cfg.Provider.DestroyMachine(ctx, lease.Machine.ID)
	lease.release()
}

// LeaseFor returns the active lease for sessionKey, if any. The broker uses it to
// route a visitor's request to their VM.
func (lm *LeaseManager) LeaseFor(sessionKey string) (*Lease, bool) {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	lease, ok := lm.leases[sessionKey]
	return lease, ok
}

// ActiveLeases reports the number of live leased machines.
func (lm *LeaseManager) ActiveLeases() int {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	return len(lm.leases)
}

// mergeEnv returns base overlaid with over (over wins). Neither input is
// mutated. A nil result is fine for the provider (no env).
func mergeEnv(base, over map[string]string) map[string]string {
	if len(base) == 0 && len(over) == 0 {
		return nil
	}
	out := make(map[string]string, len(base)+len(over))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range over {
		out[k] = v
	}
	return out
}
