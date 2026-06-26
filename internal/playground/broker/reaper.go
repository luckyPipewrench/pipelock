// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"context"
	"fmt"
	"io"
	"time"
)

const (
	// defaultReaperGrace is the minimum time a provider machine must have
	// existed before the reaper considers it orphaned. It MUST exceed the
	// maximum CreateMachine+WaitReady->lease-registration window: a machine
	// exists at the provider during WaitReady BEFORE the LeaseManager
	// registers it, so a too-short grace would destroy a VM mid-setup.
	//
	// SAFETY INVARIANT: a machine younger than grace is ALWAYS spared, even
	// if it is not in the active lease set. The create path is bounded well
	// under 60s; 5 minutes provides ample headroom.
	defaultReaperGrace = 5 * time.Minute

	// defaultReaperInterval is how often the background reconciliation loop
	// ticks.
	defaultReaperInterval = 2 * time.Minute
)

// ReaperConfig configures the orphan-VM reaper.
type ReaperConfig struct {
	// Provider lists managed machines and destroys orphans.
	Provider MachineProvider
	// ActiveIDs returns provider machine IDs protected from orphan cleanup:
	// active leases plus any warm-pool machines or in-flight warm handoffs.
	ActiveIDs func() map[string]struct{}
	// Now returns the current time. Injectable for tests; nil uses time.Now.
	Now func() time.Time
	// Grace is the minimum machine age before the reaper considers it
	// orphaned. Zero uses defaultReaperGrace.
	Grace time.Duration
	// Interval is how often the background loop ticks. Zero uses
	// defaultReaperInterval.
	Interval time.Duration
	// Log receives one-line audit messages (machine id + outcome). Nil
	// discards. Never receives secrets.
	Log io.Writer
}

// Reaper reconciles actual provider machines against live leases and destroys
// strays. It is safe for concurrent use.
type Reaper struct {
	provider  MachineProvider
	activeIDs func() map[string]struct{}
	now       func() time.Time
	grace     time.Duration
	interval  time.Duration
	log       io.Writer
}

// NewReaper validates cfg and returns a Reaper.
func NewReaper(cfg ReaperConfig) (*Reaper, error) {
	if cfg.Provider == nil {
		return nil, fmt.Errorf("reaper: Provider is required")
	}
	if cfg.ActiveIDs == nil {
		return nil, fmt.Errorf("reaper: ActiveIDs is required")
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	grace := cfg.Grace
	if grace <= 0 {
		grace = defaultReaperGrace
	}
	interval := cfg.Interval
	if interval <= 0 {
		interval = defaultReaperInterval
	}
	log := cfg.Log
	if log == nil {
		log = io.Discard
	}
	return &Reaper{
		provider:  cfg.Provider,
		activeIDs: cfg.ActiveIDs,
		now:       now,
		grace:     grace,
		interval:  interval,
		log:       log,
	}, nil
}

// ReconcileOnce lists managed machines, compares against active leases, and
// destroys orphans that are older than the grace period. A machine with a zero
// CreatedAt (unknown age) is treated as NOT-yet-past-grace and spared
// (fail-safe: do not destroy what we cannot age-check).
//
// Returns the count of machines destroyed. Returns a non-nil error only when
// the list call itself fails; individual destroy errors are logged and
// skipped.
func (r *Reaper) ReconcileOnce(ctx context.Context) (int, error) {
	machines, err := r.provider.ListManagedMachines(ctx)
	if err != nil {
		return 0, fmt.Errorf("reaper: list managed machines: %w", err)
	}
	active := r.activeIDs()
	now := r.now()
	destroyed := 0
	for _, m := range machines {
		if _, ok := active[m.ID]; ok {
			continue // actively leased
		}
		// SAFETY INVARIANT: a machine younger than grace is ALWAYS spared.
		// A zero/unknown CreatedAt is treated as NOT-yet-past-grace.
		if m.CreatedAt.IsZero() || now.Sub(m.CreatedAt) < r.grace {
			continue
		}
		if dErr := r.provider.DestroyMachine(ctx, m.ID); dErr != nil {
			_, _ = fmt.Fprintf(r.log, "reaper: destroy %s: %v\n", m.ID, dErr)
			continue
		}
		_, _ = fmt.Fprintf(r.log, "reaper: destroyed orphan %s (age %s)\n", m.ID, now.Sub(m.CreatedAt).Truncate(time.Second))
		destroyed++
	}
	return destroyed, nil
}

// Run calls ReconcileOnce immediately (startup reconciliation), then ticks
// every interval until ctx is done. It exits promptly on context cancellation.
func (r *Reaper) Run(ctx context.Context) {
	// Startup reconciliation: destroy orphans left by a prior broker instance.
	if _, err := r.ReconcileOnce(ctx); err != nil {
		_, _ = fmt.Fprintf(r.log, "reaper: startup reconcile: %v\n", err)
	}

	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := r.ReconcileOnce(ctx); err != nil {
				_, _ = fmt.Fprintf(r.log, "reaper: reconcile: %v\n", err)
			}
		}
	}
}
