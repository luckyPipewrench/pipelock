// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"
)

const (
	// defaultMaxWarmAge is how long a warm VM may sit unused before it is
	// recycled. This MUST be less than the VM session TTL so a handed-out VM
	// is always fresh.
	defaultMaxWarmAge = 10 * time.Minute

	// defaultPoolSize is the number of pre-created VMs the pool tries to keep
	// warm when no explicit --warm-pool-size is given.
	defaultPoolSize = 1

	// poolMaintainInterval is how often the background maintainer ticks.
	poolMaintainInterval = 2 * time.Second

	// poolDestroyTimeout bounds cleanup calls made with a non-cancelled context.
	// Destroy failure keeps the VM tracked and its limiter slot held.
	poolDestroyTimeout = 30 * time.Second
)

// warmEntry is one ready-to-hand-out VM in the warm pool.
type warmEntry struct {
	machine *Machine
	vmCode  string
	release func() // concurrency-slot release (transferred on handout)
	created time.Time
}

// PoolConfig configures the warm VM pool.
type PoolConfig struct {
	// Provider creates and destroys VMs. Required.
	Provider MachineProvider
	// Concurrency is the shared limiter that caps warm + active machines.
	// Required. The Pool acquires a slot when pre-creating a warm VM and
	// transfers ownership of that slot when the VM is handed out. The same
	// limiter MUST be shared with the LeaseManager so warm + active never
	// exceeds the operator cap.
	//
	// INVARIANT 1: warm + active slots never exceed Cap().
	Concurrency ConcurrencyAcquirer
	// NewVMCode generates a unique invite code for each warm VM. Required.
	NewVMCode func() (string, error)
	// BuildSpec returns the MachineSpec for a warm VM given its vmCode env.
	// Required.
	BuildSpec func(vmCode string) MachineSpec
	// Size is the target number of warm VMs to maintain. Zero or negative
	// uses defaultPoolSize.
	Size int
	// MaxWarmAge is the maximum age of a warm VM before it is recycled.
	// Zero uses defaultMaxWarmAge.
	//
	// INVARIANT 5: stale warm VMs older than MaxWarmAge are destroyed and
	// replaced.
	MaxWarmAge time.Duration
	// Now returns the current time. Injectable for tests; nil uses time.Now.
	Now func() time.Time
	// Log receives one-line audit messages. Nil discards.
	Log io.Writer
}

// ConcurrencyAcquirer is the interface the pool needs from the shared
// concurrency limiter.
type ConcurrencyAcquirer interface {
	Acquire() (release func(), ok bool)
}

// Pool maintains a small set of pre-created, ready VMs so a visitor
// session-create can skip the cold-start cost. It is safe for concurrent use.
type Pool struct {
	provider   MachineProvider
	conc       ConcurrencyAcquirer
	newVMCode  func() (string, error)
	buildSpec  func(vmCode string) MachineSpec
	size       int
	maxWarmAge time.Duration
	now        func() time.Time
	log        io.Writer

	mu      sync.Mutex
	entries []warmEntry
	// quarantine holds VMs whose destroy call failed. They remain protected
	// from the reaper and keep their limiter slot, but Acquire must never hand
	// them to a visitor after cleanup already tried to remove them.
	quarantine map[string]warmEntry
	// handoff holds machine IDs popped by Acquire but not yet adopted into an
	// active lease. They are NO LONGER in entries but NOT YET in
	// LeaseManager.ActiveMachineIDs, so without tracking them here the reaper
	// could see them as unowned and destroy them mid-handoff (TOCTOU). They stay
	// in the reaper's protected set (via WarmMachineIDs) until FinishHandoff.
	handoff map[string]struct{}
	closed  bool
	// paused stops the maintainer from creating warm VMs (kill switch). Unlike
	// closed (permanent, shutdown), paused is reversible via Resume.
	paused bool
}

// NewPool validates cfg and returns a Pool. Call Run() to start the background
// maintainer.
func NewPool(cfg PoolConfig) (*Pool, error) {
	if cfg.Provider == nil {
		return nil, fmt.Errorf("pool: Provider is required")
	}
	if cfg.Concurrency == nil {
		return nil, fmt.Errorf("pool: Concurrency is required")
	}
	if cfg.NewVMCode == nil {
		return nil, fmt.Errorf("pool: NewVMCode is required")
	}
	if cfg.BuildSpec == nil {
		return nil, fmt.Errorf("pool: BuildSpec is required")
	}
	size := cfg.Size
	if size <= 0 {
		size = defaultPoolSize
	}
	maxWarmAge := cfg.MaxWarmAge
	if maxWarmAge <= 0 {
		maxWarmAge = defaultMaxWarmAge
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	log := cfg.Log
	if log == nil {
		log = io.Discard
	}
	return &Pool{
		provider:   cfg.Provider,
		conc:       cfg.Concurrency,
		newVMCode:  cfg.NewVMCode,
		buildSpec:  cfg.BuildSpec,
		size:       size,
		maxWarmAge: maxWarmAge,
		now:        now,
		log:        log,
		quarantine: make(map[string]warmEntry),
		handoff:    make(map[string]struct{}),
	}, nil
}

// Acquire pops a ready warm VM from the pool. ok=false when the pool is empty;
// the caller MUST fall back to the synchronous create path.
//
// INVARIANT 3: a visitor NEVER fails because the pool is empty.
//
// On success the concurrency slot is transferred to the caller (the slot was
// acquired when the warm VM was pre-created). The caller owns release().
func (p *Pool) Acquire() (machine *Machine, vmCode string, release func(), ok bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.entries) == 0 {
		return nil, "", nil, false
	}
	// Pop the oldest entry (FIFO: freshest are appended at the back).
	e := p.entries[0]
	p.entries[0] = warmEntry{} // clear reference
	p.entries = p.entries[1:]
	// Mark the machine as in-flight handoff: it has left entries but is not yet
	// an active lease. Keep it in the reaper's protected set until FinishHandoff
	// (called by the caller once AdoptWarm succeeds OR the VM is destroyed on
	// failure). Closes the reaper TOCTOU window.
	if e.machine != nil {
		p.handoff[e.machine.ID] = struct{}{}
	}
	return e.machine, e.vmCode, e.release, true
}

// FinishHandoff clears an in-flight handoff marker for machineID. The caller
// invokes it after Acquire once the machine is either adopted into an active
// lease (now protected by ActiveMachineIDs) or destroyed on adopt failure (no
// longer exists). Idempotent.
func (p *Pool) FinishHandoff(machineID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.handoff, machineID)
}

// WarmMachineIDs returns a snapshot of machine IDs the reaper must protect:
// every VM currently in the warm pool PLUS every VM in an in-flight handoff
// (popped by Acquire, not yet an active lease). Combined with
// LeaseManager.ActiveMachineIDs, this guarantees no broker-owned VM is ever
// unprotected — including during the Acquire->AdoptWarm window.
//
// INVARIANT 2: the reaper MUST NOT destroy warm or handing-off VMs.
func (p *Pool) WarmMachineIDs() map[string]struct{} {
	p.mu.Lock()
	defer p.mu.Unlock()
	ids := make(map[string]struct{}, len(p.entries)+len(p.quarantine)+len(p.handoff))
	for _, e := range p.entries {
		if e.machine != nil {
			ids[e.machine.ID] = struct{}{}
		}
	}
	for id := range p.quarantine {
		ids[id] = struct{}{}
	}
	for id := range p.handoff {
		ids[id] = struct{}{}
	}
	return ids
}

// Run starts the background maintainer that keeps the pool at Size warm VMs.
// It exits when ctx is done. Call Drain() after ctx cancels to tear down any
// remaining warm VMs.
func (p *Pool) Run(ctx context.Context) {
	// Initial fill on startup.
	p.maintain(ctx)

	ticker := time.NewTicker(poolMaintainInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.maintain(ctx)
		}
	}
}

// Drain destroys all warm VMs currently in the pool and releases their
// concurrency slots.
//
// INVARIANT 4: warm VMs are cleaned up on graceful shutdown.
func (p *Pool) Drain(ctx context.Context) {
	p.mu.Lock()
	p.closed = true
	draining := make([]warmEntry, len(p.entries))
	copy(draining, p.entries)
	p.entries = nil
	for id, e := range p.quarantine {
		draining = append(draining, e)
		delete(p.quarantine, id)
	}
	p.mu.Unlock()

	failed := p.destroyWarmEntries(ctx, draining, "drain")
	p.quarantineFailed(failed)
}

// Pause stops the maintainer from creating new warm VMs and destroys the ones
// currently warm, releasing their concurrency slots. It is the kill-switch
// counterpart to Drain: reversible via Resume. Without this, a paused/killed
// broker would keep a warm VM running and replenishing it under the serve
// context, so the kill switch would not actually stop standing compute/spend.
func (p *Pool) Pause(ctx context.Context) {
	p.mu.Lock()
	p.paused = true
	draining := make([]warmEntry, len(p.entries))
	copy(draining, p.entries)
	p.entries = nil
	for id, e := range p.quarantine {
		draining = append(draining, e)
		delete(p.quarantine, id)
	}
	p.mu.Unlock()

	failed := p.destroyWarmEntries(ctx, draining, "pause")
	p.quarantineFailed(failed)
}

// Resume re-enables warm-VM creation. The maintainer refills the pool on its
// next tick.
func (p *Pool) Resume() {
	p.mu.Lock()
	p.paused = false
	p.mu.Unlock()
}

// maintain recycles stale entries and fills the pool up to Size.
func (p *Pool) maintain(ctx context.Context) {
	p.retryQuarantine(ctx)
	p.recycleStale(ctx)
	p.fill(ctx)
}

// recycleStale destroys warm VMs older than MaxWarmAge.
func (p *Pool) recycleStale(ctx context.Context) {
	now := p.now()
	p.mu.Lock()
	var stale []warmEntry
	kept := make([]warmEntry, 0, len(p.entries))
	for _, e := range p.entries {
		if now.Sub(e.created) >= p.maxWarmAge {
			stale = append(stale, e)
		} else {
			kept = append(kept, e)
		}
	}
	p.entries = kept
	p.mu.Unlock()

	failed := p.destroyWarmEntries(ctx, stale, "recycle stale")
	p.quarantineFailed(failed)
}

func (p *Pool) retryQuarantine(ctx context.Context) {
	p.mu.Lock()
	if len(p.quarantine) == 0 {
		p.mu.Unlock()
		return
	}
	retry := make([]warmEntry, 0, len(p.quarantine))
	for id, e := range p.quarantine {
		retry = append(retry, e)
		delete(p.quarantine, id)
	}
	p.mu.Unlock()

	failed := p.destroyWarmEntries(ctx, retry, "retry quarantined")
	p.quarantineFailed(failed)
}

func (p *Pool) quarantineFailed(entries []warmEntry) {
	if len(entries) == 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.quarantine == nil {
		p.quarantine = make(map[string]warmEntry)
	}
	for _, e := range entries {
		if e.machine == nil {
			continue
		}
		p.quarantine[e.machine.ID] = e
	}
}

func (p *Pool) destroyWarmEntries(ctx context.Context, entries []warmEntry, reason string) []warmEntry {
	failed := make([]warmEntry, 0)
	for _, e := range entries {
		if e.machine == nil {
			continue
		}
		destroyCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), poolDestroyTimeout)
		err := p.provider.DestroyMachine(destroyCtx, e.machine.ID)
		cancel()
		if err != nil {
			failed = append(failed, e)
			_, _ = fmt.Fprintf(p.log, "pool: %s destroy warm vm %s failed: %v\n", reason, e.machine.ID, err)
			continue
		}
		e.release()
		_, _ = fmt.Fprintf(p.log, "pool: %s destroyed warm vm %s\n", reason, e.machine.ID)
	}
	return failed
}

// fill creates warm VMs up to Size, respecting the shared concurrency cap.
func (p *Pool) fill(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}
		p.mu.Lock()
		need := p.size - len(p.entries)
		isClosed := p.closed
		isPaused := p.paused
		p.mu.Unlock()
		if need <= 0 || isClosed || isPaused {
			return
		}

		// INVARIANT 1: acquire a concurrency slot BEFORE creating the VM.
		// This slot counts toward the global cap, ensuring warm + active
		// never exceeds the configured concurrency.
		release, ok := p.conc.Acquire()
		if !ok {
			// At capacity: don't create more warm VMs. The pool will try
			// again on the next maintain tick.
			return
		}

		vmCode, err := p.newVMCode()
		if err != nil {
			release()
			_, _ = fmt.Fprintf(p.log, "pool: generate vm code: %v\n", err)
			return
		}
		spec := p.buildSpec(vmCode)
		m, err := p.provider.CreateMachine(ctx, spec)
		if err != nil {
			release()
			_, _ = fmt.Fprintf(p.log, "pool: create warm vm: %v\n", err)
			return
		}
		if werr := p.provider.WaitReady(ctx, m.ID); werr != nil {
			_ = p.provider.DestroyMachine(context.WithoutCancel(ctx), m.ID)
			release()
			_, _ = fmt.Fprintf(p.log, "pool: warm vm %s not ready: %v\n", m.ID, werr)
			return
		}

		p.mu.Lock()
		// Re-check closed AND paused under the lock: a Drain (closed) or Kill
		// (paused) can land while this VM was being created/booted, and the top
		// of the loop checked before CreateMachine. Without this, a kill mid-
		// create would leave a warm VM running after the pool was supposed to
		// stop. Destroy it and free the slot.
		if p.closed || p.paused {
			p.mu.Unlock()
			_ = p.provider.DestroyMachine(context.WithoutCancel(ctx), m.ID)
			release()
			return
		}
		p.entries = append(p.entries, warmEntry{
			machine: m,
			vmCode:  vmCode,
			release: release,
			created: p.now(),
		})
		// Do NOT log vmCode: it is the per-VM broker->VM session credential.
		_, _ = fmt.Fprintf(p.log, "pool: warm vm %s ready\n", m.ID)
		p.mu.Unlock()
	}
}
