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
	closed  bool
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
	return e.machine, e.vmCode, e.release, true
}

// WarmMachineIDs returns a snapshot of machine IDs currently in the warm pool.
// Combined with LeaseManager.ActiveMachineIDs, this protects warm VMs from the
// reaper.
//
// INVARIANT 2: the reaper MUST NOT destroy warm VMs.
func (p *Pool) WarmMachineIDs() map[string]struct{} {
	p.mu.Lock()
	defer p.mu.Unlock()
	ids := make(map[string]struct{}, len(p.entries))
	for _, e := range p.entries {
		if e.machine != nil {
			ids[e.machine.ID] = struct{}{}
		}
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
	p.mu.Unlock()

	for _, e := range draining {
		_ = p.provider.DestroyMachine(ctx, e.machine.ID)
		e.release()
		_, _ = fmt.Fprintf(p.log, "pool: drain destroyed warm vm %s\n", e.machine.ID)
	}
}

// maintain recycles stale entries and fills the pool up to Size.
func (p *Pool) maintain(ctx context.Context) {
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

	for _, e := range stale {
		_ = p.provider.DestroyMachine(ctx, e.machine.ID)
		e.release()
		_, _ = fmt.Fprintf(p.log, "pool: recycled stale warm vm %s (age %s)\n",
			e.machine.ID, now.Sub(e.created).Truncate(time.Second))
	}
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
		p.mu.Unlock()
		if need <= 0 || isClosed {
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
		if p.closed {
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
		_, _ = fmt.Fprintf(p.log, "pool: warm vm %s ready (code %s)\n", m.ID, vmCode)
		p.mu.Unlock()
	}
}
