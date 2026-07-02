// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/playground/livechat"
)

const testImage = "registry.fly.io/playground:test"

// testVMCode returns a deterministic code generator for tests.
func testVMCode() func() (string, error) {
	var n atomic.Int64
	return func() (string, error) {
		return fmt.Sprintf("code-%d", n.Add(1)), nil
	}
}

func testBuildSpec(vmCode string) MachineSpec {
	return MachineSpec{
		Image: testImage,
		Env:   map[string]string{"PLAYGROUND_CODE": vmCode},
	}
}

// newTestPool constructs a Pool wired to a fake provider and a shared limiter.
func newTestPool(t *testing.T, provider MachineProvider, limiter *livechat.ConcurrencyLimiter, size int, maxWarmAge time.Duration, now func() time.Time) *Pool {
	t.Helper()
	if maxWarmAge <= 0 {
		maxWarmAge = 10 * time.Minute
	}
	if now == nil {
		now = time.Now
	}
	log := &safeBuffer{}
	p, err := NewPool(PoolConfig{
		Provider:    provider,
		Concurrency: limiter,
		NewVMCode:   testVMCode(),
		BuildSpec:   testBuildSpec,
		Size:        size,
		MaxWarmAge:  maxWarmAge,
		Now:         now,
		Log:         log,
	})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	return p
}

// TestPoolAcquireReturnsWarmVM verifies Acquire returns a warm VM when one is
// ready, and ok=false when the pool is empty.
func TestPoolAcquireReturnsWarmVM(t *testing.T) {
	fp := &fakeProvider{}
	limiter := livechat.NewConcurrencyLimiter(3)
	pool := newTestPool(t, fp, limiter, 1, 0, nil)

	// Pool is empty initially: Acquire must return ok=false.
	_, _, _, ok := pool.Acquire()
	if ok {
		t.Fatal("Acquire on empty pool should return ok=false")
	}

	// Run one maintain cycle to fill the pool.
	ctx := context.Background()
	pool.maintain(ctx)

	// Now Acquire should succeed.
	m, code, release, ok := pool.Acquire()
	if !ok {
		t.Fatal("Acquire should succeed after maintain fills the pool")
	}
	if m == nil || m.ID == "" {
		t.Fatal("acquired machine is nil or has no ID")
	}
	if code == "" {
		t.Fatal("acquired vmCode is empty")
	}
	if release == nil {
		t.Fatal("acquired release func is nil")
	}
	// The release function is transferred to the caller.
	release()
}

// TestPoolHandoffStaysReaperProtected proves the warm-handoff TOCTOU is closed.
// Acquire pops a VM out of the warm entries BEFORE the caller adopts it into an
// active lease; in that window the VM is owned by neither the pool's entries nor
// LeaseManager.ActiveMachineIDs. If WarmMachineIDs did not also cover in-flight
// handoffs, a reaper sweep in that window could destroy a live, about-to-be-used
// VM (it can outlive the 5m grace, since warm VMs live up to maxWarmAge). The VM
// must stay reaper-protected until FinishHandoff.
func TestPoolHandoffStaysReaperProtected(t *testing.T) {
	fp := &fakeProvider{}
	limiter := livechat.NewConcurrencyLimiter(3)
	pool := newTestPool(t, fp, limiter, 1, 0, nil)
	pool.maintain(context.Background())

	m, _, release, ok := pool.Acquire()
	if !ok {
		t.Fatal("Acquire should succeed after maintain fills the pool")
	}

	// Popped from entries...
	pool.mu.Lock()
	nEntries := len(pool.entries)
	pool.mu.Unlock()
	if nEntries != 0 {
		t.Fatalf("entries = %d after Acquire, want 0 (machine popped)", nEntries)
	}
	// ...but STILL in the reaper-protected set (in-flight handoff).
	if _, prot := pool.WarmMachineIDs()[m.ID]; !prot {
		t.Fatalf("machine %s not protected during handoff; reaper could destroy a live VM", m.ID)
	}

	// FinishHandoff clears protection (caller has adopted it into a lease or
	// destroyed it on adopt failure).
	pool.FinishHandoff(m.ID)
	if _, prot := pool.WarmMachineIDs()[m.ID]; prot {
		t.Fatalf("machine %s still protected after FinishHandoff", m.ID)
	}
	release()
}

// TestPoolCapInvariant verifies that warm + active machines never exceed the
// configured concurrency cap.
//
// INVARIANT 1: warm + active slots never exceed Cap().
func TestPoolCapInvariant(t *testing.T) {
	fp := &fakeProvider{}
	limiter := livechat.NewConcurrencyLimiter(2)
	// Build a lease manager with the shared limiter (not via newManager,
	// which creates its own limiter).
	lm, err := NewLeaseManager(LeaseConfig{
		Provider:    fp,
		Concurrency: limiter,
		Image:       testImage,
	})
	if err != nil {
		t.Fatalf("NewLeaseManager: %v", err)
	}

	pool := newTestPool(t, fp, limiter, 1, 0, nil)

	// Fill the pool: 1 warm VM, consuming 1 of 2 slots.
	pool.maintain(context.Background())
	if limiter.InUse() != 1 {
		t.Fatalf("InUse after pool fill = %d, want 1", limiter.InUse())
	}

	// Lease one active VM: should succeed (2 of 2 slots used: 1 warm + 1 active).
	lease, leaseErr := lm.Lease(context.Background(), "sess-1", nil)
	if leaseErr != nil {
		t.Fatalf("Lease: %v", leaseErr)
	}
	if limiter.InUse() != 2 {
		t.Fatalf("InUse after lease = %d, want 2", limiter.InUse())
	}

	// Another pool fill should NOT create a VM (at cap).
	pool.maintain(context.Background())
	if limiter.InUse() != 2 {
		t.Fatalf("InUse after second maintain = %d, want 2 (cap)", limiter.InUse())
	}

	// Verify total machines created: 1 warm + 1 active = 2.
	created, _ := fp.counts()
	if created != 2 {
		t.Errorf("total machines created = %d, want 2", created)
	}

	// Hand out the warm VM: slot count stays at 2 (transferred, not released).
	m, code, warmRelease, ok := pool.Acquire()
	if !ok {
		t.Fatal("Acquire should succeed")
	}
	_ = code
	// Adopt the warm VM as a lease. Slot is transferred: no new slot consumed.
	adoptedLease, adoptErr := lm.AdoptWarm("sess-warm", m, warmRelease)
	if adoptErr != nil {
		t.Fatalf("AdoptWarm: %v", adoptErr)
	}
	if limiter.InUse() != 2 {
		t.Fatalf("InUse after handout = %d, want 2 (no change on handout)", limiter.InUse())
	}

	// Release both leases: slots freed.
	lm.Release(context.Background(), "sess-1")
	_ = lease
	lm.Release(context.Background(), "sess-warm")
	_ = adoptedLease
	// The warm VM's slot was released via lm.Release -> lease.release().
	// Plus the active VM's slot.
	if limiter.InUse() != 0 {
		t.Fatalf("InUse after releasing both = %d, want 0", limiter.InUse())
	}
}

// TestPoolHandoutDoesNotLeakOrDoubleCountSlot verifies that handing out a warm
// VM transfers exactly one slot (no leak, no double-count).
func TestPoolHandoutDoesNotLeakOrDoubleCountSlot(t *testing.T) {
	fp := &fakeProvider{}
	limiter := livechat.NewConcurrencyLimiter(3)
	pool := newTestPool(t, fp, limiter, 1, 0, nil)

	// Fill: 1 warm VM, 1 slot used.
	pool.maintain(context.Background())
	if limiter.InUse() != 1 {
		t.Fatalf("InUse after fill = %d, want 1", limiter.InUse())
	}

	// Acquire: slot stays at 1 (popped from pool, not released).
	_, _, release, ok := pool.Acquire()
	if !ok {
		t.Fatal("Acquire should succeed")
	}
	if limiter.InUse() != 1 {
		t.Fatalf("InUse after Acquire = %d, want 1", limiter.InUse())
	}

	// Release the slot (caller's responsibility after session ends).
	release()
	if limiter.InUse() != 0 {
		t.Fatalf("InUse after release = %d, want 0", limiter.InUse())
	}

	// Pool replenish: maintain creates a new warm VM.
	pool.maintain(context.Background())
	if limiter.InUse() != 1 {
		t.Fatalf("InUse after replenish = %d, want 1", limiter.InUse())
	}
}

// TestReaperSparesWarmVMs proves a warm VM (tagged, not in active leases) is
// NOT destroyed because WarmMachineIDs is in the protected set.
//
// INVARIANT 2: reaper MUST NOT destroy warm VMs.
func TestReaperSparesWarmVMs(t *testing.T) {
	baseTime := time.Date(2026, 6, 25, 12, 0, 0, 0, time.UTC)

	fp := &fakeProvider{}
	limiter := livechat.NewConcurrencyLimiter(3)
	pool := newTestPool(t, fp, limiter, 1, 0, func() time.Time { return baseTime })
	pool.maintain(context.Background())

	// The warm VM is in managedMachines (fakeProvider appends on create).
	// Give it an old CreatedAt so it would normally be reaped.
	fp.mu.Lock()
	for i := range fp.managedMachines {
		fp.managedMachines[i].CreatedAt = baseTime.Add(-10 * time.Minute)
	}
	fp.mu.Unlock()

	warmIDs := pool.WarmMachineIDs()
	if len(warmIDs) != 1 {
		t.Fatalf("WarmMachineIDs = %d, want 1", len(warmIDs))
	}

	// Build the reaper with the combined protected set (active leases UNION warm pool).
	activeIDsFn := func() map[string]struct{} {
		// No active leases in this test.
		ids := make(map[string]struct{})
		for id := range pool.WarmMachineIDs() {
			ids[id] = struct{}{}
		}
		return ids
	}

	reaper, err := NewReaper(ReaperConfig{
		Provider:  fp,
		ActiveIDs: activeIDsFn,
		Now:       func() time.Time { return baseTime },
		Grace:     5 * time.Minute,
		Log:       &safeBuffer{},
	})
	if err != nil {
		t.Fatalf("NewReaper: %v", err)
	}

	destroyed, recErr := reaper.ReconcileOnce(context.Background())
	if recErr != nil {
		t.Fatalf("ReconcileOnce: %v", recErr)
	}
	if destroyed != 0 {
		t.Errorf("reaper destroyed %d warm VMs, want 0 (warm VMs must be spared)", destroyed)
	}
}

// TestPoolFallbackOnEmpty verifies that when the pool is empty, Acquire returns
// ok=false and the caller can fall back to the synchronous create path.
//
// INVARIANT 3: a visitor NEVER fails because the pool is empty.
func TestPoolFallbackOnEmpty(t *testing.T) {
	fp := &fakeProvider{}
	limiter := livechat.NewConcurrencyLimiter(3)
	pool := newTestPool(t, fp, limiter, 1, 0, nil)

	// Don't run maintain: pool stays empty.
	_, _, _, ok := pool.Acquire()
	if ok {
		t.Fatal("Acquire on empty pool should return ok=false")
	}

	// Cold path still works: lease directly.
	lm, err := NewLeaseManager(LeaseConfig{
		Provider:    fp,
		Concurrency: limiter,
		Image:       testImage,
	})
	if err != nil {
		t.Fatalf("NewLeaseManager: %v", err)
	}
	lease, leaseErr := lm.Lease(context.Background(), "cold-path", nil)
	if leaseErr != nil {
		t.Fatalf("cold-path Lease: %v", leaseErr)
	}
	if lease.Machine.ID == "" {
		t.Fatal("cold-path lease has no machine")
	}
}

// TestPoolDrainDestroysAll verifies that Drain destroys all warm VMs and
// releases their concurrency slots.
//
// INVARIANT 4: warm VMs are drained on graceful shutdown.
// TestPoolPauseDrainsAndStopsRefill proves the kill-switch behavior: Pause
// destroys the warm VMs (freeing their concurrency slots) AND stops the
// maintainer from refilling, until Resume. Without this a killed/paused broker
// would keep standing warm compute and keep replenishing it.
func TestPoolPauseDrainsAndStopsRefill(t *testing.T) {
	fp := &fakeProvider{}
	limiter := livechat.NewConcurrencyLimiter(3)
	pool := newTestPool(t, fp, limiter, 1, 0, nil)
	pool.maintain(context.Background())
	if got := len(pool.WarmMachineIDs()); got != 1 {
		t.Fatalf("warm before pause = %d, want 1", got)
	}

	pool.Pause(context.Background())
	if got := len(pool.WarmMachineIDs()); got != 0 {
		t.Fatalf("warm after pause = %d, want 0 (drained)", got)
	}
	if got := limiter.InUse(); got != 0 {
		t.Fatalf("slots in use after pause = %d, want 0 (released)", got)
	}

	// Paused: the maintainer must NOT refill.
	pool.maintain(context.Background())
	if got := len(pool.WarmMachineIDs()); got != 0 {
		t.Fatalf("paused pool refilled: %d warm, want 0", got)
	}

	// Resume: the maintainer refills again.
	pool.Resume()
	pool.maintain(context.Background())
	if got := len(pool.WarmMachineIDs()); got != 1 {
		t.Fatalf("warm after resume = %d, want 1", got)
	}
}

func TestPoolDrainDestroysAll(t *testing.T) {
	fp := &fakeProvider{}
	limiter := livechat.NewConcurrencyLimiter(5)
	pool := newTestPool(t, fp, limiter, 2, 0, nil)

	// Fill: 2 warm VMs.
	pool.maintain(context.Background())
	pool.maintain(context.Background()) // second call may be needed if fill creates one at a time
	if limiter.InUse() != 2 {
		t.Fatalf("InUse after fill = %d, want 2", limiter.InUse())
	}
	warmBefore := len(pool.WarmMachineIDs())
	if warmBefore != 2 {
		t.Fatalf("warm VMs after fill = %d, want 2", warmBefore)
	}

	pool.Drain(context.Background())

	if len(pool.WarmMachineIDs()) != 0 {
		t.Errorf("warm VMs after drain = %d, want 0", len(pool.WarmMachineIDs()))
	}
	if limiter.InUse() != 0 {
		t.Errorf("InUse after drain = %d, want 0 (all slots freed)", limiter.InUse())
	}

	// Drain is idempotent.
	pool.Drain(context.Background())
}

// TestPoolRecycleStale verifies that warm entries older than MaxWarmAge are
// destroyed and replaced.
//
// INVARIANT 5: stale-warm recycling.
func TestPoolRecycleStale(t *testing.T) {
	fp := &fakeProvider{}
	limiter := livechat.NewConcurrencyLimiter(3)

	now := time.Date(2026, 6, 25, 12, 0, 0, 0, time.UTC)
	currentTime := now
	var timeMu sync.Mutex
	clockFn := func() time.Time {
		timeMu.Lock()
		defer timeMu.Unlock()
		return currentTime
	}

	pool := newTestPool(t, fp, limiter, 1, 5*time.Minute, clockFn)

	// Fill at t=0.
	pool.maintain(context.Background())
	warmIDs := pool.WarmMachineIDs()
	if len(warmIDs) != 1 {
		t.Fatalf("warm VMs after fill = %d, want 1", len(warmIDs))
	}
	var oldID string
	for id := range warmIDs {
		oldID = id
	}

	// Advance clock past MaxWarmAge.
	timeMu.Lock()
	currentTime = now.Add(6 * time.Minute)
	timeMu.Unlock()

	// Maintain: the stale entry should be destroyed and a fresh one created.
	pool.maintain(context.Background())
	newIDs := pool.WarmMachineIDs()
	if len(newIDs) != 1 {
		t.Fatalf("warm VMs after recycle = %d, want 1", len(newIDs))
	}
	for id := range newIDs {
		if id == oldID {
			t.Errorf("old warm VM %s should have been recycled", oldID)
		}
	}

	// The old VM should have been destroyed.
	fp.mu.Lock()
	found := false
	for _, d := range fp.destroyed {
		if d == oldID {
			found = true
		}
	}
	fp.mu.Unlock()
	if !found {
		t.Errorf("old warm VM %s not found in destroyed list", oldID)
	}

	// Slot count: still 1 (recycled = destroyed old + created new).
	if limiter.InUse() != 1 {
		t.Errorf("InUse after recycle = %d, want 1", limiter.InUse())
	}
}

func TestPoolRecycleStaleDestroyFailureKeepsEntryAndSlot(t *testing.T) {
	fp := &destroyErrProvider{fakeProvider: &fakeProvider{}, destroyErr: errors.New("destroy failed")}
	limiter := livechat.NewConcurrencyLimiter(1)

	now := time.Date(2026, 6, 25, 12, 0, 0, 0, time.UTC)
	currentTime := now
	var timeMu sync.Mutex
	clockFn := func() time.Time {
		timeMu.Lock()
		defer timeMu.Unlock()
		return currentTime
	}

	pool := newTestPool(t, fp, limiter, 1, 5*time.Minute, clockFn)
	pool.maintain(context.Background())
	warmIDs := pool.WarmMachineIDs()
	if len(warmIDs) != 1 {
		t.Fatalf("warm VMs after fill = %d, want 1", len(warmIDs))
	}
	var oldID string
	for id := range warmIDs {
		oldID = id
	}

	timeMu.Lock()
	currentTime = now.Add(6 * time.Minute)
	timeMu.Unlock()

	pool.maintain(context.Background())
	newIDs := pool.WarmMachineIDs()
	if len(newIDs) != 1 {
		t.Fatalf("warm VMs after failed recycle = %d, want 1", len(newIDs))
	}
	if _, ok := newIDs[oldID]; !ok {
		t.Fatalf("stale VM %s should stay tracked when destroy fails", oldID)
	}
	if _, _, _, ok := pool.Acquire(); ok {
		t.Fatal("failed-destroy stale VM was handed out; want quarantined")
	}
	if limiter.InUse() != 1 {
		t.Fatalf("InUse after failed recycle = %d, want 1", limiter.InUse())
	}
	created, _ := fp.counts()
	if created != 1 {
		t.Fatalf("created after failed recycle = %d, want 1; failed destroy must not free slot for replacement", created)
	}

	fp.destroyErr = nil
	pool.maintain(context.Background())
	recoveredIDs := pool.WarmMachineIDs()
	if len(recoveredIDs) != 1 {
		t.Fatalf("warm VMs after quarantine retry = %d, want replacement", len(recoveredIDs))
	}
	if _, ok := recoveredIDs[oldID]; ok {
		t.Fatalf("old VM %s stayed tracked after successful quarantine retry", oldID)
	}
	if limiter.InUse() != 1 {
		t.Fatalf("InUse after quarantine retry/refill = %d, want 1", limiter.InUse())
	}
	created, _ = fp.counts()
	if created != 2 {
		t.Fatalf("created after quarantine retry/refill = %d, want 2", created)
	}
	if fp.destroyCalls != 2 {
		t.Fatalf("destroy attempts after quarantine retry = %d, want 2", fp.destroyCalls)
	}
}

func TestPoolFillWaitReadyDestroyFailureQuarantinesVM(t *testing.T) {
	// fill() creates a VM, WaitReady fails, and the follow-up destroy ALSO fails.
	// The VM must be quarantined (still tracked + slot held), NOT forgotten with
	// its slot released — otherwise a still-alive VM leaks and the freed slot lets
	// warm+active drift above the cap (the cost-amplifier bug).
	fp := &destroyErrProvider{
		fakeProvider: &fakeProvider{waitErr: errors.New("not ready")},
		destroyErr:   errors.New("destroy failed"),
	}
	limiter := livechat.NewConcurrencyLimiter(1)
	pool := newTestPool(t, fp, limiter, 1, 0, nil)

	pool.maintain(context.Background())

	warmIDs := pool.WarmMachineIDs()
	if len(warmIDs) != 1 {
		t.Fatalf("WarmMachineIDs after not-ready+failed-destroy = %d, want 1 (quarantined)", len(warmIDs))
	}
	if _, _, _, ok := pool.Acquire(); ok {
		t.Fatal("quarantined not-ready VM was handed out; must not be acquirable")
	}
	if limiter.InUse() != 1 {
		t.Fatalf("InUse = %d, want 1 (slot held for the still-alive VM whose destroy failed)", limiter.InUse())
	}
	if created, _ := fp.counts(); created != 1 {
		t.Fatalf("created = %d, want 1 (a freed slot would spawn a replacement = the leak/cost bug)", created)
	}

	// Recover: destroy + WaitReady now succeed; quarantine retry cleans up and refills.
	fp.destroyErr = nil
	fp.waitErr = nil
	pool.maintain(context.Background())
	if limiter.InUse() != 1 {
		t.Fatalf("InUse after recovery = %d, want 1", limiter.InUse())
	}
}

func TestPoolAbortHandoffDestroyFailureQuarantines(t *testing.T) {
	// AbortHandoff on a warm VM whose destroy fails must keep it tracked (in
	// quarantine, still reaper-protected) with its slot held, and clear the
	// handoff marker — never release the slot and forget a still-alive VM.
	fp := &destroyErrProvider{fakeProvider: &fakeProvider{}, destroyErr: errors.New("destroy failed")}
	limiter := livechat.NewConcurrencyLimiter(1)
	pool := newTestPool(t, fp, limiter, 1, 0, nil)
	pool.maintain(context.Background())

	m, _, release, ok := pool.Acquire()
	if !ok {
		t.Fatal("Acquire should return the warm VM")
	}
	if _, in := pool.WarmMachineIDs()[m.ID]; !in {
		t.Fatal("acquired VM should be in the handoff-protected set")
	}

	pool.AbortHandoff(context.Background(), m, release, "adopt failed")

	if _, in := pool.WarmMachineIDs()[m.ID]; !in {
		t.Fatalf("AbortHandoff with failing destroy must keep the VM tracked (quarantine)")
	}
	if limiter.InUse() != 1 {
		t.Fatalf("InUse = %d, want 1 (slot held until destroy succeeds)", limiter.InUse())
	}
	pool.mu.Lock()
	_, stillHandoff := pool.handoff[m.ID]
	_, inQuarantine := pool.quarantine[m.ID]
	pool.mu.Unlock()
	if stillHandoff {
		t.Error("AbortHandoff should clear the handoff marker")
	}
	if !inQuarantine {
		t.Error("AbortHandoff with failing destroy should quarantine the VM")
	}
}

func TestPoolPauseDestroyFailureQuarantinesVM(t *testing.T) {
	fp := &destroyErrProvider{fakeProvider: &fakeProvider{}, destroyErr: errors.New("destroy failed")}
	limiter := livechat.NewConcurrencyLimiter(1)
	pool := newTestPool(t, fp, limiter, 1, 0, nil)
	pool.maintain(context.Background())
	warmIDs := pool.WarmMachineIDs()
	if len(warmIDs) != 1 {
		t.Fatalf("warm VMs after fill = %d, want 1", len(warmIDs))
	}
	var oldID string
	for id := range warmIDs {
		oldID = id
	}

	pool.Pause(context.Background())
	quarantinedIDs := pool.WarmMachineIDs()
	if len(quarantinedIDs) != 1 {
		t.Fatalf("warm VMs after failed pause destroy = %d, want quarantined VM", len(quarantinedIDs))
	}
	if _, ok := quarantinedIDs[oldID]; !ok {
		t.Fatalf("failed pause destroy VM %s should stay protected", oldID)
	}
	if _, _, _, ok := pool.Acquire(); ok {
		t.Fatal("failed-destroy paused VM was handed out; want quarantined")
	}
	if limiter.InUse() != 1 {
		t.Fatalf("InUse after failed pause destroy = %d, want 1", limiter.InUse())
	}

	fp.destroyErr = nil
	pool.maintain(context.Background())
	if got := len(pool.WarmMachineIDs()); got != 0 {
		t.Fatalf("warm VMs after paused quarantine retry = %d, want 0", got)
	}
	if limiter.InUse() != 0 {
		t.Fatalf("InUse after paused quarantine retry = %d, want 0", limiter.InUse())
	}
}

// TestPoolMaintainerExitsOnCancel verifies the Run goroutine exits promptly
// when its context is cancelled.
func TestPoolMaintainerExitsOnCancel(t *testing.T) {
	fp := &fakeProvider{}
	limiter := livechat.NewConcurrencyLimiter(3)
	pool := newTestPool(t, fp, limiter, 1, 0, nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		pool.Run(ctx)
		close(done)
	}()

	// Let the maintainer run at least one cycle.
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for len(pool.WarmMachineIDs()) == 0 {
		select {
		case <-deadline.C:
			t.Fatal("pool did not fill within deadline")
		case <-time.After(50 * time.Millisecond):
		}
	}

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not exit after cancel")
	}
}

// TestPoolCreateFailDoesNotLeak verifies that a failed VM create during pool
// fill does not leak a concurrency slot.
func TestPoolCreateFailDoesNotLeak(t *testing.T) {
	fp := &fakeProvider{createErr: fmt.Errorf("provider down")}
	limiter := livechat.NewConcurrencyLimiter(3)
	pool := newTestPool(t, fp, limiter, 1, 0, nil)

	pool.maintain(context.Background())

	if limiter.InUse() != 0 {
		t.Errorf("InUse after failed fill = %d, want 0 (slot not leaked)", limiter.InUse())
	}
	if len(pool.WarmMachineIDs()) != 0 {
		t.Errorf("warm VMs after failed fill = %d, want 0", len(pool.WarmMachineIDs()))
	}
}

// TestPoolWaitReadyFailDoesNotLeak verifies that a failed WaitReady during pool
// fill tears down the machine and frees the slot.
func TestPoolWaitReadyFailDoesNotLeak(t *testing.T) {
	fp := &fakeProvider{waitErr: fmt.Errorf("never started")}
	limiter := livechat.NewConcurrencyLimiter(3)
	pool := newTestPool(t, fp, limiter, 1, 0, nil)

	pool.maintain(context.Background())

	if limiter.InUse() != 0 {
		t.Errorf("InUse after wait fail = %d, want 0", limiter.InUse())
	}
	// Machine was created and then destroyed on wait failure.
	created, destroyed := fp.counts()
	if created != 1 || destroyed != 1 {
		t.Errorf("created=%d destroyed=%d, want 1 and 1", created, destroyed)
	}
}

// TestNewPoolValidation checks that NewPool rejects missing required fields.
func TestNewPoolValidation(t *testing.T) {
	fp := &fakeProvider{}
	limiter := livechat.NewConcurrencyLimiter(1)
	vmCode := testVMCode()

	tests := []struct {
		name string
		cfg  PoolConfig
	}{
		{"no provider", PoolConfig{Concurrency: limiter, NewVMCode: vmCode, BuildSpec: testBuildSpec}},
		{"no concurrency", PoolConfig{Provider: fp, NewVMCode: vmCode, BuildSpec: testBuildSpec}},
		{"no vm code", PoolConfig{Provider: fp, Concurrency: limiter, BuildSpec: testBuildSpec}},
		{"no build spec", PoolConfig{Provider: fp, Concurrency: limiter, NewVMCode: vmCode}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewPool(tt.cfg); err == nil {
				t.Error("want validation error")
			}
		})
	}
}

// TestPoolAdoptWarmSessionPath verifies the full warm-handout path: pool
// creates a warm VM, it's acquired, adopted as a lease, and the session-create
// uses the warm VM's code.
func TestPoolAdoptWarmSessionPath(t *testing.T) {
	fp := &fakeProvider{}
	limiter := livechat.NewConcurrencyLimiter(3)
	pool := newTestPool(t, fp, limiter, 1, 0, nil)

	// Fill the pool.
	pool.maintain(context.Background())

	// Acquire the warm VM.
	m, code, release, ok := pool.Acquire()
	if !ok {
		t.Fatal("Acquire should succeed after fill")
	}

	// Adopt as a lease.
	lm, err := NewLeaseManager(LeaseConfig{
		Provider:    fp,
		Concurrency: limiter,
		Image:       testImage,
	})
	if err != nil {
		t.Fatalf("NewLeaseManager: %v", err)
	}

	lease, adoptErr := lm.AdoptWarm("warm-session", m, release)
	if adoptErr != nil {
		t.Fatalf("AdoptWarm: %v", adoptErr)
	}
	if lease.Machine.ID != m.ID {
		t.Errorf("adopted lease machine ID = %s, want %s", lease.Machine.ID, m.ID)
	}
	pool.FinishHandoff(m.ID)
	if _, protected := pool.WarmMachineIDs()[m.ID]; protected {
		t.Fatalf("machine %s still reaper-protected after FinishHandoff", m.ID)
	}

	// The vmCode from the pool is what the session-create will use.
	if code == "" {
		t.Error("warm vmCode is empty")
	}

	// Release the lease (destroy + free slot).
	lm.Release(context.Background(), "warm-session")
	if limiter.InUse() != 0 {
		t.Errorf("InUse after release = %d, want 0", limiter.InUse())
	}
}

// TestPoolConcurrentAcquireSafe verifies that concurrent Acquire calls are
// safe under the race detector.
func TestPoolConcurrentAcquireSafe(t *testing.T) {
	fp := &fakeProvider{}
	limiter := livechat.NewConcurrencyLimiter(10)
	pool := newTestPool(t, fp, limiter, 5, 0, nil)

	// Fill the pool.
	pool.maintain(context.Background())

	var wg sync.WaitGroup
	acquired := make(chan struct{}, 10)
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, release, ok := pool.Acquire(); ok {
				acquired <- struct{}{}
				release()
			}
		}()
	}
	wg.Wait()
	close(acquired)
	count := 0
	for range acquired {
		count++
	}
	if count != 5 {
		t.Errorf("acquired %d from pool of 5, want exactly 5", count)
	}
}

// TestAdoptWarmValidation verifies AdoptWarm rejects empty session keys and
// nil machines.
func TestAdoptWarmValidation(t *testing.T) {
	fp := &fakeProvider{}
	limiter := livechat.NewConcurrencyLimiter(3)
	lm, err := NewLeaseManager(LeaseConfig{
		Provider:    fp,
		Concurrency: limiter,
		Image:       testImage,
	})
	if err != nil {
		t.Fatalf("NewLeaseManager: %v", err)
	}

	t.Run("empty session key", func(t *testing.T) {
		_, err := lm.AdoptWarm("", &Machine{ID: "m1"}, func() {})
		if err == nil {
			t.Error("want error for empty session key")
		}
	})

	t.Run("nil machine", func(t *testing.T) {
		_, err := lm.AdoptWarm("s1", nil, func() {})
		if err == nil {
			t.Error("want error for nil machine")
		}
	})

	t.Run("duplicate session key", func(t *testing.T) {
		_, err := lm.AdoptWarm("dup", &Machine{ID: "m1", PrivateIP: "fdaa::1"}, func() {})
		if err != nil {
			t.Fatalf("first AdoptWarm: %v", err)
		}
		_, err = lm.AdoptWarm("dup", &Machine{ID: "m2", PrivateIP: "fdaa::2"}, func() {})
		if err == nil {
			t.Error("want ErrDuplicateLease for duplicate session key")
		}
	})
}

// TestPoolFillVMCodeError verifies that a vmCode generation error during fill
// does not leak a slot.
func TestPoolFillVMCodeError(t *testing.T) {
	fp := &fakeProvider{}
	limiter := livechat.NewConcurrencyLimiter(3)
	log := &safeBuffer{}
	p, err := NewPool(PoolConfig{
		Provider:    fp,
		Concurrency: limiter,
		NewVMCode:   func() (string, error) { return "", fmt.Errorf("code gen failed") },
		BuildSpec:   testBuildSpec,
		Size:        1,
		Log:         log,
	})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	p.maintain(context.Background())
	if limiter.InUse() != 0 {
		t.Errorf("InUse after vmCode error = %d, want 0", limiter.InUse())
	}
}

// TestPoolDrainPreventsNewEntries verifies that after Drain, the maintainer
// does not create new warm VMs.
func TestPoolDrainPreventsNewEntries(t *testing.T) {
	fp := &fakeProvider{}
	limiter := livechat.NewConcurrencyLimiter(5)
	pool := newTestPool(t, fp, limiter, 2, 0, nil)

	pool.maintain(context.Background())
	if len(pool.WarmMachineIDs()) == 0 {
		t.Fatal("pool should have warm VMs after maintain")
	}

	pool.Drain(context.Background())

	// Maintain after drain should not create new VMs.
	pool.maintain(context.Background())
	if len(pool.WarmMachineIDs()) != 0 {
		t.Errorf("warm VMs after drain+maintain = %d, want 0", len(pool.WarmMachineIDs()))
	}
}
