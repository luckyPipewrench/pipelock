// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/playground/livechat"
)

func TestReleaseDestroyDeadlineRetainsCapacityAndRetries(t *testing.T) {
	p := &blockingDestroyProvider{fakeProvider: &fakeProvider{}, entered: make(chan struct{}, 2), allow: make(chan struct{})}
	lm := newManager(t, p, 1)
	lm.destroyTimeout = 20 * time.Millisecond
	lease, err := lm.Lease(context.Background(), "first", nil)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { lm.Release(context.Background(), "first"); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("destroy did not return after deadline")
	}
	if _, ok := lm.ActiveMachineIDs()[lease.Machine.ID]; !ok {
		t.Fatal("timed-out VM lost from quarantine")
	}
	if _, err := lm.Lease(context.Background(), "second", nil); !errors.Is(err, ErrAtCapacity) {
		t.Fatalf("capacity after timeout = %v", err)
	}
	close(p.allow)
	lm.RetryFailedDestroys(context.Background())
	if _, ok := lm.ActiveMachineIDs()[lease.Machine.ID]; ok {
		t.Fatal("retry did not clear quarantine")
	}
}

func TestAdoptWarmReleaseCallbackCanReadManager(t *testing.T) {
	lm := newManager(t, &fakeProvider{}, 1)
	called := make(chan struct{})
	_, err := lm.AdoptWarm("warm", &Machine{ID: "warm-machine"}, func() {
		lm.ActiveMachineIDs()
		close(called)
	})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { lm.Release(context.Background(), "warm"); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("release callback deadlocked on manager lock")
	}
	select {
	case <-called:
	default:
		t.Fatal("release callback was not called")
	}
}

func TestRetryFailedDestroysHonorsCallerCancellation(t *testing.T) {
	p := &blockingDestroyProvider{fakeProvider: &fakeProvider{}, entered: make(chan struct{}, 4), allow: make(chan struct{})}
	lm := newManager(t, p, 2)
	lm.destroyTimeout = 20 * time.Millisecond
	var ids []string
	for _, key := range []string{"first", "second"} {
		lease, err := lm.Lease(context.Background(), key, nil)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, lease.Machine.ID)
		lm.Release(context.Background(), key)
	}
	// With the caller's cancellation honored, a canceled reaper must not wait
	// out a fresh per-machine deadline.
	lm.destroyTimeout = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p.mu.Lock()
	callsBefore := p.calls
	p.mu.Unlock()
	done := make(chan struct{})
	go func() { lm.RetryFailedDestroys(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		close(p.allow)
		t.Fatal("canceled retry kept waiting on provider deletion")
	}
	p.mu.Lock()
	callsAfter := p.calls
	p.mu.Unlock()
	if callsAfter != callsBefore {
		t.Fatalf("canceled retry called the provider %d times", callsAfter-callsBefore)
	}
	for _, id := range ids {
		if _, ok := lm.ActiveMachineIDs()[id]; !ok {
			t.Fatalf("canceled retry dropped %s from quarantine", id)
		}
	}
	close(p.allow)
	lm.RetryFailedDestroys(context.Background())
	if got := len(lm.ActiveMachineIDs()); got != 0 {
		t.Fatalf("machines left after uncanceled retry = %d", got)
	}
}

func TestReconcileBoundsFailedDestroyRetriesBeforeListing(t *testing.T) {
	const retryBatchSize = 2
	p := &failingDestroyProvider{fakeProvider: &fakeProvider{}, fail: true}
	lm := newManager(t, p, retryBatchSize+2)
	for i := range retryBatchSize + 2 {
		id := fmt.Sprintf("quarantined-%d", i)
		lm.quarantine[id] = &Lease{Machine: &Machine{ID: id}, release: func() {}}
	}
	reaper, err := NewReaper(ReaperConfig{Provider: p, ActiveIDs: lm.ActiveMachineIDs, RetryFailedDestroys: lm.RetryFailedDestroys})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reaper.ReconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if p.destroyCalls != retryBatchSize {
		t.Fatalf("first reconciliation retried %d machines before listing, want %d", p.destroyCalls, retryBatchSize)
	}
	if got := len(lm.ActiveMachineIDs()); got != retryBatchSize+2 {
		t.Fatalf("quarantine after failed batch = %d, want %d", got, retryBatchSize+2)
	}
	if _, err := reaper.ReconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := len(p.attempted); got != retryBatchSize+2 {
		t.Fatalf("retry attempts after two cycles = %d, want %d", got, retryBatchSize+2)
	}
	seen := make(map[string]struct{}, len(p.attempted))
	for _, id := range p.attempted {
		seen[id] = struct{}{}
	}
	if len(seen) != retryBatchSize+2 {
		t.Fatalf("retry cycles skipped quarantined machines: attempts = %v", p.attempted)
	}
	p.fail = false
	for cycle, wantRemaining := range []int{2, 0} {
		if _, err := reaper.ReconcileOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
		if got := len(lm.ActiveMachineIDs()); got != wantRemaining {
			t.Fatalf("quarantine after recovery cycle %d = %d, want %d", cycle+1, got, wantRemaining)
		}
	}
}

func TestRetryFailedDestroysCancellationStopsInFlightDelete(t *testing.T) {
	p := &blockingDestroyProvider{fakeProvider: &fakeProvider{}, entered: make(chan struct{}, 4), allow: make(chan struct{})}
	lm := newManager(t, p, 1)
	lm.destroyTimeout = 20 * time.Millisecond
	lease, err := lm.Lease(context.Background(), "first", nil)
	if err != nil {
		t.Fatal(err)
	}
	lm.Release(context.Background(), "first")
	<-p.entered // the Release attempt
	lm.destroyTimeout = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { lm.RetryFailedDestroys(ctx); close(done) }()
	<-p.entered
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		close(p.allow)
		t.Fatal("in-flight delete ignored caller cancellation")
	}
	if _, ok := lm.ActiveMachineIDs()[lease.Machine.ID]; !ok {
		t.Fatal("canceled delete dropped the VM from quarantine")
	}
	close(p.allow)
}

func TestDestroyFailuresAreLoggedOnEveryPath(t *testing.T) {
	p := &failingDestroyProvider{fakeProvider: &fakeProvider{}, fail: true}
	var log bytes.Buffer
	lm, err := NewLeaseManager(LeaseConfig{Provider: p, Concurrency: livechat.NewConcurrencyLimiter(1), Image: "playground:test", Log: &log})
	if err != nil {
		t.Fatal(err)
	}
	lease, err := lm.Lease(context.Background(), "first", nil)
	if err != nil {
		t.Fatal(err)
	}
	lm.Release(context.Background(), "first")
	if _, err := lm.Lease(context.Background(), "second", nil); !errors.Is(err, ErrAtCapacity) {
		t.Fatalf("lease retry = %v", err)
	}
	lm.RetryFailedDestroys(context.Background())
	if got := strings.Count(log.String(), lease.Machine.ID+" failed: provider teardown unavailable"); got != 3 {
		t.Fatalf("logged destroy failures = %d, want 3; log=%q", got, log.String())
	}
}

// fakeProvider is an in-memory MachineProvider for testing the lease lifecycle
// and the orphan reaper.
type fakeProvider struct {
	mu         sync.Mutex
	created    []MachineSpec
	createdIDs []string
	destroyed  []string
	createErr  error
	waitErr    error
	nextID     int

	// managedMachines is the set returned by ListManagedMachines. Tests
	// populate it directly; CreateMachine also appends here with the
	// playground role tag so the fake behaves like the real Fly adapter.
	managedMachines []Machine
	listErr         error
}

type failingDestroyProvider struct {
	*fakeProvider
	fail         bool
	destroyCalls int
	attempted    []string
}

type blockingDestroyProvider struct {
	*fakeProvider
	entered chan struct{}
	allow   chan struct{}
	mu      sync.Mutex
	calls   int
}

func (p *blockingDestroyProvider) DestroyMachine(ctx context.Context, id string) error {
	p.mu.Lock()
	p.calls++
	p.mu.Unlock()
	select {
	case p.entered <- struct{}{}:
	default:
	}
	select {
	case <-p.allow:
	case <-ctx.Done():
		return ctx.Err()
	}
	return p.fakeProvider.DestroyMachine(ctx, id)
}

func TestReleaseSlowDestroyDoesNotBlockReadsOrDoubleClaim(t *testing.T) {
	p := &blockingDestroyProvider{fakeProvider: &fakeProvider{}, entered: make(chan struct{}, 2), allow: make(chan struct{})}
	lm := newManager(t, p, 1)
	lease, err := lm.Lease(context.Background(), "first", nil)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { lm.Release(context.Background(), "first"); close(done) }()
	select {
	case <-p.entered:
	case <-time.After(time.Second):
		t.Fatal("destroy did not start")
	}
	readDone := make(chan struct{})
	go func() { _, _ = lm.LeaseFor("first"); _ = lm.ActiveMachineIDs(); close(readDone) }()
	select {
	case <-readDone:
	case <-time.After(time.Second):
		t.Fatal("reads blocked by slow destroy")
	}
	leaseDone := make(chan error, 1)
	go func() { _, err := lm.Lease(context.Background(), "second", nil); leaseDone <- err }()
	select {
	case err := <-leaseDone:
		if !errors.Is(err, ErrAtCapacity) {
			t.Fatalf("lease during destroy = %v, want capacity refusal", err)
		}
	case <-time.After(time.Second):
		t.Fatal("lease blocked by slow destroy")
	}
	retryDone := make(chan struct{})
	go func() { lm.RetryFailedDestroys(context.Background()); close(retryDone) }()
	select {
	case <-retryDone:
	case <-time.After(time.Second):
		t.Fatal("retry blocked by slow destroy")
	}
	p.mu.Lock()
	calls := p.calls
	p.mu.Unlock()
	if calls != 1 {
		t.Fatalf("concurrent destroy calls = %d, want 1", calls)
	}
	if _, ok := lm.ActiveMachineIDs()[lease.Machine.ID]; !ok {
		t.Fatal("in-flight destroy disappeared from active IDs")
	}
	close(p.allow)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("release did not finish")
	}
}

func TestLeaseRetryFailedDestroyIsRateBounded(t *testing.T) {
	p := &failingDestroyProvider{fakeProvider: &fakeProvider{}, fail: true}
	lm := newManager(t, p, 1)
	if _, err := lm.Lease(context.Background(), "first", nil); err != nil {
		t.Fatal(err)
	}
	lm.Release(context.Background(), "first")
	for i := range 3 {
		_, err := lm.Lease(context.Background(), fmt.Sprintf("next-%d", i), nil)
		if !errors.Is(err, ErrAtCapacity) {
			t.Fatalf("lease %d = %v", i, err)
		}
	}
	if p.destroyCalls != 2 {
		t.Fatalf("destroy attempts = %d, want initial attempt and one prompt retry", p.destroyCalls)
	}
	lm.mu.Lock()
	next := lm.nextRetry
	lm.mu.Unlock()
	if next.IsZero() {
		t.Fatal("retry window not recorded")
	}
}

func TestLeasePromptRecoveryRetriesOneMachine(t *testing.T) {
	p := &failingDestroyProvider{fakeProvider: &fakeProvider{}, fail: true}
	lm := newManager(t, p, 3)
	for i := range 3 {
		key := fmt.Sprintf("session-%d", i)
		if _, err := lm.Lease(context.Background(), key, nil); err != nil {
			t.Fatal(err)
		}
	}
	for i := range 3 {
		lm.Release(context.Background(), fmt.Sprintf("session-%d", i))
	}
	if p.destroyCalls != 3 {
		t.Fatalf("initial destroy attempts = %d, want 3", p.destroyCalls)
	}
	if _, err := lm.Lease(context.Background(), "next", nil); !errors.Is(err, ErrAtCapacity) {
		t.Fatalf("lease after failed destroys = %v, want capacity refusal", err)
	}
	if p.destroyCalls != 4 {
		t.Fatalf("prompt destroy attempts = %d, want one additional attempt", p.destroyCalls)
	}
}

func (p *failingDestroyProvider) DestroyMachine(ctx context.Context, id string) error {
	p.destroyCalls++
	p.attempted = append(p.attempted, id)
	if p.fail {
		return errors.New("provider teardown unavailable")
	}
	return p.fakeProvider.DestroyMachine(ctx, id)
}

func (f *fakeProvider) CreateMachine(_ context.Context, spec MachineSpec) (*Machine, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.createErr != nil {
		return nil, f.createErr
	}
	f.nextID++
	id := fmt.Sprintf("m%d", f.nextID)
	f.created = append(f.created, spec)
	f.createdIDs = append(f.createdIDs, id)
	m := &Machine{ID: id, State: "created", PrivateIP: "fdaa::" + id, CreatedAt: time.Now()}
	f.managedMachines = append(f.managedMachines, *m)
	return m, nil
}

func (f *fakeProvider) WaitReady(_ context.Context, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.waitErr
}

func (f *fakeProvider) DestroyMachine(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.destroyed = append(f.destroyed, id)
	return nil
}

func (f *fakeProvider) ListManagedMachines(_ context.Context) ([]Machine, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	out := make([]Machine, len(f.managedMachines))
	copy(out, f.managedMachines)
	return out, nil
}

func (f *fakeProvider) counts() (created, destroyed int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.createdIDs), len(f.destroyed)
}

func newManager(t *testing.T, provider MachineProvider, capacity int) *LeaseManager {
	t.Helper()
	lm, err := NewLeaseManager(LeaseConfig{
		Provider:    provider,
		Concurrency: livechat.NewConcurrencyLimiter(capacity),
		Image:       "registry.fly.io/playground:test",
		BaseEnv:     map[string]string{"PLAYGROUND_LISTEN": "0.0.0.0:8080"},
	})
	if err != nil {
		t.Fatalf("NewLeaseManager: %v", err)
	}
	return lm
}

func TestLeaseSuccess(t *testing.T) {
	fp := &fakeProvider{}
	lm := newManager(t, fp, 2)

	lease, err := lm.Lease(context.Background(), "sess-1", map[string]string{"PLAYGROUND_CODE": "abc", "PLAYGROUND_LISTEN": "0.0.0.0:9000"})
	if err != nil {
		t.Fatalf("Lease: %v", err)
	}
	if lease.Machine.ID == "" || lease.Machine.PrivateIP == "" {
		t.Fatalf("lease machine incomplete: %+v", lease.Machine)
	}
	if lm.ActiveLeases() != 1 {
		t.Fatalf("ActiveLeases = %d, want 1", lm.ActiveLeases())
	}
	got, ok := lm.LeaseFor("sess-1")
	if !ok || got != lease {
		t.Fatal("LeaseFor did not return the lease")
	}
	// env merge: sessionEnv overrides BaseEnv.
	fp.mu.Lock()
	spec := fp.created[0]
	fp.mu.Unlock()
	if spec.Env["PLAYGROUND_CODE"] != "abc" {
		t.Errorf("session env not passed: %v", spec.Env)
	}
	if spec.Env["PLAYGROUND_LISTEN"] != "0.0.0.0:9000" {
		t.Errorf("session env did not override base: %v", spec.Env)
	}
}

func TestNewLeaseManagerOwnsBaseEnv(t *testing.T) {
	baseEnv := map[string]string{"PLAYGROUND_LISTEN": "0.0.0.0:8080"}
	fp := &fakeProvider{}
	lm, err := NewLeaseManager(LeaseConfig{
		Provider:    fp,
		Concurrency: livechat.NewConcurrencyLimiter(1),
		Image:       "registry.fly.io/playground:test",
		BaseEnv:     baseEnv,
	})
	if err != nil {
		t.Fatalf("NewLeaseManager: %v", err)
	}
	baseEnv["PLAYGROUND_ORCHESTRATOR_"+"KEY"] = "durable-root"

	if _, err := lm.Lease(context.Background(), "sess-1", nil); err != nil {
		t.Fatalf("Lease: %v", err)
	}
	fp.mu.Lock()
	spec := fp.created[0]
	fp.mu.Unlock()
	if _, found := spec.Env["PLAYGROUND_ORCHESTRATOR_"+"KEY"]; found {
		t.Fatal("lease inherited a BaseEnv mutation made after manager construction")
	}
}

func TestLeaseAtCapacity(t *testing.T) {
	fp := &fakeProvider{}
	lm := newManager(t, fp, 1)

	if _, err := lm.Lease(context.Background(), "sess-1", nil); err != nil {
		t.Fatalf("first Lease: %v", err)
	}
	_, err := lm.Lease(context.Background(), "sess-2", nil)
	if !errors.Is(err, ErrAtCapacity) {
		t.Fatalf("second Lease: want ErrAtCapacity, got %v", err)
	}
	if created, _ := fp.counts(); created != 1 {
		t.Errorf("created %d machines at cap 1, want 1", created)
	}
}

func TestLeaseCreateFailFreesSlot(t *testing.T) {
	fp := &fakeProvider{createErr: errors.New("boom")}
	lm := newManager(t, fp, 1)

	if _, err := lm.Lease(context.Background(), "sess-1", nil); err == nil {
		t.Fatal("want create error")
	}
	if lm.ActiveLeases() != 0 {
		t.Errorf("ActiveLeases = %d after failed create, want 0", lm.ActiveLeases())
	}
	// The slot must be freed: a subsequent lease (with a working provider on the
	// SAME limiter) must succeed, proving the cap-1 slot wasn't leaked.
	fp.createErr = nil
	if _, err := lm.Lease(context.Background(), "sess-2", nil); err != nil {
		t.Fatalf("slot leaked after failed create: %v", err)
	}
}

func TestLeaseWaitFailDestroysAndFreesSlot(t *testing.T) {
	fp := &fakeProvider{waitErr: errors.New("never started")}
	lm := newManager(t, fp, 1)

	if _, err := lm.Lease(context.Background(), "sess-1", nil); err == nil {
		t.Fatal("want wait error")
	}
	created, destroyed := fp.counts()
	if created != 1 || destroyed != 1 {
		t.Errorf("fail-closed teardown: created=%d destroyed=%d, want 1 and 1", created, destroyed)
	}
	if lm.ActiveLeases() != 0 {
		t.Errorf("ActiveLeases = %d after wait fail, want 0", lm.ActiveLeases())
	}
	// Slot freed: a working lease succeeds on the same cap-1 limiter.
	fp.waitErr = nil
	if _, err := lm.Lease(context.Background(), "sess-2", nil); err != nil {
		t.Fatalf("slot leaked after wait fail: %v", err)
	}
}

func TestReleaseDestroysAndFreesSlot(t *testing.T) {
	fp := &fakeProvider{}
	lm := newManager(t, fp, 1)

	lease, err := lm.Lease(context.Background(), "sess-1", nil)
	if err != nil {
		t.Fatalf("Lease: %v", err)
	}
	lm.Release(context.Background(), "sess-1")

	if lm.ActiveLeases() != 0 {
		t.Errorf("ActiveLeases = %d after release, want 0", lm.ActiveLeases())
	}
	if _, destroyed := fp.counts(); destroyed != 1 {
		t.Errorf("machine not destroyed on release")
	}
	if _, ok := lm.LeaseFor("sess-1"); ok {
		t.Error("LeaseFor returned a released lease")
	}
	_ = lease
	// Idempotent: releasing again is a no-op (no panic, no double-destroy beyond 1).
	lm.Release(context.Background(), "sess-1")
	lm.Release(context.Background(), "never-existed")
	if _, destroyed := fp.counts(); destroyed != 1 {
		t.Errorf("idempotent release destroyed %d times, want 1", destroyed)
	}
	// Slot freed: can lease again on the cap-1 limiter.
	if _, err := lm.Lease(context.Background(), "sess-2", nil); err != nil {
		t.Fatalf("slot leaked after release: %v", err)
	}
}

func TestReleaseDestroyFailureRetainsCapacityUntilRetry(t *testing.T) {
	provider := &failingDestroyProvider{fakeProvider: &fakeProvider{}, fail: true}
	lm := newManager(t, provider, 1)
	lease, err := lm.Lease(context.Background(), "sess-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	lm.Release(context.Background(), "sess-1")
	if _, ok := lm.LeaseFor("sess-1"); ok {
		t.Fatal("released session remains routable")
	}
	if _, ok := lm.ActiveMachineIDs()[lease.Machine.ID]; !ok {
		t.Fatal("failed teardown lost machine identity")
	}
	if _, err := lm.Lease(context.Background(), "sess-2", nil); !errors.Is(err, ErrAtCapacity) {
		t.Fatalf("lease after failed teardown = %v, want capacity refusal", err)
	}
	provider.fail = false
	// Advance the prompt-recovery window without sleeping.
	lm.mu.Lock()
	lm.nextRetry = time.Time{}
	lm.mu.Unlock()
	if _, err := lm.Lease(context.Background(), "sess-2", nil); err != nil {
		t.Fatalf("lease after teardown recovery: %v", err)
	}
}

func TestWaitFailureDestroyFailureRetainsCapacity(t *testing.T) {
	provider := &failingDestroyProvider{fakeProvider: &fakeProvider{waitErr: errors.New("not ready")}, fail: true}
	lm := newManager(t, provider, 1)
	if _, err := lm.Lease(context.Background(), "sess-1", nil); err == nil {
		t.Fatal("expected readiness error")
	}
	if _, err := lm.Lease(context.Background(), "sess-2", nil); !errors.Is(err, ErrAtCapacity) {
		t.Fatalf("lease after failed readiness teardown = %v, want capacity refusal", err)
	}
}

func TestLeaseDuplicateKey(t *testing.T) {
	fp := &fakeProvider{}
	lm := newManager(t, fp, 5)

	if _, err := lm.Lease(context.Background(), "dup", nil); err != nil {
		t.Fatalf("first Lease: %v", err)
	}
	_, err := lm.Lease(context.Background(), "dup", nil)
	if !errors.Is(err, ErrDuplicateLease) {
		t.Fatalf("want ErrDuplicateLease, got %v", err)
	}
	if created, _ := fp.counts(); created != 1 {
		t.Errorf("duplicate key created %d machines, want 1", created)
	}
}

func TestActiveMachineIDs(t *testing.T) {
	fp := &fakeProvider{}
	lm := newManager(t, fp, 3)

	// Empty initially.
	ids := lm.ActiveMachineIDs()
	if len(ids) != 0 {
		t.Fatalf("ActiveMachineIDs on empty manager = %d, want 0", len(ids))
	}

	// Lease two machines.
	l1, err := lm.Lease(context.Background(), "s1", nil)
	if err != nil {
		t.Fatalf("Lease s1: %v", err)
	}
	l2, err := lm.Lease(context.Background(), "s2", nil)
	if err != nil {
		t.Fatalf("Lease s2: %v", err)
	}

	ids = lm.ActiveMachineIDs()
	if len(ids) != 2 {
		t.Fatalf("ActiveMachineIDs = %d, want 2", len(ids))
	}
	if _, ok := ids[l1.Machine.ID]; !ok {
		t.Errorf("machine %s not in active set", l1.Machine.ID)
	}
	if _, ok := ids[l2.Machine.ID]; !ok {
		t.Errorf("machine %s not in active set", l2.Machine.ID)
	}

	// Release one.
	lm.Release(context.Background(), "s1")
	ids = lm.ActiveMachineIDs()
	if len(ids) != 1 {
		t.Fatalf("ActiveMachineIDs after release = %d, want 1", len(ids))
	}
	if _, ok := ids[l2.Machine.ID]; !ok {
		t.Errorf("machine %s not in active set after releasing s1", l2.Machine.ID)
	}
}

func TestNewLeaseManagerValidation(t *testing.T) {
	limiter := livechat.NewConcurrencyLimiter(1)
	tests := []struct {
		name string
		cfg  LeaseConfig
	}{
		{"no provider", LeaseConfig{Concurrency: limiter, Image: "i"}},
		{"no concurrency", LeaseConfig{Provider: &fakeProvider{}, Image: "i"}},
		{"no image", LeaseConfig{Provider: &fakeProvider{}, Concurrency: limiter}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewLeaseManager(tt.cfg); err == nil {
				t.Error("want validation error")
			}
		})
	}
}
