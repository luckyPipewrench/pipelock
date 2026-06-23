// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/playground/livechat"
)

// fakeProvider is an in-memory MachineProvider for testing the lease lifecycle.
type fakeProvider struct {
	mu         sync.Mutex
	created    []MachineSpec
	createdIDs []string
	destroyed  []string
	createErr  error
	waitErr    error
	nextID     int
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
	return &Machine{ID: id, State: "created", PrivateIP: "fdaa::" + id}, nil
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
