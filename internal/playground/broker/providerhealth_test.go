// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

type blockingProviderLog struct {
	entered chan struct{}
	release chan struct{}
}

func (w *blockingProviderLog) Write(p []byte) (int, error) {
	close(w.entered)
	<-w.release
	return len(p), nil
}

func TestProviderHealthPersistentFailureLogsOnce(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	var log bytes.Buffer
	health := NewProviderHealth(func() time.Time { return now }, &log)
	provider := NewHealthTrackingProvider(&fakeProvider{createErr: errors.New("provider rejected credential")}, health)

	for range providerFailingThreshold + 5 {
		if _, err := provider.CreateMachine(context.Background(), MachineSpec{Image: testImage}); err == nil {
			t.Fatal("CreateMachine succeeded, want failure")
		}
	}

	snap := health.Snapshot()
	if snap.OK {
		t.Fatal("Snapshot.OK = true after persistent failures, want false")
	}
	if snap.State != ProviderStateFailing {
		t.Fatalf("state = %s, want %s", snap.State, ProviderStateFailing)
	}
	if snap.ConsecutiveFailures != providerFailingThreshold+5 {
		t.Fatalf("failures = %d, want %d", snap.ConsecutiveFailures, providerFailingThreshold+5)
	}
	if got := strings.Count(log.String(), "broker cannot create sandboxes"); got != 1 {
		t.Fatalf("broker-cannot-create-sandboxes log count = %d, want 1; log=%q", got, log.String())
	}
}

func TestProviderHealthFailingLogOmitsRawProviderError(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	var log bytes.Buffer
	health := NewProviderHealth(func() time.Time { return now }, &log)
	errText := "provider rejected token secret-token-value for invite outer-code"

	for range providerFailingThreshold {
		health.RecordFailure(errors.New(errText))
	}

	got := log.String()
	if !strings.Contains(got, "broker cannot create sandboxes") {
		t.Fatalf("failure log missing outage signal: %q", got)
	}
	if strings.Contains(got, errText) || strings.Contains(got, "secret-token-value") || strings.Contains(got, "outer-code") {
		t.Fatalf("failure log exposed raw provider error: %q", got)
	}
}

func TestProviderHealthLoggingDoesNotHoldStateMutex(t *testing.T) {
	log := &blockingProviderLog{entered: make(chan struct{}), release: make(chan struct{})}
	health := NewProviderHealth(nil, log)
	for range providerFailingThreshold - 1 {
		health.RecordFailure(errors.New("provider unavailable"))
	}
	done := make(chan struct{})
	go func() {
		health.RecordFailure(errors.New("provider unavailable"))
		close(done)
	}()
	<-log.entered

	snapshotDone := make(chan struct{})
	go func() {
		_ = health.Snapshot()
		close(snapshotDone)
	}()
	select {
	case <-snapshotDone:
	case <-time.After(time.Second):
		t.Fatal("Snapshot blocked behind provider log write")
	}
	close(log.release)
	<-done
}

func TestProviderHealthBackoffGrowthAndCap(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	health := NewProviderHealth(func() time.Time { return now }, nil)
	want := []time.Duration{
		5 * time.Second,
		10 * time.Second,
		20 * time.Second,
		40 * time.Second,
		80 * time.Second,
		160 * time.Second,
		providerBackoffMax,
		providerBackoffMax,
	}

	for i, delay := range want {
		health.RecordFailure(errors.New("provider unavailable"))
		until, active := health.BackoffActive()
		if !active {
			t.Fatalf("failure %d: backoff inactive, want active", i+1)
		}
		if got := until.Sub(now); got != delay {
			t.Fatalf("failure %d: backoff = %s, want %s", i+1, got, delay)
		}
	}
}

func TestProviderHealthRecoveryResetsBackoffAndLogsOnce(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	var log bytes.Buffer
	health := NewProviderHealth(func() time.Time { return now }, &log)

	for range providerFailingThreshold {
		health.RecordFailure(errors.New("provider unavailable"))
	}
	if snap := health.Snapshot(); snap.State != ProviderStateFailing {
		t.Fatalf("state before recovery = %s, want failing", snap.State)
	}

	now = now.Add(time.Minute)
	health.RecordSuccess()
	health.RecordSuccess()

	snap := health.Snapshot()
	if !snap.OK || snap.State != ProviderStateOK {
		t.Fatalf("snapshot after recovery = ok:%v state:%s, want ok:true state:ok", snap.OK, snap.State)
	}
	if snap.ConsecutiveFailures != 0 {
		t.Fatalf("failures after recovery = %d, want 0", snap.ConsecutiveFailures)
	}
	if _, active := health.BackoffActive(); active {
		t.Fatal("backoff active after recovery")
	}
	if got := strings.Count(log.String(), "machine provider reachable again"); got != 1 {
		t.Fatalf("recovery log count = %d, want 1; log=%q", got, log.String())
	}
}

func TestProviderHealthBackgroundSuccessDoesNotHideCreateFailure(t *testing.T) {
	health := NewProviderHealth(func() time.Time {
		return time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	}, nil)
	provider := NewHealthTrackingProvider(&fakeProvider{createErr: errors.New("create denied")}, health)

	for range providerFailingThreshold {
		_, _ = provider.CreateMachine(context.Background(), MachineSpec{Image: testImage})
	}
	if _, err := provider.ListManagedMachines(context.Background()); err != nil {
		t.Fatalf("ListManagedMachines: %v", err)
	}

	snap := health.Snapshot()
	if snap.OK || snap.State != ProviderStateFailing || snap.ConsecutiveFailures != providerFailingThreshold {
		t.Fatalf("background success hid create failure: %+v", snap)
	}
}

func TestProviderHealthBackgroundFailureLogDoesNotClaimCreateFailure(t *testing.T) {
	var log bytes.Buffer
	health := NewProviderHealth(nil, &log)

	for range providerFailingThreshold {
		health.RecordBackgroundFailure(errors.New("provider unavailable"))
	}

	got := log.String()
	if !strings.Contains(got, "consecutive background errors") {
		t.Fatalf("background failure log = %q, want generic background failure", got)
	}
	if strings.Contains(got, "cannot create sandboxes") {
		t.Fatalf("background failure log falsely claims create failure: %q", got)
	}
}

func TestProviderHealthBackgroundSuccessClearsBackgroundFailure(t *testing.T) {
	health := NewProviderHealth(func() time.Time {
		return time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	}, nil)
	inner := &fakeProvider{listErr: errors.New("list denied")}
	provider := NewHealthTrackingProvider(inner, health)

	_, _ = provider.ListManagedMachines(context.Background())
	inner.listErr = nil
	if _, err := provider.ListManagedMachines(context.Background()); err != nil {
		t.Fatalf("ListManagedMachines recovery: %v", err)
	}

	snap := health.Snapshot()
	if !snap.OK || snap.State != ProviderStateOK || snap.ConsecutiveFailures != 0 {
		t.Fatalf("background recovery did not clear background failure: %+v", snap)
	}
}

func TestProviderHealthContextCanceledDoesNotCount(t *testing.T) {
	health := NewProviderHealth(func() time.Time {
		return time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	}, nil)

	health.RecordFailure(context.Canceled)
	health.RecordFailure(errors.Join(errors.New("wrapped"), context.Canceled))

	snap := health.Snapshot()
	if snap.State != ProviderStateUnknown || !snap.OK || snap.ConsecutiveFailures != 0 {
		t.Fatalf("snapshot after context cancellation = %+v, want unknown/ok/no failures", snap)
	}
	if _, active := health.BackoffActive(); active {
		t.Fatal("context cancellation activated backoff")
	}
}

func TestProviderHealthDeadlineExceededCounts(t *testing.T) {
	health := NewProviderHealth(func() time.Time {
		return time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	}, nil)

	health.RecordFailure(context.DeadlineExceeded)

	snap := health.Snapshot()
	if snap.State != ProviderStateDegraded || !snap.OK || snap.ConsecutiveFailures != 1 {
		t.Fatalf("snapshot after deadline exceeded = %+v, want degraded/ok/one failure", snap)
	}
	if _, active := health.BackoffActive(); !active {
		t.Fatal("deadline exceeded did not activate backoff")
	}
}

func TestHealthTrackingProviderWaitReadyFailureDoesNotAffectHealth(t *testing.T) {
	health := NewProviderHealth(func() time.Time {
		return time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	}, nil)
	inner := &fakeProvider{waitErr: errors.New("guest never started")}
	provider := NewHealthTrackingProvider(inner, health)

	m, err := provider.CreateMachine(context.Background(), MachineSpec{Image: testImage})
	if err != nil {
		t.Fatalf("CreateMachine: %v", err)
	}
	if err := provider.WaitReady(context.Background(), m.ID); err == nil {
		t.Fatal("WaitReady succeeded, want failure")
	}

	snap := health.Snapshot()
	if snap.State != ProviderStateOK || !snap.OK || snap.ConsecutiveFailures != 0 {
		t.Fatalf("snapshot after WaitReady failure = %+v, want ok/no failures", snap)
	}
}

func TestHealthTrackingProviderDestroyMachineTracksAndPropagates(t *testing.T) {
	health := NewProviderHealth(nil, nil)
	destroyErr := errors.New("destroy denied")
	inner := &destroyErrProvider{fakeProvider: &fakeProvider{}, destroyErr: destroyErr}
	provider := NewHealthTrackingProvider(inner, health)

	if err := provider.DestroyMachine(context.Background(), "vm-1"); !errors.Is(err, destroyErr) {
		t.Fatalf("DestroyMachine error = %v, want %v", err, destroyErr)
	}
	if snap := health.Snapshot(); snap.State != ProviderStateDegraded || snap.ConsecutiveFailures != 1 {
		t.Fatalf("snapshot after destroy failure = %+v, want degraded/one failure", snap)
	}

	inner.destroyErr = nil
	if err := provider.DestroyMachine(context.Background(), "vm-1"); err != nil {
		t.Fatalf("DestroyMachine recovery: %v", err)
	}
	if snap := health.Snapshot(); snap.State != ProviderStateOK || snap.ConsecutiveFailures != 0 {
		t.Fatalf("snapshot after destroy recovery = %+v, want ok/no failures", snap)
	}
}

func TestHealthTrackingProviderListMachinesTracksAndPropagates(t *testing.T) {
	health := NewProviderHealth(nil, nil)
	listErr := errors.New("list denied")
	inner := &fakeProvider{listErr: listErr}
	provider := NewHealthTrackingProvider(inner, health)

	if _, err := provider.ListManagedMachines(context.Background()); !errors.Is(err, listErr) {
		t.Fatalf("ListManagedMachines error = %v, want %v", err, listErr)
	}
	if snap := health.Snapshot(); snap.State != ProviderStateDegraded || snap.ConsecutiveFailures != 1 {
		t.Fatalf("snapshot after list failure = %+v, want degraded/one failure", snap)
	}

	inner.listErr = nil
	if _, err := provider.ListManagedMachines(context.Background()); err != nil {
		t.Fatalf("ListManagedMachines recovery: %v", err)
	}
	if snap := health.Snapshot(); snap.State != ProviderStateOK || snap.ConsecutiveFailures != 0 {
		t.Fatalf("snapshot after list recovery = %+v, want ok/no failures", snap)
	}
}

func TestNewHealthTrackingProviderNilHealthReturnsInner(t *testing.T) {
	inner := &fakeProvider{}
	if got := NewHealthTrackingProvider(inner, nil); got != inner {
		t.Fatalf("NewHealthTrackingProvider nil health returned %T, want original provider", got)
	}
}

func TestProviderHealthConcurrentAccessRace(t *testing.T) {
	var log bytes.Buffer
	health := NewProviderHealth(func() time.Time {
		return time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	}, &log)

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				health.RecordFailure(errors.New("provider unavailable"))
				health.RecordBackgroundFailure(errors.New("provider unavailable"))
				health.RecordBackgroundSuccess()
				health.RecordSuccess()
				_, _ = health.BackoffActive()
				_ = health.Snapshot()
			}
		}()
	}
	wg.Wait()
}
