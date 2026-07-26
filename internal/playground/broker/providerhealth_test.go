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

func TestNewHealthTrackingProviderNilHealthReturnsInner(t *testing.T) {
	inner := &fakeProvider{}
	if got := NewHealthTrackingProvider(inner, nil); got != inner {
		t.Fatalf("NewHealthTrackingProvider nil health returned %T, want original provider", got)
	}
}

func TestProviderHealthConcurrentAccessRace(t *testing.T) {
	health := NewProviderHealth(func() time.Time {
		return time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	}, nil)

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				health.RecordFailure(errors.New("provider unavailable"))
				health.RecordSuccess()
				_, _ = health.BackoffActive()
				_ = health.Snapshot()
			}
		}()
	}
	wg.Wait()
}
