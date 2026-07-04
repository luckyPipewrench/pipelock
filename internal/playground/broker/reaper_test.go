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
)

func TestReaperReconcileOnce(t *testing.T) {
	const graceWindow = 5 * time.Minute

	baseTime := time.Date(2026, 6, 25, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name         string
		machines     []Machine
		activeIDs    map[string]struct{}
		wantDestroy  int
		wantSpareIDs []string
	}{
		{
			name: "destroy stray older than grace",
			machines: []Machine{
				{ID: "orphan-old", State: "started", CreatedAt: baseTime.Add(-10 * time.Minute)},
			},
			activeIDs:   map[string]struct{}{},
			wantDestroy: 1,
		},
		{
			name: "spare active machine even if old",
			machines: []Machine{
				{ID: "active-old", State: "started", CreatedAt: baseTime.Add(-10 * time.Minute)},
			},
			activeIDs:    map[string]struct{}{"active-old": {}},
			wantDestroy:  0,
			wantSpareIDs: []string{"active-old"},
		},
		{
			name: "spare too-young machine not in active set (mid-setup race guard)",
			machines: []Machine{
				{ID: "young-orphan", State: "created", CreatedAt: baseTime.Add(-30 * time.Second)},
			},
			activeIDs:    map[string]struct{}{},
			wantDestroy:  0,
			wantSpareIDs: []string{"young-orphan"},
		},
		{
			name: "spare machine with zero CreatedAt (unknown age)",
			machines: []Machine{
				{ID: "unknown-age", State: "started"},
			},
			activeIDs:    map[string]struct{}{},
			wantDestroy:  0,
			wantSpareIDs: []string{"unknown-age"},
		},
		{
			name: "mixed: destroy old orphan, spare active and young",
			machines: []Machine{
				{ID: "orphan-old", State: "started", CreatedAt: baseTime.Add(-10 * time.Minute)},
				{ID: "active-old", State: "started", CreatedAt: baseTime.Add(-10 * time.Minute)},
				{ID: "young", State: "created", CreatedAt: baseTime.Add(-10 * time.Second)},
				{ID: "unknown", State: "started"},
			},
			activeIDs:    map[string]struct{}{"active-old": {}},
			wantDestroy:  1,
			wantSpareIDs: []string{"active-old", "young", "unknown"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &fakeProvider{managedMachines: tt.machines}
			var logBuf bytes.Buffer
			reaper, err := NewReaper(ReaperConfig{
				Provider:  fp,
				ActiveIDs: func() map[string]struct{} { return tt.activeIDs },
				Now:       func() time.Time { return baseTime },
				Grace:     graceWindow,
				Interval:  time.Hour, // irrelevant for ReconcileOnce
				Log:       &logBuf,
			})
			if err != nil {
				t.Fatalf("NewReaper: %v", err)
			}
			destroyed, err := reaper.ReconcileOnce(context.Background())
			if err != nil {
				t.Fatalf("ReconcileOnce: %v", err)
			}
			if destroyed != tt.wantDestroy {
				t.Errorf("destroyed = %d, want %d", destroyed, tt.wantDestroy)
			}
			fp.mu.Lock()
			destroyedSet := make(map[string]struct{}, len(fp.destroyed))
			for _, id := range fp.destroyed {
				destroyedSet[id] = struct{}{}
			}
			fp.mu.Unlock()
			for _, id := range tt.wantSpareIDs {
				if _, ok := destroyedSet[id]; ok {
					t.Errorf("machine %s should have been spared but was destroyed", id)
				}
			}
		})
	}
}

func TestReaperReconcileHeartbeatLog(t *testing.T) {
	baseTime := time.Date(2026, 6, 25, 12, 0, 0, 0, time.UTC)

	// A reconcile that finds nothing MUST still log a heartbeat. This is the
	// observability that was missing when the production reaper was blinded by
	// Fly summary mode and silently reaped nothing for a week.
	t.Run("zero machines logs managed=0", func(t *testing.T) {
		fp := &fakeProvider{}
		var logBuf bytes.Buffer
		reaper, err := NewReaper(ReaperConfig{
			Provider:  fp,
			ActiveIDs: func() map[string]struct{} { return nil },
			Now:       func() time.Time { return baseTime },
			Log:       &logBuf,
		})
		if err != nil {
			t.Fatalf("NewReaper: %v", err)
		}
		if _, err := reaper.ReconcileOnce(context.Background()); err != nil {
			t.Fatalf("ReconcileOnce: %v", err)
		}
		if !strings.Contains(logBuf.String(), "reaper: reconcile managed=0") {
			t.Errorf("want managed=0 heartbeat, got: %q", logBuf.String())
		}
	})

	t.Run("recurring zero machines logs alert", func(t *testing.T) {
		fp := &fakeProvider{}
		var logBuf bytes.Buffer
		reaper, err := NewReaper(ReaperConfig{
			Provider:  fp,
			ActiveIDs: func() map[string]struct{} { return nil },
			Now:       func() time.Time { return baseTime },
			Log:       &logBuf,
		})
		if err != nil {
			t.Fatalf("NewReaper: %v", err)
		}
		for i := 0; i < managedZeroAlertThreshold-1; i++ {
			if _, err := reaper.ReconcileOnce(context.Background()); err != nil {
				t.Fatalf("ReconcileOnce before threshold: %v", err)
			}
		}
		if strings.Contains(logBuf.String(), "event=managed_zero_recurred") {
			t.Fatalf("alert fired before threshold: %q", logBuf.String())
		}
		if _, err := reaper.ReconcileOnce(context.Background()); err != nil {
			t.Fatalf("ReconcileOnce at threshold: %v", err)
		}
		if !strings.Contains(logBuf.String(), "event=managed_zero_recurred") {
			t.Fatalf("missing recurring managed=0 alert: %q", logBuf.String())
		}
		if !strings.Contains(logBuf.String(), fmt.Sprintf("consecutive=%d", managedZeroAlertThreshold)) {
			t.Fatalf("missing consecutive count in alert: %q", logBuf.String())
		}
	})

	t.Run("zero-CreatedAt tagged machine logs skipped_unknown_age", func(t *testing.T) {
		fp := &fakeProvider{managedMachines: []Machine{{ID: "unknown", State: "started"}}}
		var logBuf bytes.Buffer
		reaper, err := NewReaper(ReaperConfig{
			Provider:  fp,
			ActiveIDs: func() map[string]struct{} { return nil },
			Now:       func() time.Time { return baseTime },
			Log:       &logBuf,
		})
		if err != nil {
			t.Fatalf("NewReaper: %v", err)
		}
		if _, err := reaper.ReconcileOnce(context.Background()); err != nil {
			t.Fatalf("ReconcileOnce: %v", err)
		}
		if !strings.Contains(logBuf.String(), "skipped_unknown_age=1") {
			t.Errorf("want skipped_unknown_age=1 in heartbeat, got: %q", logBuf.String())
		}
	})
}

func TestReaperReconcileOnceListError(t *testing.T) {
	fp := &fakeProvider{listErr: errors.New("provider down")}
	reaper, err := NewReaper(ReaperConfig{
		Provider:  fp,
		ActiveIDs: func() map[string]struct{} { return nil },
		Log:       &bytes.Buffer{},
	})
	if err != nil {
		t.Fatalf("NewReaper: %v", err)
	}
	_, recErr := reaper.ReconcileOnce(context.Background())
	if recErr == nil {
		t.Fatal("ReconcileOnce should fail when list fails")
	}
	if !strings.Contains(recErr.Error(), "provider down") {
		t.Errorf("error should wrap list error: %v", recErr)
	}
}

func TestReaperReconcileOnceDestroyError(t *testing.T) {
	// A destroy error should be logged and skipped, not fail the whole reconcile.
	baseTime := time.Date(2026, 6, 25, 12, 0, 0, 0, time.UTC)
	fp := &fakeProvider{
		managedMachines: []Machine{
			{ID: "orphan-a", State: "started", CreatedAt: baseTime.Add(-10 * time.Minute)},
			{ID: "orphan-b", State: "started", CreatedAt: baseTime.Add(-10 * time.Minute)},
		},
	}
	original := fp
	wrapper := &destroyErrProvider{fakeProvider: original, destroyErr: errors.New("nope")}

	var logBuf bytes.Buffer
	reaper, err := NewReaper(ReaperConfig{
		Provider:  wrapper,
		ActiveIDs: func() map[string]struct{} { return map[string]struct{}{} },
		Now:       func() time.Time { return baseTime },
		Grace:     5 * time.Minute,
		Log:       &logBuf,
	})
	if err != nil {
		t.Fatalf("NewReaper: %v", err)
	}
	destroyed, recErr := reaper.ReconcileOnce(context.Background())
	if recErr != nil {
		t.Fatalf("ReconcileOnce should not fail for destroy errors: %v", recErr)
	}
	if destroyed != 0 {
		t.Errorf("destroyed = %d, want 0 (all destroys failed)", destroyed)
	}
	if wrapper.destroyCalls != 2 {
		t.Errorf("DestroyMachine calls = %d, want 2", wrapper.destroyCalls)
	}
	if !strings.Contains(logBuf.String(), "nope") {
		t.Errorf("destroy error should be logged: %s", logBuf.String())
	}
}

// destroyErrProvider wraps fakeProvider but makes DestroyMachine always fail.
type destroyErrProvider struct {
	*fakeProvider
	destroyErr   error
	destroyCalls int
}

func (d *destroyErrProvider) DestroyMachine(_ context.Context, _ string) error {
	d.destroyCalls++
	return d.destroyErr
}

func TestReaperRunStartupReconcileAndCancel(t *testing.T) {
	baseTime := time.Date(2026, 6, 25, 12, 0, 0, 0, time.UTC)
	fp := &fakeProvider{
		managedMachines: []Machine{
			{ID: "startup-orphan", State: "started", CreatedAt: baseTime.Add(-10 * time.Minute)},
		},
	}
	var logBuf bytes.Buffer
	reaper, err := NewReaper(ReaperConfig{
		Provider:  fp,
		ActiveIDs: func() map[string]struct{} { return map[string]struct{}{} },
		Now:       func() time.Time { return baseTime },
		Grace:     5 * time.Minute,
		Interval:  50 * time.Millisecond, // short for test
		Log:       &logBuf,
	})
	if err != nil {
		t.Fatalf("NewReaper: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		reaper.Run(ctx)
		close(done)
	}()

	// Wait for the startup reconcile to have destroyed the orphan.
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for {
		fp.mu.Lock()
		n := len(fp.destroyed)
		fp.mu.Unlock()
		if n >= 1 {
			break
		}
		select {
		case <-deadline.C:
			t.Fatal("startup reconcile did not destroy orphan within deadline")
		default:
		}
		// Yield to the reaper goroutine.
		select {
		case <-time.After(10 * time.Millisecond):
		case <-deadline.C:
			t.Fatal("startup reconcile did not destroy orphan within deadline")
		}
	}

	fp.mu.Lock()
	if len(fp.destroyed) < 1 {
		t.Error("startup reconcile did not destroy the orphan")
	}
	found := false
	for _, id := range fp.destroyed {
		if id == "startup-orphan" {
			found = true
		}
	}
	fp.mu.Unlock()
	if !found {
		t.Error("startup-orphan was not destroyed")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not exit after cancel")
	}
}

func TestNewReaperValidation(t *testing.T) {
	fp := &fakeProvider{}
	tests := []struct {
		name string
		cfg  ReaperConfig
	}{
		{"no provider", ReaperConfig{ActiveIDs: func() map[string]struct{} { return nil }}},
		{"no active ids", ReaperConfig{Provider: fp}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewReaper(tt.cfg); err == nil {
				t.Error("want validation error")
			}
		})
	}
}

// safeBuffer is a thread-safe bytes.Buffer for tests that read while a
// goroutine writes.
type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *safeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *safeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestReaperRunLogsStartupAndTickErrors(t *testing.T) {
	fp := &fakeProvider{listErr: errors.New("boom")}
	logBuf := &safeBuffer{}
	reaper, err := NewReaper(ReaperConfig{
		Provider:  fp,
		ActiveIDs: func() map[string]struct{} { return nil },
		Interval:  50 * time.Millisecond,
		Log:       logBuf,
	})
	if err != nil {
		t.Fatalf("NewReaper: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		reaper.Run(ctx)
		close(done)
	}()

	// Wait long enough for at least the startup reconcile + one tick to fire
	// and log the list errors.
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for strings.Count(logBuf.String(), "boom") < 2 {
		select {
		case <-deadline.C:
			t.Fatalf("expected at least 2 error logs, got: %s", logBuf.String())
		case <-time.After(20 * time.Millisecond):
		}
	}

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not exit after cancel")
	}
}

func TestReaperDefaults(t *testing.T) {
	reaper, err := NewReaper(ReaperConfig{
		Provider:  &fakeProvider{},
		ActiveIDs: func() map[string]struct{} { return nil },
	})
	if err != nil {
		t.Fatalf("NewReaper: %v", err)
	}
	if reaper.grace != defaultReaperGrace {
		t.Errorf("grace = %v, want %v", reaper.grace, defaultReaperGrace)
	}
	if reaper.interval != defaultReaperInterval {
		t.Errorf("interval = %v, want %v", reaper.interval, defaultReaperInterval)
	}
}
