// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package emit

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type lifecycleSink struct {
	sink     Sink
	stats    func() sinkStats
	full     error
	degraded error
}

type lifecycleFactory func(*testing.T, func() error) lifecycleSink

// The callback stands in for delivery, not admission. HTTP sinks acknowledge
// an HTTP response; syslog acknowledges the writer call, not receiver delivery.
type lifecycleTransport struct{ deliver func() error }

func (r lifecycleTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	_ = req.Body.Close()
	status := http.StatusOK
	if err := r.deliver(); err != nil {
		status = http.StatusBadRequest
	}
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
}

func TestHTTPAsyncSinkLifecycle(t *testing.T) {
	factories := map[string]lifecycleFactory{
		"webhook": func(_ *testing.T, deliver func() error) lifecycleSink {
			s := NewWebhookSink("https://collector.vendor.example/events", WithQueueSize(1), WithMinSeverity(SeverityWarn))
			s.client = &http.Client{Transport: lifecycleTransport{deliver}, Timeout: time.Second}
			return lifecycleSink{s, s.Stats, ErrQueueFull, ErrWebhookDegraded}
		},
		"otlp": func(t *testing.T, deliver func() error) lifecycleSink {
			s, err := NewOTLPSink("https://collector.vendor.example/logs", "test", SeverityWarn, nil, time.Second, 1, false)
			if err != nil {
				t.Fatal(err)
			}
			s.client = &http.Client{Transport: lifecycleTransport{deliver}, Timeout: time.Second}
			return lifecycleSink{s, s.Stats, ErrOTLPQueueFull, ErrOTLPDegraded}
		},
	}
	for name, factory := range factories {
		t.Run(name, func(t *testing.T) { runAsyncSinkLifecycle(t, factory) })
	}
}

func lifecycleWait(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("sink lifecycle deadline exceeded")
	}
}

func lifecyclePoll(t *testing.T, predicate func() bool) {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		if predicate() {
			return
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatal("sink state deadline exceeded")
		}
	}
}

func runAsyncSinkLifecycle(t *testing.T, factory lifecycleFactory) {
	t.Helper()
	event := Event{Type: "blocked", Severity: SeverityWarn}
	ctx := context.Background()
	t.Run("saturation_drain_and_idempotent_close", func(t *testing.T) {
		started := make(chan struct{})
		release := make(chan struct{})
		var first sync.Once
		var unblock sync.Once
		s := factory(t, func() error { first.Do(func() { close(started) }); <-release; return nil })
		defer func() { unblock.Do(func() { close(release) }); _ = s.sink.Close() }()
		if err := s.sink.Emit(ctx, Event{Type: "startup", Severity: SeverityInfo}); err != nil {
			t.Fatal(err)
		}
		if stats := s.stats(); stats.QueueLen != 0 || stats.Delivered != 0 {
			t.Fatalf("filtered event admitted: %+v", stats)
		}
		if err := s.sink.Emit(ctx, event); err != nil {
			t.Fatal(err)
		}
		lifecycleWait(t, started)
		if err := s.sink.Emit(ctx, event); err != nil {
			t.Fatal(err)
		}
		if err := s.sink.Emit(ctx, event); !errors.Is(err, s.full) {
			t.Fatalf("saturation = %v, want %v", err, s.full)
		}
		if stats := s.stats(); stats.Dropped != 1 || stats.QueueLen != 1 || !stats.Degraded {
			t.Fatalf("saturation accounting: %+v", stats)
		}
		done := make(chan struct{})
		go func() {
			var wg sync.WaitGroup
			for range 8 {
				wg.Go(func() { _ = s.sink.Close() })
			}
			wg.Wait()
			close(done)
		}()
		unblock.Do(func() { close(release) })
		lifecycleWait(t, done)
		if err := s.sink.Emit(ctx, event); err == nil || errors.Is(err, s.degraded) || errors.Is(err, s.full) {
			t.Fatalf("closed admission = %v", err)
		}
		// Filtering precedes the closed check for every initialized built-in sink.
		if err := s.sink.Emit(ctx, Event{Severity: SeverityInfo}); err != nil {
			t.Fatalf("closed filtered event = %v", err)
		}
		stats := s.stats()
		if stats.Delivered+stats.Failed+stats.Abandoned != 2 || stats.Delivered != 2 || stats.Dropped != 1 || stats.QueueLen != 0 {
			t.Fatalf("terminal accounting: %+v", stats)
		}
	})
	t.Run("degraded_error_is_accepted_advisory", func(t *testing.T) {
		var fail atomic.Bool
		fail.Store(true)
		s := factory(t, func() error {
			if fail.Load() {
				return errors.New("delivery refused")
			}
			return nil
		})
		defer func() { _ = s.sink.Close() }()
		if err := s.sink.Emit(ctx, event); err != nil {
			t.Fatal(err)
		}
		lifecyclePoll(t, func() bool { return s.stats().Failed == 1 && s.stats().Degraded })
		fail.Store(false)
		if err := s.sink.Emit(ctx, event); !errors.Is(err, s.degraded) {
			t.Fatalf("degraded admission = %v, want %v", err, s.degraded)
		}
		if err := s.sink.Close(); err != nil {
			t.Fatal(err)
		}
		stats := s.stats()
		if stats.Delivered != 1 || stats.Failed != 1 || stats.Abandoned != 0 || stats.Dropped != 0 || stats.QueueLen != 0 || stats.Degraded {
			t.Fatalf("advisory accounting/recovery: %+v", stats)
		}
	})
	t.Run("concurrent_admission_and_close", func(t *testing.T) {
		s := factory(t, func() error { return nil })
		defer func() { _ = s.sink.Close() }()
		start := make(chan struct{})
		done := make(chan struct{})
		var accepted atomic.Uint64
		if err := s.sink.Emit(ctx, event); err != nil {
			t.Fatal(err)
		}
		accepted.Store(1)
		var wg sync.WaitGroup
		for range 32 {
			wg.Go(func() {
				<-start
				err := s.sink.Emit(ctx, event)
				if err == nil || errors.Is(err, s.degraded) {
					accepted.Add(1)
				}
			})
		}
		for range 4 {
			wg.Go(func() { <-start; _ = s.sink.Close() })
		}
		close(start)
		go func() { wg.Wait(); close(done) }()
		lifecycleWait(t, done)
		stats := s.stats()
		if stats.Delivered+stats.Failed+stats.Abandoned != accepted.Load() || stats.QueueLen != 0 {
			t.Fatalf("accepted=%d terminal=%+v", accepted.Load(), stats)
		}
	})
}
