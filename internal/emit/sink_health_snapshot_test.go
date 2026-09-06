// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package emit

import (
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

type sinkHealthTransitionCase struct {
	name       string
	lock       func()
	unlock     func()
	transition func()
	blockedOn  string
	count      func() uint64
	stats      func() sinkStats
	health     func() SinkHealth
}

// TestSinkHealthTransitionsPublishAtomically holds a sink's health mutex while
// each degraded transition starts. A transition must not expose its counter
// before it has also published Degraded and LastError. Otherwise a scrape can
// report delivery failure while hiding the reason, which is inconsistent
// telemetry for an unhealthy audit sink.
func TestSinkHealthTransitionsPublishAtomically(t *testing.T) {
	for _, tt := range sinkHealthTransitionCases() {
		t.Run(tt.name, func(t *testing.T) {
			tt.lock()
			locked := true
			t.Cleanup(func() {
				if locked {
					tt.unlock()
				}
			})
			done := make(chan struct{})
			transitionID := make(chan string, 1)
			go func() {
				transitionID <- currentGoroutineID()
				tt.transition()
				close(done)
			}()

			waitForSinkHealthTransitionBlock(t, <-transitionID, tt.blockedOn)
			if got := tt.count(); got != 0 {
				t.Fatalf("counter became visible before degraded health details: %d", got)
			}

			tt.unlock()
			locked = false
			testwait.For(t, 2*time.Second, func() bool {
				select {
				case <-done:
					return true
				default:
					return false
				}
			}, "health transition completion")
			stats := tt.stats()
			if tt.count() == 0 || !stats.Degraded || stats.LastError == "" {
				t.Fatalf("stats = %+v, want published degraded transition", stats)
			}
			health := tt.health()
			if !health.Degraded || !health.LastErrorPresent {
				t.Fatalf("SinkHealth() = %+v, want degraded state and error presence", health)
			}
		})
	}
}

func currentGoroutineID() string {
	stack := make([]byte, 64)
	for {
		n := runtime.Stack(stack, false)
		if n < len(stack) {
			fields := strings.Fields(string(stack[:n]))
			if len(fields) >= 2 {
				return fields[1]
			}
			return ""
		}
		stack = make([]byte, len(stack)*2)
	}
}

func allGoroutineStacks() string {
	stack := make([]byte, 64<<10)
	for {
		n := runtime.Stack(stack, true)
		if n < len(stack) {
			return string(stack[:n])
		}
		stack = make([]byte, len(stack)*2)
	}
}

func waitForSinkHealthTransitionBlock(t *testing.T, id, function string) {
	t.Helper()
	testwait.For(t, 2*time.Second, func() bool {
		header := "goroutine " + id + " "
		for _, goroutine := range strings.Split(allGoroutineStacks(), "\n\n") {
			if strings.HasPrefix(goroutine, header) && strings.Contains(goroutine, function) && strings.Contains(goroutine, "sync.runtime_SemacquireMutex") {
				return true
			}
		}
		return false
	}, "transition %s blocked on lastErrMu (%s)", id, function)
}

func sinkHealthTransitionCases() []sinkHealthTransitionCase {
	var tests []sinkHealthTransitionCase
	for _, newSink := range []func() sinkHealthTransitionCase{
		func() sinkHealthTransitionCase {
			sink := newManualOTLPSink()
			return sinkHealthTransitionCase{
				name: "otlp failure", lock: sink.lastErrMu.Lock, unlock: sink.lastErrMu.Unlock,
				transition: func() { sink.recordFailure("send_error", Event{}, errors.New("send failed")) }, blockedOn: "(*OTLPSink).recordFailure", count: sink.failed.Load, stats: sink.Stats, health: sink.SinkHealth,
			}
		},
		func() sinkHealthTransitionCase {
			sink := newManualOTLPSink()
			return sinkHealthTransitionCase{
				name: "otlp drop", lock: sink.lastErrMu.Lock, unlock: sink.lastErrMu.Unlock,
				transition: func() { sink.recordDropped("queue_full", nil) }, blockedOn: "(*OTLPSink).recordDropped", count: sink.dropped.Load, stats: sink.Stats, health: sink.SinkHealth,
			}
		},
		func() sinkHealthTransitionCase {
			sink := newManualOTLPSink()
			return sinkHealthTransitionCase{
				name: "otlp abandon", lock: sink.lastErrMu.Lock, unlock: sink.lastErrMu.Unlock,
				transition: func() { sink.recordAbandoned("drain_timeout", Event{}, 1) }, blockedOn: "(*OTLPSink).recordAbandoned", count: sink.abandoned.Load, stats: sink.Stats, health: sink.SinkHealth,
			}
		},
		func() sinkHealthTransitionCase {
			sink := &WebhookSink{queue: make(chan Event, 1)}
			return sinkHealthTransitionCase{
				name: "webhook failure", lock: sink.lastErrMu.Lock, unlock: sink.lastErrMu.Unlock,
				transition: func() { sink.recordFailure("send_error", Event{}, errors.New("send failed")) }, blockedOn: "(*WebhookSink).recordFailure", count: sink.failed.Load, stats: sink.Stats, health: sink.SinkHealth,
			}
		},
		func() sinkHealthTransitionCase {
			sink := &WebhookSink{queue: make(chan Event, 1)}
			return sinkHealthTransitionCase{
				name: "webhook drop", lock: sink.lastErrMu.Lock, unlock: sink.lastErrMu.Unlock,
				transition: func() { sink.recordDropped("queue_full", nil) }, blockedOn: "(*WebhookSink).recordDropped", count: sink.dropped.Load, stats: sink.Stats, health: sink.SinkHealth,
			}
		},
		func() sinkHealthTransitionCase {
			sink := &WebhookSink{queue: make(chan Event, 1)}
			return sinkHealthTransitionCase{
				name: "webhook abandon", lock: sink.lastErrMu.Lock, unlock: sink.lastErrMu.Unlock,
				transition: func() { sink.recordAbandoned(1) }, blockedOn: "(*WebhookSink).recordAbandoned", count: sink.abandoned.Load, stats: sink.Stats, health: sink.SinkHealth,
			}
		},
	} {
		tests = append(tests, newSink())
	}
	return append(tests, syslogHealthTransitionCases()...)
}
