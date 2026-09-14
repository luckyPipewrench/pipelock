// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"testing"
	"time"
)

// TestSendReloadNeverDropsAQueuedSignal hammers the coalescing path with a
// stalled consumer. A filesystem event may be coalesced away, but a queued
// SIGHUP event must survive: systemd is waiting on that exact reload cycle.
func TestSendReloadNeverDropsAQueuedSignal(t *testing.T) {
	r := NewReloader("unused")
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 2000; i++ {
			r.sendReload(ReloadEvent{Trigger: ReloadTriggerFile})
		}
	}()
	r.sendReload(ReloadEvent{Trigger: ReloadTriggerSignal})
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("sendReload did not converge under a stalled consumer")
	}
	select {
	case event := <-r.reloads:
		if event.Trigger != ReloadTriggerSignal {
			t.Fatalf("queued SIGHUP event was displaced by %v", event.Trigger)
		}
	default:
		t.Fatal("queued SIGHUP event was dropped entirely")
	}
}

// TestSendReloadSignalReplacesSignal keeps the newest SIGHUP when the consumer
// has not drained the previous one; delivering one verdict per outstanding
// reload job is what systemd waits on.
func TestSendReloadSignalReplacesSignal(t *testing.T) {
	r := NewReloader("unused")
	first := &Config{}
	second := &Config{}
	r.sendReload(ReloadEvent{Config: first, Trigger: ReloadTriggerSignal})
	r.sendReload(ReloadEvent{Config: second, Trigger: ReloadTriggerSignal})
	select {
	case event := <-r.reloads:
		if event.Config != second {
			t.Fatal("newest SIGHUP event was not the one queued")
		}
	default:
		t.Fatal("no SIGHUP event queued")
	}
	select {
	case event := <-r.reloads:
		t.Fatalf("a second event remained queued: %+v", event)
	default:
	}
}
