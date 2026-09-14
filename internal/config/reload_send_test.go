// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"path/filepath"
	"testing"
)

// TestSendReloadNeverDropsAQueuedSignal hammers the coalescing path with a
// stalled consumer. A filesystem event may be coalesced away, but a queued
// SIGHUP event must survive: systemd is waiting on that exact reload cycle.
func TestSendReloadNeverDropsAQueuedSignal(t *testing.T) {
	r := NewReloader("unused")
	// One producer, matching production: the reloader's watch loop is the only
	// caller. A concurrent second producer can drain the queued signal while
	// this one is mid-coalesce, which the function does not support and which
	// made an earlier version of this test hang instead of assert.
	r.sendReload(ReloadEvent{Trigger: ReloadTriggerSignal})
	for i := 0; i < 2000; i++ {
		r.sendReload(ReloadEvent{Trigger: ReloadTriggerFile})
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

// TestSendReloadCarriesTheNewestConfigUnderAQueuedSignal pins the half of the
// fold that a "keep the signal" rule on its own loses: the newest successfully
// loaded configuration still has to reach the runtime. Before this, the queued
// SIGHUP was requeued and the filesystem event was discarded with its config.
func TestSendReloadCarriesTheNewestConfigUnderAQueuedSignal(t *testing.T) {
	r := NewReloader("unused")
	signalled := &Config{}
	newest := &Config{}
	r.sendReload(ReloadEvent{Config: signalled, Trigger: ReloadTriggerSignal})
	r.sendReload(ReloadEvent{Config: newest, Trigger: ReloadTriggerFile})
	select {
	case event := <-r.reloads:
		if event.Trigger != ReloadTriggerSignal {
			t.Fatalf("trigger = %v, want the SIGHUP to survive so systemd still gets its verdict", event.Trigger)
		}
		if event.Config != newest {
			t.Fatal("the newest loaded configuration was dropped, so it would never be applied")
		}
	default:
		t.Fatal("no reload event was queued")
	}
}

// TestSendReloadReportsTheNewestFailure covers the other direction: when the
// newest attempt failed to load, that failure is what describes the file now,
// and the runtime answers it by keeping the running configuration.
func TestSendReloadReportsTheNewestFailure(t *testing.T) {
	r := NewReloader("unused")
	r.sendReload(ReloadEvent{Config: &Config{}, Trigger: ReloadTriggerSignal})
	r.sendReload(ReloadEvent{Err: errTestReloadLoad, Trigger: ReloadTriggerFile})
	select {
	case event := <-r.reloads:
		if event.Trigger != ReloadTriggerSignal {
			t.Fatalf("trigger = %v, want the SIGHUP preserved", event.Trigger)
		}
		if !errors.Is(event.Err, errTestReloadLoad) || event.Config != nil {
			t.Fatalf("event = %+v, want the newest load failure with no config", event)
		}
	default:
		t.Fatal("no reload event was queued")
	}
}

var errTestReloadLoad = errors.New("load failed")

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

// TestReloadsAccessorIsTheRuntimeChannel covers the accessor the runtime
// consumes; the fold's behaviour is pinned by the sendReload tests above.
func TestReloadsAccessorIsTheRuntimeChannel(t *testing.T) {
	r := NewReloader("/nonexistent/pipelock.yaml")
	if r.Reloads() == nil {
		t.Fatal("Reloads() returned a nil channel")
	}
	r.sendReload(ReloadEvent{Trigger: ReloadTriggerSignal})
	select {
	case got := <-r.Reloads():
		if got.Trigger != ReloadTriggerSignal {
			t.Fatalf("queued event trigger = %v, want the signal trigger", got.Trigger)
		}
	default:
		t.Fatal("no reload event was queued")
	}
}

// TestTryReloadFailedLoadEventContract pins what a failed load delivers. The
// runtime keys its systemd verdict on Err, so the event has to carry the
// requested trigger, a non-nil error and no configuration; and the legacy
// Changes() channel must stay empty, because a configuration that never loaded
// must not reach a consumer that has no error to check.
func TestTryReloadFailedLoadEventContract(t *testing.T) {
	for _, trigger := range []ReloadTrigger{ReloadTriggerSignal, ReloadTriggerFile} {
		r := NewReloader(filepath.Join(t.TempDir(), "absent.yaml"))
		r.tryReload(trigger)
		select {
		case event := <-r.Reloads():
			if event.Trigger != trigger {
				t.Fatalf("trigger = %v, want %v", event.Trigger, trigger)
			}
			if event.Err == nil {
				t.Fatal("a failed load delivered no error, so the runtime would treat it as applied")
			}
			if event.Config != nil {
				t.Fatalf("a failed load delivered a config: %+v", event.Config)
			}
		default:
			t.Fatal("a failed load delivered no reload event")
		}
		select {
		case cfg := <-r.Changes():
			t.Fatalf("a failed load reached the Changes channel: %+v", cfg)
		default:
		}
	}
}
