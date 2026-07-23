// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package emit

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestEmitterSinkHealthIncludesAllBuiltInSinks(t *testing.T) {
	webhook := &WebhookSink{queue: make(chan Event, 3)}
	webhook.delivered.Store(2)
	webhook.failed.Store(1)
	webhook.degraded.Store(true)
	webhook.lastErr = "HTTP 500"

	syslog := &SyslogSink{queue: make(chan syslogMessage, 5)}
	syslog.dropped.Store(3)
	syslog.degraded.Store(true)
	syslog.lastErr = "queue_full"

	otlp := &OTLPSink{queue: make(chan Event, 7)}
	otlp.abandoned.Store(4)
	otlp.degraded.Store(true)
	otlp.lastErr = "drain_timeout"

	emitter := NewEmitter("test", webhook, NewFilteringSink(syslog, Filter{Actions: []string{"block"}}), otlp)
	got := emitter.SinkHealth()
	if len(got) != 3 {
		t.Fatalf("SinkHealth() = %+v, want three built-in sinks", got)
	}

	byName := make(map[string]SinkHealth, len(got))
	for _, health := range got {
		byName[health.Sink] = health
	}
	if health := byName[SinkWebhook]; health.Delivered != 2 || health.Failed != 1 || !health.Degraded || !health.LastErrorPresent || health.QueueCap != 3 {
		t.Errorf("webhook health = %+v", health)
	}
	if health := byName[SinkSyslog]; health.Dropped != 3 || !health.Degraded || !health.LastErrorPresent || health.QueueCap != 5 {
		t.Errorf("syslog health = %+v", health)
	}
	if health := byName[SinkOTLP]; health.Abandoned != 4 || !health.Degraded || !health.LastErrorPresent || health.QueueCap != 7 {
		t.Errorf("otlp health = %+v", health)
	}
}

func TestEmitterSinkHealthAggregatesDuplicateSinkTypes(t *testing.T) {
	first := &WebhookSink{queue: make(chan Event, 2)}
	first.delivered.Store(2)
	second := &WebhookSink{queue: make(chan Event, 3)}
	second.dropped.Store(1)
	second.degraded.Store(true)
	second.lastErr = "queue_full"

	got := NewEmitter("test", first, second).SinkHealth()
	if len(got) != 1 {
		t.Fatalf("SinkHealth() = %+v, want one aggregated webhook series", got)
	}
	if got[0].Sink != SinkWebhook || got[0].Delivered != 2 || got[0].Dropped != 1 || got[0].QueueCap != 5 || !got[0].Degraded || !got[0].LastErrorPresent {
		t.Fatalf("aggregated health = %+v", got[0])
	}
}

func TestEmitterSinkHealthNilAndUnknown(t *testing.T) {
	var nilEmitter *Emitter
	if got := nilEmitter.SinkHealth(); got != nil {
		t.Fatalf("nil emitter health = %+v, want nil", got)
	}
	if got := NewEmitter("test", &mockSink{}).SinkHealth(); len(got) != 0 {
		t.Fatalf("unknown sink health = %+v, want empty", got)
	}
	var filtered *FilteringSink
	if got := filtered.SinkHealth(); got != (SinkHealth{}) {
		t.Fatalf("nil filtered sink health = %+v, want zero", got)
	}
}

func TestEmitterSinkHealthKeepsReloadingSinkVisibleThroughDrain(t *testing.T) {
	old := &WebhookSink{queue: make(chan Event, 2)}
	old.delivered.Store(2)
	current := &WebhookSink{queue: make(chan Event, 3)}
	current.delivered.Store(1)
	emitter := NewEmitter("test", old)

	retired := emitter.ReloadSinks([]Sink{current})
	retiredSinks := retired.Sinks()
	if len(retiredSinks) != 1 || retiredSinks[0] != old {
		t.Fatalf("ReloadSinks() retired = %+v, want old webhook", retiredSinks)
	}

	// This is the real reload ordering: the replacement is published before
	// the old sink drains. Any abandonment during that drain must remain visible
	// instead of disappearing behind the fresh sink's zeroed counters.
	old.recordAbandoned(2)
	health := emitter.SinkHealth()
	if len(health) != 1 {
		t.Fatalf("SinkHealth() = %+v, want one aggregated webhook series", health)
	}
	if health[0].Delivered != 3 || health[0].Abandoned != 2 || !health[0].Degraded || !health[0].LastErrorPresent {
		t.Fatalf("reload drain health = %+v, want old and current sink state aggregated", health[0])
	}

	emitter.FinalizeRetiredSinks(retired)
	health = emitter.SinkHealth()
	if len(health) != 1 || health[0].Delivered != 3 || health[0].Abandoned != 2 {
		t.Fatalf("finalized reload health = %+v, want process-lifetime counters preserved", health)
	}
	if health[0].Degraded || health[0].LastErrorPresent || health[0].QueueCap != 3 {
		t.Fatalf("finalized reload gauges = %+v, want only current sink state", health[0])
	}
}

func TestEmitterFinalizeRetiredSinksDefensiveGuards(t *testing.T) {
	t.Run("nil generation is a no-op", func(t *testing.T) {
		emitter := NewEmitter("test")
		// Keep a nil entry tracked so removing the explicit nil guard would
		// select and dereference it instead of remaining a no-op.
		emitter.retiring = []*RetiredSinks{nil}

		emitter.FinalizeRetiredSinks(nil)

		if len(emitter.retiring) != 1 || emitter.retiring[0] != nil {
			t.Fatalf("retiring generations = %+v, want tracked nil entry unchanged", emitter.retiring)
		}
		if emitter.retired != nil {
			t.Fatalf("retired totals = %+v, want nil", emitter.retired)
		}
	})

	t.Run("already finalized generation is ignored", func(t *testing.T) {
		old := &WebhookSink{queue: make(chan Event, 1)}
		old.delivered.Store(3)
		emitter := NewEmitter("test", old)
		generation := emitter.ReloadSinks(nil)

		emitter.FinalizeRetiredSinks(generation)
		emitter.FinalizeRetiredSinks(generation)

		health := emitter.SinkHealth()
		if len(health) != 1 || health[0].Sink != SinkWebhook || health[0].Delivered != 3 {
			t.Fatalf("SinkHealth() = %+v, want webhook delivered=3 counted once", health)
		}
		if len(emitter.retiring) != 0 {
			t.Fatalf("retiring generations = %+v, want empty", emitter.retiring)
		}
	})
}

func TestEmitterSinkHealthPreservesLateRetiringFailureAcrossShutdown(t *testing.T) {
	old := &interleavingHealthSink{
		closeStarted: make(chan struct{}),
		releaseClose: make(chan struct{}),
	}
	current := &interleavingHealthSink{}
	emitter := NewEmitter("test", old)
	retired := emitter.ReloadSinks([]Sink{current})

	oldCloseDone := make(chan struct{})
	go func() {
		defer close(oldCloseDone)
		for _, sink := range retired.Sinks() {
			_ = sink.Close()
		}
		emitter.FinalizeRetiredSinks(retired)
	}()

	select {
	case <-old.closeStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("retiring sink did not start closing")
	}
	if err := emitter.Close(); err != nil {
		t.Fatalf("Emitter.Close() error = %v", err)
	}

	// The retiring generation records these counters only after shutdown has
	// finished closing and finalizing the current generation.
	close(old.releaseClose)
	select {
	case <-oldCloseDone:
	case <-time.After(2 * time.Second):
		t.Fatal("retiring sink did not finish closing")
	}

	health := emitter.SinkHealth()
	if len(health) != 1 || health[0].Failed != 1 || health[0].Abandoned != 2 {
		t.Fatalf("SinkHealth() = %+v, want late failed=1 and abandoned=2 preserved", health)
	}
}

type interleavingHealthSink struct {
	closeStarted chan struct{}
	releaseClose chan struct{}
	failed       atomic.Uint64
	abandoned    atomic.Uint64
}

func (*interleavingHealthSink) Emit(context.Context, Event) error { return nil }

func (s *interleavingHealthSink) Close() error {
	if s.closeStarted == nil {
		return nil
	}
	close(s.closeStarted)
	<-s.releaseClose
	s.failed.Add(1)
	s.abandoned.Add(2)
	return nil
}

func (s *interleavingHealthSink) SinkHealth() SinkHealth {
	return SinkHealth{
		Sink:      SinkWebhook,
		Failed:    s.failed.Load(),
		Abandoned: s.abandoned.Load(),
	}
}
