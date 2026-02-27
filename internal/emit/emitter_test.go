package emit

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// mockSink records events and can be configured to return errors.
type mockSink struct {
	mu     sync.Mutex
	events []Event
	err    error
	closed bool
}

func (m *mockSink) Emit(_ context.Context, event Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, event)
	return m.err
}

func (m *mockSink) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return m.err
}

func (m *mockSink) getEvents() []Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]Event, len(m.events))
	copy(cp, m.events)
	return cp
}

func (m *mockSink) isClosed() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closed
}

func TestEmitter_FanOut(t *testing.T) {
	s1 := &mockSink{}
	s2 := &mockSink{}
	s3 := &mockSink{}

	em := NewEmitter("test-host", s1, s2, s3)

	em.Emit(context.Background(), "blocked", map[string]any{"url": "https://evil.com"})

	for i, s := range []*mockSink{s1, s2, s3} {
		events := s.getEvents()
		if len(events) != 1 {
			t.Errorf("sink %d: got %d events, want 1", i, len(events))
			continue
		}
		if events[0].Type != "blocked" { //nolint:goconst // test value
			t.Errorf("sink %d: event type = %q, want %q", i, events[0].Type, "blocked")
		}
		if events[0].InstanceID != "test-host" {
			t.Errorf("sink %d: instance = %q, want %q", i, events[0].InstanceID, "test-host")
		}
	}

	_ = em.Close()
}

func TestEmitter_EmitLookupSeverity(t *testing.T) {
	tests := []struct {
		name      string
		eventType string
		wantSev   Severity
	}{
		{name: "known warn type", eventType: "blocked", wantSev: SeverityWarn},
		{name: "known critical type", eventType: "kill_switch_deny", wantSev: SeverityCritical},
		{name: "known info type", eventType: "allowed", wantSev: SeverityInfo},
		{name: "unknown defaults to info", eventType: "completely_unknown", wantSev: SeverityInfo},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &mockSink{}
			em := NewEmitter("test", s)

			em.Emit(context.Background(), tt.eventType, nil)

			events := s.getEvents()
			if len(events) != 1 {
				t.Fatalf("got %d events, want 1", len(events))
			}
			if events[0].Severity != tt.wantSev {
				t.Errorf("severity = %v, want %v", events[0].Severity, tt.wantSev)
			}
		})
	}
}

func TestEmitter_EmitWithSeverity(t *testing.T) {
	s := &mockSink{}
	em := NewEmitter("test", s)

	// Override severity for chain_detection which isn't in the map.
	em.EmitWithSeverity(context.Background(), SeverityCritical, "chain_detection", map[string]any{
		"action": "block",
	})

	events := s.getEvents()
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	if events[0].Severity != SeverityCritical {
		t.Errorf("severity = %v, want %v", events[0].Severity, SeverityCritical)
	}
	if events[0].Type != "chain_detection" {
		t.Errorf("type = %q, want %q", events[0].Type, "chain_detection")
	}

	_ = em.Close()
}

func TestEmitter_NilEmitter(t *testing.T) {
	var em *Emitter

	// Should not panic.
	em.Emit(context.Background(), "blocked", nil)
	em.EmitWithSeverity(context.Background(), SeverityCritical, "blocked", nil)

	if err := em.Close(); err != nil {
		t.Errorf("nil emitter Close() returned error: %v", err)
	}
}

func TestEmitter_EmptyEmitter(t *testing.T) {
	em := NewEmitter("test")

	// No sinks — should not panic.
	em.Emit(context.Background(), "blocked", nil)

	if err := em.Close(); err != nil {
		t.Errorf("empty emitter Close() returned error: %v", err)
	}
}

func TestEmitter_CloseCallsAllSinks(t *testing.T) {
	s1 := &mockSink{}
	s2 := &mockSink{}

	em := NewEmitter("test", s1, s2)
	err := em.Close()
	if err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	if !s1.isClosed() {
		t.Error("sink 1 was not closed")
	}
	if !s2.isClosed() {
		t.Error("sink 2 was not closed")
	}
}

func TestEmitter_CloseReturnsFirstError(t *testing.T) {
	errFirst := errors.New("first sink error")
	errSecond := errors.New("second sink error")

	s1 := &mockSink{err: errFirst}
	s2 := &mockSink{err: errSecond}

	em := NewEmitter("test", s1, s2)
	err := em.Close()

	if !errors.Is(err, errFirst) {
		t.Errorf("Close error = %v, want %v", err, errFirst)
	}

	// Both sinks should still be closed even though the first errored.
	if !s1.isClosed() {
		t.Error("sink 1 was not closed")
	}
	if !s2.isClosed() {
		t.Error("sink 2 was not closed")
	}
}

func TestEmitter_SinkErrorIgnoredOnEmit(t *testing.T) {
	s1 := &mockSink{err: errors.New("emit error")}
	s2 := &mockSink{}

	em := NewEmitter("test", s1, s2)

	// Should not panic despite s1 returning an error.
	em.Emit(context.Background(), "blocked", nil)

	// s2 should still receive the event.
	events := s2.getEvents()
	if len(events) != 1 {
		t.Errorf("sink 2 got %d events, want 1", len(events))
	}

	_ = em.Close()
}

func TestEmitter_EventTimestampIsSet(t *testing.T) {
	s := &mockSink{}
	em := NewEmitter("test", s)

	before := time.Now()
	em.Emit(context.Background(), "allowed", nil)

	events := s.getEvents()
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	if events[0].Timestamp.Before(before) {
		t.Error("event timestamp is before emission time")
	}

	_ = em.Close()
}

func TestEmitter_ReloadSinks(t *testing.T) {
	old1 := &mockSink{}
	old2 := &mockSink{}
	em := NewEmitter("test", old1, old2)

	// Emit to old sinks
	em.Emit(context.Background(), "blocked", nil)
	if len(old1.getEvents()) != 1 {
		t.Fatal("old sink 1 should have 1 event before reload")
	}

	// Reload with new sinks
	new1 := &mockSink{}
	returned := em.ReloadSinks([]Sink{new1})

	if len(returned) != 2 {
		t.Fatalf("expected 2 old sinks returned, got %d", len(returned))
	}

	// Close old sinks (caller responsibility)
	for _, s := range returned {
		_ = s.Close()
	}

	// Emit to new sinks
	em.Emit(context.Background(), "error", nil)
	if len(new1.getEvents()) != 1 {
		t.Errorf("new sink should have 1 event, got %d", len(new1.getEvents()))
	}
	// Old sinks should NOT receive the new event
	if len(old1.getEvents()) != 1 {
		t.Errorf("old sink 1 should still have 1 event, got %d", len(old1.getEvents()))
	}

	_ = em.Close()
}

func TestEmitter_ReloadSinks_ToEmpty(t *testing.T) {
	s := &mockSink{}
	em := NewEmitter("test", s)

	// Reload to zero sinks
	old := em.ReloadSinks(nil)
	if len(old) != 1 {
		t.Fatalf("expected 1 old sink, got %d", len(old))
	}
	for _, o := range old {
		_ = o.Close()
	}

	// Should not panic with zero sinks
	em.Emit(context.Background(), "blocked", nil)

	_ = em.Close()
}

func TestEmitter_ReloadSinks_FromEmpty(t *testing.T) {
	em := NewEmitter("test") // 0 sinks

	em.Emit(context.Background(), "blocked", nil) // no-op, no panic

	// Reload to add sinks
	s := &mockSink{}
	old := em.ReloadSinks([]Sink{s})
	if len(old) != 0 {
		t.Fatalf("expected 0 old sinks, got %d", len(old))
	}

	em.Emit(context.Background(), "error", nil)
	if len(s.getEvents()) != 1 {
		t.Errorf("new sink should have 1 event, got %d", len(s.getEvents()))
	}

	_ = em.Close()
}

func TestEmitter_ReloadSinks_Concurrent(t *testing.T) {
	s1 := &mockSink{}
	em := NewEmitter("test", s1)

	// Fire events concurrently while reloading
	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Emitters
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					em.Emit(context.Background(), "blocked", nil)
				}
			}
		}()
	}

	// Reloader
	for range 50 {
		newSink := &mockSink{}
		old := em.ReloadSinks([]Sink{newSink})
		for _, o := range old {
			_ = o.Close()
		}
	}

	close(stop)
	wg.Wait()
	_ = em.Close()
	// If we get here without a race detector failure, the test passes.
}

func TestEmitter_FieldsPassedThrough(t *testing.T) {
	s := &mockSink{}
	em := NewEmitter("test", s)

	fields := map[string]any{
		"url":    "https://evil.com",
		"reason": "blocklist",
		"score":  0.95,
	}
	em.Emit(context.Background(), "blocked", fields)

	events := s.getEvents()
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	if events[0].Fields["url"] != "https://evil.com" {
		t.Errorf("fields[url] = %v, want %q", events[0].Fields["url"], "https://evil.com")
	}
	if events[0].Fields["reason"] != "blocklist" {
		t.Errorf("fields[reason] = %v, want %q", events[0].Fields["reason"], "blocklist")
	}

	_ = em.Close()
}
