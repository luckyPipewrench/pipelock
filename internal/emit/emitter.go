// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package emit

import (
	"context"
	"fmt"
	"os"
	"slices"
	"sync"
	"time"
)

// Emitter fans out audit events to multiple sinks.
// All methods are safe for concurrent use.
type Emitter struct {
	mu         sync.RWMutex
	sinks      []Sink
	retiring   []*RetiredSinks
	retired    map[string]SinkHealth
	instanceID string
}

// RetiredSinks identifies one sink generation replaced by ReloadSinks.
// Callers close Sinks before passing the generation to FinalizeRetiredSinks.
type RetiredSinks struct {
	sinks []Sink
}

// Sinks returns the sinks owned by this retired generation.
func (r *RetiredSinks) Sinks() []Sink {
	if r == nil {
		return nil
	}
	return append([]Sink(nil), r.sinks...)
}

// NewEmitter creates an Emitter that sends events to all provided sinks.
func NewEmitter(instanceID string, sinks ...Sink) *Emitter {
	return &Emitter{
		sinks:      append([]Sink(nil), sinks...),
		instanceID: instanceID,
	}
}

// Emit sends an event to all sinks with severity looked up from EventSeverity.
// Unknown event types default to SeverityInfo.
// Errors from individual sinks are ignored (fire-and-forget).
func (e *Emitter) Emit(ctx context.Context, eventType string, fields map[string]any) {
	if e == nil {
		return
	}

	sev, ok := EventSeverity[eventType]
	if !ok {
		sev = SeverityInfo
	}

	e.EmitWithSeverity(ctx, sev, eventType, fields)
}

// EmitWithSeverity sends an event with an explicit severity to all sinks.
// Use this for events whose severity depends on runtime context
// (e.g., chain detection action, escalation target level).
// Errors from individual sinks are ignored (fire-and-forget).
func (e *Emitter) EmitWithSeverity(ctx context.Context, sev Severity, eventType string, fields map[string]any) {
	if e == nil {
		return
	}

	var copied map[string]any
	if fields != nil {
		copied = make(map[string]any, len(fields))
		for k, v := range fields {
			copied[k] = v
		}
	}

	event := Event{
		Severity:   sev,
		Type:       eventType,
		Timestamp:  time.Now(),
		InstanceID: e.instanceID,
		Fields:     copied,
	}

	e.mu.RLock()
	sinks := e.sinks
	e.mu.RUnlock()

	for _, s := range sinks {
		if err := s.Emit(ctx, event); err != nil && !isExpectedSinkStatus(err) {
			fmt.Fprintf(os.Stderr, "emit: sink error (event=%s): %v\n", eventType, err)
		}
	}
}

// isExpectedSinkStatus reports whether err is an exact routine, already-accounted
// sink status: a queue-full drop or a degraded advisory. Each built-in sink
// returns these sentinels directly after reflecting the status in Stats(). A
// wrapped or joined error may carry a distinct failure and must remain visible.
func isExpectedSinkStatus(err error) bool {
	// Exact identity match, deliberately NOT errors.Is: a wrapped or joined error
	// (e.g. errors.Join(ErrQueueFull, realErr)) may carry a distinct failure and
	// must stay visible. slices.Contains compares by ==, so only a bare sentinel
	// is treated as a routine, already-accounted status.
	return slices.Contains(routineSinkStatuses, err)
}

// routineSinkStatuses are the exact sentinels a sink returns for a queue-full
// drop or a degraded advisory, both already reflected in the sink's Stats().
var routineSinkStatuses = []error{
	ErrQueueFull, ErrSyslogQueueFull, ErrOTLPQueueFull,
	ErrWebhookDegraded, ErrSyslogDegraded, ErrOTLPDegraded,
}

// ReloadSinks atomically replaces the sink set and returns the old generation.
// The caller is responsible for closing the generation's sinks and finalizing
// that generation afterward.
// This enables hot-reload of emit configuration without restarting.
func (e *Emitter) ReloadSinks(newSinks []Sink) *RetiredSinks {
	e.mu.Lock()
	defer e.mu.Unlock()
	old := e.sinks
	e.sinks = append([]Sink(nil), newSinks...)
	// Keep the old generation visible until its asynchronous queues have been
	// drained and the caller finalizes it. Otherwise failures and abandonments
	// recorded by Close after this swap disappear from live sink-health metrics.
	return e.retireSinksLocked(old)
}

// FinalizeRetiredSinks snapshots the terminal delivery counters of sink
// generation returned by ReloadSinks and releases its objects. Callers must
// invoke it after that generation's sinks have finished closing. Retired
// counters remain process-lifetime cumulative so Prometheus _total series never
// reset on a config reload; queue and degraded gauges continue to describe only
// live or actively draining sinks.
func (e *Emitter) FinalizeRetiredSinks(generation *RetiredSinks) {
	if e == nil || generation == nil {
		return
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	index := slices.Index(e.retiring, generation)
	if index < 0 {
		return
	}
	if e.retired == nil {
		e.retired = make(map[string]SinkHealth)
	}
	for _, sink := range generation.sinks {
		provider, ok := sink.(sinkHealthProvider)
		if !ok {
			continue
		}
		current := provider.SinkHealth()
		if current.Sink == "" {
			continue
		}
		total := e.retired[current.Sink]
		total.Sink = current.Sink
		total.Delivered += current.Delivered
		total.Failed += current.Failed
		total.Dropped += current.Dropped
		total.Abandoned += current.Abandoned
		e.retired[current.Sink] = total
	}
	e.retiring = slices.Delete(e.retiring, index, index+1)
}

// retireSinksLocked moves sinks into a separately owned draining generation.
// e.mu must be held by the caller.
func (e *Emitter) retireSinksLocked(sinks []Sink) *RetiredSinks {
	generation := &RetiredSinks{sinks: sinks}
	if len(sinks) > 0 {
		e.retiring = append(e.retiring, generation)
	}
	return generation
}

// Close closes all sinks and returns the first error encountered.
func (e *Emitter) Close() error {
	if e == nil {
		return nil
	}

	e.mu.Lock()
	sinks := e.sinks
	e.sinks = nil
	generation := e.retireSinksLocked(sinks)
	e.mu.Unlock()

	var firstErr error
	for _, s := range sinks {
		if err := s.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	e.FinalizeRetiredSinks(generation)
	return firstErr
}
