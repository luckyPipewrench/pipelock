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
	instanceID string
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

// ReloadSinks atomically replaces the sink set and returns the old sinks.
// The caller is responsible for closing the returned sinks.
// This enables hot-reload of emit configuration without restarting.
func (e *Emitter) ReloadSinks(newSinks []Sink) []Sink {
	e.mu.Lock()
	defer e.mu.Unlock()
	old := e.sinks
	e.sinks = append([]Sink(nil), newSinks...)
	return old
}

// Close closes all sinks and returns the first error encountered.
func (e *Emitter) Close() error {
	if e == nil {
		return nil
	}

	e.mu.Lock()
	sinks := e.sinks
	e.sinks = nil
	e.mu.Unlock()

	var firstErr error
	for _, s := range sinks {
		if err := s.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
