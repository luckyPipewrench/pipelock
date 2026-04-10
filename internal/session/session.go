// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package session provides shared session types for adaptive enforcement.
// Both internal/proxy and internal/mcp import this package; it must not import
// either to avoid circular dependencies.
package session

import (
	"fmt"
	"sync/atomic"
	"time"
)

// SignalType identifies a threat signal for adaptive enforcement.
type SignalType int

const (
	SignalBlock         SignalType = iota // +3 — hard block from any scanner/transport
	SignalNearMiss                        // +1 — warn-level finding from any scanner/transport
	SignalDomainAnomaly                   // +2 — domain burst detection
	SignalEntropyBudget                   // +2 — CEE entropy exceeded
	SignalFragmentDLP                     // +3 — CEE fragment reassembly found secret
	SignalStrip                           // +2 — active mitigation, repeated stripping = sustained attack
)

// SignalPoints maps signal types to their score contribution.
var SignalPoints = map[SignalType]float64{
	SignalBlock:         3.0,
	SignalNearMiss:      1.0,
	SignalDomainAnomaly: 2.0,
	SignalEntropyBudget: 2.0,
	SignalFragmentDLP:   3.0,
	SignalStrip:         2.0,
}

// escalationLabels maps escalation levels to human-readable names.
// Level 3 and above all map to the last entry ("critical").
var escalationLabels = []string{"normal", "elevated", "high", "critical"}

// EscalationLabel returns the human-readable name for an escalation level.
// Negative levels return "normal". Levels beyond the defined range return
// "critical" (the last defined label).
func EscalationLabel(level int) string {
	if level < 0 {
		return escalationLabels[0] // "normal"
	}
	if level >= len(escalationLabels) {
		return escalationLabels[len(escalationLabels)-1] // "critical"
	}
	return escalationLabels[level]
}

// Recorder tracks adaptive enforcement signals for a session.
type Recorder interface {
	RecordSignal(sig SignalType, threshold float64) (escalated bool, from, to string)
	RecordClean(decayRate float64)
	EscalationLevel() int
	ThreatScore() float64
}

// Store manages session lifecycle.
type Store interface {
	GetOrCreate(key string) Recorder
}

// TaskContext describes the current task boundary attached to a live session.
type TaskContext struct {
	CurrentTaskID    string
	CurrentTaskLabel string
	StartedAt        time.Time
	LastBoundaryAt   time.Time
}

// TaskContextProvider exposes task-boundary context and runtime trust
// overrides without coupling callers to the proxy package.
type TaskContextProvider interface {
	TaskSnapshot() TaskContext
	RuntimeTrustOverrides() []TrustOverride
}

// ToolFreezer checks whether a tool call is permitted under a frozen tool
// inventory. Used by MCP proxy paths to enforce airlock hard-tier restrictions
// without importing the proxy package (which would create a circular dep).
type ToolFreezer interface {
	IsFrozen(stableKey string) bool
	IsToolAllowed(stableKey, toolName string) bool
}

// invocationCounter provides unique per-invocation session keys for MCP
// transports. A single atomic counter avoids lock contention when many stdio
// subprocesses start concurrently.
var invocationCounter atomic.Uint64

// taskCounter provides unique task identifiers scoped to the current process.
var taskCounter atomic.Uint64

// NextInvocationKey returns a unique session key with the given prefix.
// Format: "<prefix>-<n>" where n is a monotonically increasing integer.
// Safe for concurrent use.
func NextInvocationKey(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, invocationCounter.Add(1))
}

// NextTaskID returns a unique pipelock-owned task identifier.
func NextTaskID() string {
	return fmt.Sprintf("task-%d", taskCounter.Add(1))
}
