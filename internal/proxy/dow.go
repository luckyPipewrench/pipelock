// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"crypto/sha256"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// DoW budget type constants.
const (
	BudgetLoop       = "loop_detected"
	BudgetRunaway    = "runaway_expansion"
	BudgetCycle      = "cycle_detected"
	BudgetRetry      = "retry_storm"
	BudgetFanOut     = "fan_out"
	BudgetConcurrent = "concurrent_limit"
	BudgetWallClock  = "wall_clock"
	BudgetToolCalls  = "tool_call_limit"
)

// DoWConfig configures denial-of-wallet detection thresholds.
// Zero values for limit fields mean unlimited (disabled).
type DoWConfig struct {
	MaxToolCallsPerSession int    `yaml:"max_tool_calls_per_session"`
	MaxConcurrentToolCalls int    `yaml:"max_concurrent_tool_calls"`
	MaxWallClockMinutes    int    `yaml:"max_wall_clock_minutes"`
	MaxRetriesPerTool      int    `yaml:"max_retries_per_tool"`
	LoopDetectionWindow    int    `yaml:"loop_detection_window"`
	FanOutLimit            int    `yaml:"fan_out_limit"`
	FanOutWindowSeconds    int    `yaml:"fan_out_window_seconds"`
	Action                 string `yaml:"action"` // "block" or "warn"
}

// DoWResult is the outcome of a DoW budget check.
type DoWResult struct {
	Allowed    bool   // true if the action is within budget
	Reason     string // human-readable explanation when blocked
	BudgetType string // which budget was exceeded (one of the Budget* constants)
}

// toolCallEntry records a tool call for loop/cycle detection.
type toolCallEntry struct {
	name     string
	argsHash string
	argsLen  int
	at       time.Time
}

// endpointEntry records an endpoint access for fan-out/retry detection.
type endpointEntry struct {
	domain string
	path   string
	status int
	at     time.Time
}

// DoWTracker tracks denial-of-wallet signals for a single session.
// Thread-safe via mutex for all state except inflight (atomic).
type DoWTracker struct {
	mu     sync.Mutex
	cfg    DoWConfig
	start  time.Time
	closed bool

	// Tool call tracking (sliding window).
	toolCalls      []toolCallEntry
	totalToolCalls int

	// Endpoint tracking (sliding window for fan-out and retry).
	endpoints []endpointEntry

	// Concurrent call tracking.
	inflight atomic.Int32
}

// NewDoWTracker creates a tracker with the given configuration.
func NewDoWTracker(cfg DoWConfig) *DoWTracker {
	return &DoWTracker{
		cfg:   cfg,
		start: time.Now(),
	}
}

// RecordToolCall records a tool invocation and checks for loop, runaway,
// and cycle patterns. Returns a DoWResult indicating whether the call is
// allowed. The argsJSON is the raw JSON arguments string.
func (t *DoWTracker) RecordToolCall(toolName, argsJSON string) DoWResult {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return DoWResult{Allowed: false, Reason: "session closed", BudgetType: BudgetWallClock}
	}

	now := time.Now()
	entry := toolCallEntry{
		name:     toolName,
		argsHash: hashArgs(argsJSON),
		argsLen:  len(argsJSON),
		at:       now,
	}

	t.totalToolCalls++
	t.toolCalls = append(t.toolCalls, entry)

	// Trim window to configured size.
	window := t.cfg.LoopDetectionWindow
	if window <= 0 {
		window = 20 // default window size
	}
	if len(t.toolCalls) > window {
		t.toolCalls = t.toolCalls[len(t.toolCalls)-window:]
	}

	// Check total tool call limit.
	if t.cfg.MaxToolCallsPerSession > 0 && t.totalToolCalls > t.cfg.MaxToolCallsPerSession {
		return DoWResult{
			Allowed:    false,
			Reason:     fmt.Sprintf("tool call limit exceeded: %d/%d", t.totalToolCalls, t.cfg.MaxToolCallsPerSession),
			BudgetType: BudgetToolCalls,
		}
	}

	// Check wall clock.
	if t.cfg.MaxWallClockMinutes > 0 {
		elapsed := now.Sub(t.start)
		limit := time.Duration(t.cfg.MaxWallClockMinutes) * time.Minute
		if elapsed > limit {
			return DoWResult{
				Allowed:    false,
				Reason:     fmt.Sprintf("wall clock budget exceeded: %s/%s", elapsed.Truncate(time.Second), limit),
				BudgetType: BudgetWallClock,
			}
		}
	}

	// Check loop: same (name, argsHash) repeated N times in window.
	if r := t.checkLoop(entry); !r.Allowed {
		return r
	}

	// Check runaway expansion: monotonically increasing args size for same tool.
	if r := t.checkRunaway(entry); !r.Allowed {
		return r
	}

	// Check cycle: A->B->A->B pattern.
	if r := t.checkCycle(); !r.Allowed {
		return r
	}

	return DoWResult{Allowed: true}
}

// RecordEndpoint records an HTTP endpoint access for fan-out and retry
// detection. status is the HTTP response status code (0 for unknown).
func (t *DoWTracker) RecordEndpoint(domain, path string, status int) DoWResult {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return DoWResult{Allowed: false, Reason: "session closed", BudgetType: BudgetWallClock}
	}

	now := time.Now()
	entry := endpointEntry{
		domain: domain,
		path:   path,
		status: status,
		at:     now,
	}

	t.endpoints = append(t.endpoints, entry)

	// Trim endpoints to fan-out window.
	windowSec := t.cfg.FanOutWindowSeconds
	if windowSec <= 0 {
		windowSec = 60 // default: 60 seconds
	}
	cutoff := now.Add(-time.Duration(windowSec) * time.Second)
	t.endpoints = pruneEndpoints(t.endpoints, cutoff)

	// Check fan-out: too many unique endpoints in window.
	if r := t.checkFanOut(); !r.Allowed {
		return r
	}

	// Check retry storm: same endpoint with non-2xx responses.
	if r := t.checkRetryStorm(domain, path); !r.Allowed {
		return r
	}

	return DoWResult{Allowed: true}
}

// AcquireConcurrent attempts to increment the in-flight counter. Returns
// a DoWResult indicating success. Call ReleaseConcurrent when the call
// completes.
func (t *DoWTracker) AcquireConcurrent() DoWResult {
	// Check closed flag under mutex (fail-closed after shutdown).
	t.mu.Lock()
	closed := t.closed
	t.mu.Unlock()

	if closed {
		return DoWResult{Allowed: false, Reason: "tracker closed", BudgetType: BudgetConcurrent}
	}

	cfgLimit := t.cfg.MaxConcurrentToolCalls
	if cfgLimit <= 0 {
		cfgLimit = 10 // default limit
	}
	limit := int32(min(cfgLimit, 1<<30)) // cap to prevent int32 overflow

	current := t.inflight.Add(1)
	if current > limit {
		t.inflight.Add(-1) // roll back
		return DoWResult{
			Allowed:    false,
			Reason:     fmt.Sprintf("concurrent tool call limit exceeded: %d/%d", current, limit),
			BudgetType: BudgetConcurrent,
		}
	}
	return DoWResult{Allowed: true}
}

// ReleaseConcurrent decrements the in-flight counter. No-op if closed
// (prevents decrementing below zero after shutdown).
func (t *DoWTracker) ReleaseConcurrent() {
	t.mu.Lock()
	closed := t.closed
	t.mu.Unlock()

	if closed {
		return
	}
	t.inflight.Add(-1)
}

// Inflight returns the current number of in-flight tool calls.
func (t *DoWTracker) Inflight() int {
	return int(t.inflight.Load())
}

// TotalToolCalls returns the total number of tool calls recorded.
func (t *DoWTracker) TotalToolCalls() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.totalToolCalls
}

// Close marks the tracker as closed. All subsequent checks return blocked.
func (t *DoWTracker) Close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed = true
}

// checkLoop checks for repeated identical tool calls in the window.
func (t *DoWTracker) checkLoop(current toolCallEntry) DoWResult {
	maxRetries := t.cfg.MaxRetriesPerTool
	if maxRetries <= 0 {
		maxRetries = 5 // default
	}

	count := 0
	for _, tc := range t.toolCalls {
		if tc.name == current.name && tc.argsHash == current.argsHash {
			count++
		}
	}

	if count > maxRetries {
		return DoWResult{
			Allowed:    false,
			Reason:     fmt.Sprintf("loop detected: %s called %d times with same args (limit %d)", current.name, count, maxRetries),
			BudgetType: BudgetLoop,
		}
	}
	return DoWResult{Allowed: true}
}

// checkRunaway looks for monotonically increasing argument sizes for the
// same tool name. Three consecutive increases = runaway expansion.
const minRunawaySteps = 3

func (t *DoWTracker) checkRunaway(current toolCallEntry) DoWResult {
	// Gather recent calls for the same tool.
	var sizes []int
	for _, tc := range t.toolCalls {
		if tc.name == current.name {
			sizes = append(sizes, tc.argsLen)
		}
	}

	if len(sizes) < minRunawaySteps+1 {
		return DoWResult{Allowed: true}
	}

	// Check the last (minRunawaySteps+1) entries for strictly increasing pattern.
	recent := sizes[len(sizes)-minRunawaySteps-1:]
	increasing := true
	for i := 1; i < len(recent); i++ {
		if recent[i] <= recent[i-1] {
			increasing = false
			break
		}
	}

	if increasing {
		return DoWResult{
			Allowed:    false,
			Reason:     fmt.Sprintf("runaway expansion: %s args size increasing over %d calls", current.name, minRunawaySteps+1),
			BudgetType: BudgetRunaway,
		}
	}
	return DoWResult{Allowed: true}
}

// checkCycle detects A->B->A->B bidirectional loop patterns.
// Requires at least 4 entries with alternating tool names.
const minCycleLength = 4

func (t *DoWTracker) checkCycle() DoWResult {
	n := len(t.toolCalls)
	if n < minCycleLength {
		return DoWResult{Allowed: true}
	}

	// Check the last 4 entries for alternating pattern.
	recent := t.toolCalls[n-minCycleLength:]
	a := recent[0].name
	b := recent[1].name

	if a == b {
		return DoWResult{Allowed: true}
	}

	if recent[2].name == a && recent[3].name == b {
		return DoWResult{
			Allowed:    false,
			Reason:     fmt.Sprintf("cycle detected: %s -> %s -> %s -> %s", a, b, a, b),
			BudgetType: BudgetCycle,
		}
	}

	return DoWResult{Allowed: true}
}

// checkFanOut checks for too many unique endpoints in the window.
func (t *DoWTracker) checkFanOut() DoWResult {
	limit := t.cfg.FanOutLimit
	if limit <= 0 {
		limit = 50 // default
	}

	unique := make(map[string]struct{})
	for _, ep := range t.endpoints {
		key := ep.domain + "/" + ep.path
		unique[key] = struct{}{}
	}

	if len(unique) > limit {
		return DoWResult{
			Allowed:    false,
			Reason:     fmt.Sprintf("fan-out: %d unique endpoints in window (limit %d)", len(unique), limit),
			BudgetType: BudgetFanOut,
		}
	}
	return DoWResult{Allowed: true}
}

// checkRetryStorm checks for repeated requests to the same endpoint with
// non-2xx status codes, indicating the agent is retrying a failing endpoint.
func (t *DoWTracker) checkRetryStorm(domain, path string) DoWResult {
	// Count non-2xx responses for this endpoint in the window.
	const maxEndpointRetries = 20 // default: max 20 retries per endpoint

	failCount := 0
	for _, ep := range t.endpoints {
		if ep.domain == domain && ep.path == path && (ep.status < 200 || ep.status >= 300) {
			failCount++
		}
	}

	if failCount > maxEndpointRetries {
		return DoWResult{
			Allowed:    false,
			Reason:     fmt.Sprintf("retry storm: %s%s failed %d times (limit %d)", domain, path, failCount, maxEndpointRetries),
			BudgetType: BudgetRetry,
		}
	}
	return DoWResult{Allowed: true}
}

// hashArgs returns a hex-encoded SHA-256 of the argument string.
// Truncated to 16 chars for space efficiency in the sliding window.
const argsHashLen = 16

func hashArgs(args string) string {
	h := sha256.Sum256([]byte(args))
	return fmt.Sprintf("%x", h[:argsHashLen/2])
}

// pruneEndpoints removes entries older than cutoff from the slice.
func pruneEndpoints(entries []endpointEntry, cutoff time.Time) []endpointEntry {
	pruned := entries[:0]
	for _, e := range entries {
		if e.at.After(cutoff) {
			pruned = append(pruned, e)
		}
	}
	return pruned
}
