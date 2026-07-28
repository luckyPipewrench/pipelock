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
	BudgetConcurrent = "concurrent_limit"
	BudgetWallClock  = "wall_clock"
	BudgetToolCalls  = "tool_call_limit"
	BudgetSubjectCap = "subject_cap"
)

const (
	defaultDoWSubjectKey         = "_default"
	defaultDoWSubjectWindow      = 30 * time.Minute
	defaultDoWSubjectMaxSubjects = 10000
)

// DoWConfig configures denial-of-wallet detection thresholds.
// Zero values for limit fields mean unlimited (disabled).
type DoWConfig struct {
	MaxToolCallsPerSession int    `yaml:"max_tool_calls_per_session"`
	MaxConcurrentToolCalls int    `yaml:"max_concurrent_tool_calls"`
	MaxWallClockMinutes    int    `yaml:"max_wall_clock_minutes"`
	WindowMinutes          int    `yaml:"window_minutes"`
	MaxRetriesPerTool      int    `yaml:"max_retries_per_tool"`
	LoopDetectionWindow    int    `yaml:"loop_detection_window"`
	Action                 string `yaml:"action"` // "block" or "warn"
}

// DoWSubjectManagerConfig configures bounded per-subject DoW tracking.
type DoWSubjectManagerConfig struct {
	TrackerConfig DoWConfig
	// IdleTTL is retained as the default budget window when WindowMinutes is
	// unset. That preserves the old 30-minute retention expectation without
	// making spent subjects live forever.
	IdleTTL     time.Duration
	MaxSubjects int
	Now         func() time.Time
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

// DoWTracker tracks denial-of-wallet signals for a single budget subject.
// Thread-safe via mutex for all state except inflight (atomic).
type DoWTracker struct {
	mu     sync.Mutex
	cfg    DoWConfig
	start  time.Time
	now    func() time.Time
	closed bool

	// Tool call tracking (sliding window).
	toolCalls      []toolCallEntry
	totalToolCalls int

	// Concurrent call tracking.
	inflight atomic.Int32
}

type dowSubjectEntry struct {
	tracker     *DoWTracker
	windowStart time.Time
}

// DoWSubjectManager owns per-subject DoW trackers for multi-client listeners.
// MCP sessions remain registered separately as protocol trust material; they do
// not own quota.
type DoWSubjectManager struct {
	mu          sync.Mutex
	cfg         DoWConfig
	window      time.Duration
	maxSubjects int
	now         func() time.Time
	subjects    map[string]*dowSubjectEntry
	// nextExpiry is the earliest windowStart+window across subjects. Before it
	// passes, no subject can be expired, so the reap scan can be skipped.
	nextExpiry time.Time
}

// NewDoWTracker creates a tracker with the given configuration.
func NewDoWTracker(cfg DoWConfig) *DoWTracker {
	return newDoWTracker(cfg, time.Now)
}

func newDoWTracker(cfg DoWConfig, now func() time.Time) *DoWTracker {
	if now == nil {
		now = time.Now
	}
	return &DoWTracker{
		cfg:   cfg,
		start: now(),
		now:   now,
	}
}

// NewDoWSubjectManager creates a bounded per-subject DoW manager.
func NewDoWSubjectManager(cfg DoWSubjectManagerConfig) *DoWSubjectManager {
	window := time.Duration(cfg.TrackerConfig.WindowMinutes) * time.Minute
	if window <= 0 {
		window = cfg.IdleTTL
	}
	if window <= 0 {
		window = defaultDoWSubjectWindow
	}
	maxSubjects := cfg.MaxSubjects
	if maxSubjects <= 0 {
		maxSubjects = defaultDoWSubjectMaxSubjects
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &DoWSubjectManager{
		cfg:         cfg.TrackerConfig,
		window:      window,
		maxSubjects: maxSubjects,
		now:         now,
		subjects:    make(map[string]*dowSubjectEntry),
	}
}

// Check records a tool call against one subject. An empty key is the
// single-session transport bucket.
func (m *DoWSubjectManager) Check(subjectKey, toolName, argsJSON string) DoWResult {
	if m == nil {
		return DoWResult{Allowed: true}
	}
	if subjectKey == "" {
		subjectKey = defaultDoWSubjectKey
	}
	tracker, ok := m.trackerFor(subjectKey)
	if !ok {
		return DoWResult{
			Allowed:    false,
			Reason:     fmt.Sprintf("DoW subject cap reached: %d/%d", m.maxSubjects, m.maxSubjects),
			BudgetType: BudgetSubjectCap,
		}
	}
	return tracker.RecordToolCall(toolName, argsJSON)
}

// SubjectCount returns the current number of live subject buckets.
func (m *DoWSubjectManager) SubjectCount() int {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reapExpiredLocked(m.now())
	return len(m.subjects)
}

func (m *DoWSubjectManager) trackerFor(subjectKey string) (*DoWTracker, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	m.reapExpiredLocked(now)
	if entry, ok := m.subjects[subjectKey]; ok {
		return entry.tracker, true
	}
	if len(m.subjects) >= m.maxSubjects {
		return nil, false
	}
	tracker := newDoWTracker(m.cfg, m.now)
	m.subjects[subjectKey] = &dowSubjectEntry{tracker: tracker, windowStart: now}
	if expiry := now.Add(m.window); m.nextExpiry.IsZero() || expiry.Before(m.nextExpiry) {
		m.nextExpiry = expiry
	}
	return tracker, true
}

func (m *DoWSubjectManager) reapExpiredLocked(now time.Time) {
	// This runs from trackerFor, so it is on the path of every tool call. A
	// full scan each time serializes every subject on a listener behind one
	// mutex for a result that is almost always empty, which is worst exactly
	// when the table is large. Nothing can have expired before nextExpiry, so
	// the common call returns without touching the map.
	if !m.nextExpiry.IsZero() && now.Before(m.nextExpiry) {
		return
	}
	var earliest time.Time
	for key, entry := range m.subjects {
		expiry := entry.windowStart.Add(m.window)
		if !now.Before(expiry) {
			delete(m.subjects, key)
			continue
		}
		if earliest.IsZero() || expiry.Before(earliest) {
			earliest = expiry
		}
	}
	m.nextExpiry = earliest
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

	now := t.now()
	entry := toolCallEntry{
		name:     toolName,
		argsHash: hashArgs(argsJSON),
		argsLen:  len(argsJSON),
		at:       now,
	}

	t.totalToolCalls++
	t.toolCalls = append(t.toolCalls, entry)

	// Trim history to the configured window. If only a retry limit is
	// configured, retain the minimum entries needed to enforce that limit
	// without enabling unrelated pattern detectors by default.
	window := t.historyWindow()
	if window <= 0 {
		t.toolCalls = nil
	} else if len(t.toolCalls) > window {
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
	if t.cfg.MaxRetriesPerTool > 0 {
		if r := t.checkLoop(entry); !r.Allowed {
			return r
		}
	}

	if t.cfg.LoopDetectionWindow <= 0 {
		return DoWResult{Allowed: true}
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

func (t *DoWTracker) historyWindow() int {
	if t.cfg.LoopDetectionWindow > 0 {
		return t.cfg.LoopDetectionWindow
	}
	if t.cfg.MaxRetriesPerTool > 0 {
		return t.cfg.MaxRetriesPerTool + 1
	}
	return 0
}

// AcquireConcurrent attempts to increment the in-flight counter. Returns
// a DoWResult indicating success. Call ReleaseConcurrent when the call
// completes.
//
// The closed check and inflight increment are performed under the same
// mutex hold to prevent a race where Close() runs between checking the
// flag and incrementing inflight, which would admit a new acquisition
// after shutdown.
func (t *DoWTracker) AcquireConcurrent() DoWResult {
	cfgLimit := t.cfg.MaxConcurrentToolCalls
	if cfgLimit <= 0 {
		cfgLimit = 10 // default limit
	}
	limit := int32(min(cfgLimit, 1<<30)) // cap to prevent int32 overflow

	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return DoWResult{Allowed: false, Reason: "tracker closed", BudgetType: BudgetConcurrent}
	}

	current := t.inflight.Add(1)
	t.mu.Unlock()

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

// ReleaseConcurrent decrements the in-flight counter with underflow
// protection. Works correctly even after Close() so that in-flight
// calls acquired before shutdown can release their slots.
func (t *DoWTracker) ReleaseConcurrent() {
	for {
		cur := t.inflight.Load()
		if cur <= 0 {
			return
		}
		if t.inflight.CompareAndSwap(cur, cur-1) {
			return
		}
	}
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
		return DoWResult{Allowed: true}
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

// hashArgs returns a hex-encoded SHA-256 of the argument string.
// Truncated to 16 chars for space efficiency in the sliding window.
const argsHashLen = 16

func hashArgs(args string) string {
	h := sha256.Sum256([]byte(args))
	return fmt.Sprintf("%x", h[:argsHashLen/2])
}
