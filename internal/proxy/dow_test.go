// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	toolGetWeather = "get_weather"
	toolReadFile   = "read_file"
	toolWriteFile  = "write_file"
	argsNYC        = `{"city":"NYC"}`
	argsSF         = `{"city":"SF"}`
	actionBlock    = "block"
	actionWarn     = "warn"
)

func defaultDoWConfig() DoWConfig {
	return DoWConfig{
		MaxRetriesPerTool:      3,
		LoopDetectionWindow:    10,
		MaxConcurrentToolCalls: 5,
		MaxWallClockMinutes:    60,
		MaxToolCallsPerSession: 100,
		Action:                 actionBlock,
	}
}

// --- Loop Detection ---

func TestDoW_LoopDetection(t *testing.T) {
	tracker := NewDoWTracker(DoWConfig{
		MaxRetriesPerTool:   3,
		LoopDetectionWindow: 10,
		Action:              actionBlock,
	})

	// First 3 calls should be allowed (at limit).
	for i := range 3 {
		result := tracker.RecordToolCall(toolGetWeather, argsNYC)
		if !result.Allowed {
			t.Fatalf("call %d should be allowed, got blocked: %s", i, result.Reason)
		}
	}

	// 4th call with same args = loop detected.
	result := tracker.RecordToolCall(toolGetWeather, argsNYC)
	if result.Allowed {
		t.Error("4th identical call should be blocked")
	}
	if result.BudgetType != BudgetLoop {
		t.Errorf("BudgetType = %q, want %q", result.BudgetType, BudgetLoop)
	}
}

func TestDoW_LoopDetection_DifferentArgs(t *testing.T) {
	tracker := NewDoWTracker(DoWConfig{
		MaxRetriesPerTool:   3,
		LoopDetectionWindow: 10,
		Action:              actionBlock,
	})

	// Same tool but different args should not trigger loop.
	cities := []string{`{"city":"NYC"}`, `{"city":"LA"}`, `{"city":"SF"}`, `{"city":"CHI"}`}
	for _, args := range cities {
		result := tracker.RecordToolCall(toolGetWeather, args)
		if !result.Allowed {
			t.Errorf("different args should be allowed, blocked with: %s", result.Reason)
		}
	}
}

func TestDoW_LoopDetection_DifferentTools(t *testing.T) {
	tracker := NewDoWTracker(DoWConfig{
		MaxRetriesPerTool:   2,
		LoopDetectionWindow: 10,
		Action:              actionBlock,
	})

	// Same args to different tools should not trigger loop.
	tools := []string{"tool_a", "tool_b", "tool_c", "tool_d"}
	for _, tool := range tools {
		result := tracker.RecordToolCall(tool, argsNYC)
		if !result.Allowed {
			t.Errorf("different tools should be allowed, blocked: %s", result.Reason)
		}
	}
}

func TestDoW_UnsetRetryAndWindowDoNotArmPatternBudgets(t *testing.T) {
	tracker := NewDoWTracker(DoWConfig{
		MaxWallClockMinutes: 60,
		Action:              actionBlock,
	})

	for i := range 10 {
		result := tracker.RecordToolCall(toolGetWeather, argsNYC)
		if !result.Allowed {
			t.Fatalf("call %d blocked by unconfigured budget: %s (%s)", i+1, result.Reason, result.BudgetType)
		}
	}
}

func TestDoW_MaxRetriesWithoutWindowEnforcesConfiguredLimitOnly(t *testing.T) {
	tracker := NewDoWTracker(DoWConfig{
		MaxRetriesPerTool: 2,
		Action:            actionBlock,
	})

	for i := range 2 {
		result := tracker.RecordToolCall(toolGetWeather, argsNYC)
		if !result.Allowed {
			t.Fatalf("call %d should be allowed, got blocked: %s", i+1, result.Reason)
		}
	}
	result := tracker.RecordToolCall(toolGetWeather, argsNYC)
	if result.Allowed {
		t.Fatal("third identical call should be blocked by configured retry budget")
	}
	if result.BudgetType != BudgetLoop {
		t.Fatalf("BudgetType = %q, want %q", result.BudgetType, BudgetLoop)
	}
}

// --- Runaway Expansion ---

func TestDoW_RunawayExpansion(t *testing.T) {
	tracker := NewDoWTracker(DoWConfig{
		MaxRetriesPerTool:   100, // high limit so loop doesn't fire first
		LoopDetectionWindow: 20,
		Action:              actionBlock,
	})

	// Monotonically increasing argument sizes for the same tool.
	// minRunawaySteps+1 = 4, so the 4th call (index 3) will see 4 entries
	// with strictly increasing sizes and trigger runaway.
	for i := range 3 {
		args := fmt.Sprintf(`{"data":"%s"}`, string(make([]byte, (i+1)*100)))
		result := tracker.RecordToolCall(toolReadFile, args)
		if !result.Allowed {
			t.Fatalf("call %d should be allowed, got blocked: %s", i, result.Reason)
		}
	}

	// The 4th call with a larger arg triggers runaway detection.
	bigArgs := fmt.Sprintf(`{"data":"%s"}`, string(make([]byte, 400)))
	result := tracker.RecordToolCall(toolReadFile, bigArgs)
	if result.Allowed {
		t.Error("4th monotonically increasing call should trigger runaway")
	}
	if result.BudgetType != BudgetRunaway {
		t.Errorf("BudgetType = %q, want %q", result.BudgetType, BudgetRunaway)
	}
}

func TestDoW_RunawayExpansion_NonMonotonic(t *testing.T) {
	tracker := NewDoWTracker(DoWConfig{
		MaxRetriesPerTool:   100,
		LoopDetectionWindow: 20,
		Action:              actionBlock,
	})

	// Non-monotonic sizes should not trigger.
	sizes := []int{100, 200, 150, 300, 100}
	for _, sz := range sizes {
		args := fmt.Sprintf(`{"data":"%s"}`, string(make([]byte, sz)))
		result := tracker.RecordToolCall(toolReadFile, args)
		if !result.Allowed && result.BudgetType == BudgetRunaway {
			t.Errorf("non-monotonic sizes should not trigger runaway: %s", result.Reason)
		}
	}
}

// --- Cycle Detection ---

func TestDoW_CycleDetection(t *testing.T) {
	tracker := NewDoWTracker(DoWConfig{
		MaxRetriesPerTool:   100, // high so loop doesn't fire
		LoopDetectionWindow: 20,
		Action:              actionBlock,
	})

	// A -> B -> A -> B pattern.
	calls := []string{toolReadFile, toolWriteFile, toolReadFile, toolWriteFile}
	var lastResult DoWResult
	for _, tool := range calls {
		lastResult = tracker.RecordToolCall(tool, "{}")
	}

	if lastResult.Allowed {
		t.Error("A->B->A->B cycle should be detected")
	}
	if lastResult.BudgetType != BudgetCycle {
		t.Errorf("BudgetType = %q, want %q", lastResult.BudgetType, BudgetCycle)
	}
}

func TestDoW_CycleDetection_NoCycle(t *testing.T) {
	tracker := NewDoWTracker(DoWConfig{
		MaxRetriesPerTool:   100,
		LoopDetectionWindow: 20,
		Action:              actionBlock,
	})

	// A -> B -> C -> D -- no cycle.
	tools := []string{"a", "b", "c", "d"}
	for _, tool := range tools {
		result := tracker.RecordToolCall(tool, "{}")
		if !result.Allowed && result.BudgetType == BudgetCycle {
			t.Errorf("sequential different tools should not trigger cycle: %s", result.Reason)
		}
	}
}

func TestDoW_CycleDetection_SameToolNotCycle(t *testing.T) {
	tracker := NewDoWTracker(DoWConfig{
		MaxRetriesPerTool:   100,
		LoopDetectionWindow: 20,
		Action:              actionBlock,
	})

	// A -> A -> A -> A -- this is a loop, not a cycle (needs two different tools).
	for range 4 {
		result := tracker.RecordToolCall(toolReadFile, `{"a":"1"}`)
		if result.BudgetType == BudgetCycle {
			t.Error("same tool repeated should not trigger cycle detection")
		}
	}
}

// --- Wall Clock ---

func TestDoW_WallClock(t *testing.T) {
	tracker := NewDoWTracker(DoWConfig{
		MaxWallClockMinutes: 1,
		LoopDetectionWindow: 20,
		MaxRetriesPerTool:   100,
		Action:              actionBlock,
	})

	// Artificially set the start time to 2 minutes ago.
	tracker.mu.Lock()
	tracker.start = time.Now().Add(-2 * time.Minute)
	tracker.mu.Unlock()

	result := tracker.RecordToolCall(toolGetWeather, argsNYC)
	if result.Allowed {
		t.Error("should be blocked after wall clock exceeded")
	}
	if result.BudgetType != BudgetWallClock {
		t.Errorf("BudgetType = %q, want %q", result.BudgetType, BudgetWallClock)
	}
}

func TestDoW_WallClock_WithinBudget(t *testing.T) {
	tracker := NewDoWTracker(DoWConfig{
		MaxWallClockMinutes: 60, // 1 hour
		LoopDetectionWindow: 20,
		MaxRetriesPerTool:   100,
		Action:              actionBlock,
	})

	result := tracker.RecordToolCall(toolGetWeather, argsNYC)
	if !result.Allowed {
		t.Errorf("should be within wall clock budget: %s", result.Reason)
	}
}

// --- Tool Call Limit ---

func TestDoW_ToolCallLimit(t *testing.T) {
	tracker := NewDoWTracker(DoWConfig{
		MaxToolCallsPerSession: 5,
		MaxRetriesPerTool:      100, // high so loop doesn't fire
		LoopDetectionWindow:    20,
		Action:                 actionBlock,
	})

	// First 5 calls should be allowed.
	for i := range 5 {
		args := fmt.Sprintf(`{"i":%d}`, i)
		result := tracker.RecordToolCall(toolGetWeather, args)
		if !result.Allowed {
			t.Fatalf("call %d should be allowed: %s", i, result.Reason)
		}
	}

	// 6th call should be blocked.
	result := tracker.RecordToolCall(toolGetWeather, `{"i":5}`)
	if result.Allowed {
		t.Error("6th call should exceed tool call limit")
	}
	if result.BudgetType != BudgetToolCalls {
		t.Errorf("BudgetType = %q, want %q", result.BudgetType, BudgetToolCalls)
	}
}

// --- Concurrent Tool Calls ---

func TestDoW_ConcurrentLimit(t *testing.T) {
	tracker := NewDoWTracker(DoWConfig{
		MaxConcurrentToolCalls: 3,
		Action:                 actionBlock,
	})

	// Acquire 3 slots.
	for i := range 3 {
		result := tracker.AcquireConcurrent()
		if !result.Allowed {
			t.Fatalf("acquire %d should succeed: %s", i, result.Reason)
		}
	}

	if tracker.Inflight() != 3 {
		t.Errorf("inflight = %d, want 3", tracker.Inflight())
	}

	// 4th should fail.
	result := tracker.AcquireConcurrent()
	if result.Allowed {
		t.Error("4th concurrent should be blocked")
	}
	if result.BudgetType != BudgetConcurrent {
		t.Errorf("BudgetType = %q, want %q", result.BudgetType, BudgetConcurrent)
	}

	// Inflight should still be 3 (failed acquire was rolled back).
	if tracker.Inflight() != 3 {
		t.Errorf("inflight = %d, want 3 (failed acquire rolled back)", tracker.Inflight())
	}

	// Release one, then acquire should succeed.
	tracker.ReleaseConcurrent()
	if tracker.Inflight() != 2 {
		t.Errorf("inflight = %d, want 2 after release", tracker.Inflight())
	}

	result = tracker.AcquireConcurrent()
	if !result.Allowed {
		t.Errorf("acquire after release should succeed: %s", result.Reason)
	}
}

func TestDoW_ConcurrentLimit_Default(t *testing.T) {
	// Zero value for MaxConcurrentToolCalls should use default of 10.
	tracker := NewDoWTracker(DoWConfig{Action: actionBlock})

	for i := range 10 {
		result := tracker.AcquireConcurrent()
		if !result.Allowed {
			t.Fatalf("acquire %d should succeed with default limit: %s", i, result.Reason)
		}
	}

	result := tracker.AcquireConcurrent()
	if result.Allowed {
		t.Error("11th concurrent should exceed default limit of 10")
	}

	// Clean up.
	for range 10 {
		tracker.ReleaseConcurrent()
	}
}

func TestDoW_ConcurrentLimit_ThreadSafe(t *testing.T) {
	const limit = 50
	tracker := NewDoWTracker(DoWConfig{
		MaxConcurrentToolCalls: limit,
		Action:                 actionBlock,
	})

	var wg sync.WaitGroup
	allowed := make(chan bool, 100)
	releaseHolders := make(chan struct{})
	holderResults := make(chan bool, limit)
	contenderResults := make(chan bool, 50)

	// Fill the concurrent-call limit with holders first, then launch
	// contenders. That deterministically exercises both allowed and denied
	// paths instead of depending on goroutine scheduling timing.
	for range limit {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result := tracker.AcquireConcurrent()
			allowed <- result.Allowed
			holderResults <- result.Allowed
			if result.Allowed {
				<-releaseHolders
				tracker.ReleaseConcurrent()
			}
		}()
	}

	for range limit {
		select {
		case ok := <-holderResults:
			if !ok {
				t.Fatal("holder acquire was denied before limit was full")
			}
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for holders to acquire concurrent slots")
		}
	}

	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result := tracker.AcquireConcurrent()
			allowed <- result.Allowed
			contenderResults <- result.Allowed
			if result.Allowed {
				tracker.ReleaseConcurrent()
			}
		}()
	}

	for range 50 {
		select {
		case <-contenderResults:
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for contenders to attempt concurrent acquire")
		}
	}

	close(releaseHolders)
	wg.Wait()
	close(allowed)

	allowedCount := 0
	deniedCount := 0
	for a := range allowed {
		if a {
			allowedCount++
		} else {
			deniedCount++
		}
	}

	if allowedCount == 0 || allowedCount > limit {
		t.Errorf("allowed concurrent acquires = %d, want 1..%d", allowedCount, limit)
	}
	if deniedCount == 0 {
		t.Error("expected some concurrent acquires to be denied while holders occupied the limit")
	}

	// Final inflight should be 0 (all released).
	if tracker.Inflight() != 0 {
		t.Errorf("inflight = %d after all released, want 0", tracker.Inflight())
	}
}

// --- Close ---

func TestDoW_ClosedTracker(t *testing.T) {
	tracker := NewDoWTracker(defaultDoWConfig())
	tracker.Close()

	result := tracker.RecordToolCall(toolGetWeather, argsNYC)
	if result.Allowed {
		t.Error("closed tracker should block tool calls")
	}
}

func TestDoW_ClosedTracker_AcquireConcurrent(t *testing.T) {
	tracker := NewDoWTracker(defaultDoWConfig())

	// Acquire a slot before closing.
	result := tracker.AcquireConcurrent()
	if !result.Allowed {
		t.Fatalf("pre-close acquire should succeed: %s", result.Reason)
	}

	tracker.Close()

	// After close, AcquireConcurrent must return not-allowed.
	result = tracker.AcquireConcurrent()
	if result.Allowed {
		t.Error("closed tracker should block AcquireConcurrent")
	}
	if result.BudgetType != BudgetConcurrent {
		t.Errorf("BudgetType = %q, want %q", result.BudgetType, BudgetConcurrent)
	}
	if !strings.Contains(result.Reason, "tracker closed") {
		t.Errorf("Reason = %q, want substring %q", result.Reason, "tracker closed")
	}
}

func TestDoW_ClosedTracker_ReleaseConcurrent(t *testing.T) {
	tracker := NewDoWTracker(defaultDoWConfig())

	// Acquire a slot, then close, then release.
	result := tracker.AcquireConcurrent()
	if !result.Allowed {
		t.Fatalf("pre-close acquire should succeed: %s", result.Reason)
	}

	if tracker.Inflight() != 1 {
		t.Fatalf("inflight = %d, want 1", tracker.Inflight())
	}

	tracker.Close()

	// Release after close should still decrement (slots acquired before
	// shutdown must be released to avoid permanently elevated counters).
	tracker.ReleaseConcurrent()

	if tracker.Inflight() != 0 {
		t.Errorf("inflight = %d, want 0 (release should decrement after close)", tracker.Inflight())
	}

	// Additional release should not underflow below zero.
	tracker.ReleaseConcurrent()

	if tracker.Inflight() != 0 {
		t.Errorf("inflight = %d, want 0 (should not underflow below zero)", tracker.Inflight())
	}
}

// --- TotalToolCalls ---

func TestDoW_TotalToolCalls(t *testing.T) {
	tracker := NewDoWTracker(DoWConfig{
		MaxRetriesPerTool:   100,
		LoopDetectionWindow: 20,
		Action:              actionBlock,
	})

	if tracker.TotalToolCalls() != 0 {
		t.Errorf("initial TotalToolCalls = %d, want 0", tracker.TotalToolCalls())
	}

	for i := range 5 {
		tracker.RecordToolCall(toolGetWeather, fmt.Sprintf(`{"i":%d}`, i))
	}

	if tracker.TotalToolCalls() != 5 {
		t.Errorf("TotalToolCalls = %d, want 5", tracker.TotalToolCalls())
	}
}

// --- hashArgs ---

func TestHashArgs_Deterministic(t *testing.T) {
	h1 := hashArgs(argsNYC)
	h2 := hashArgs(argsNYC)
	if h1 != h2 {
		t.Errorf("same input should produce same hash: %q vs %q", h1, h2)
	}
	if len(h1) != argsHashLen {
		t.Errorf("hash length = %d, want %d", len(h1), argsHashLen)
	}
}

func TestHashArgs_Different(t *testing.T) {
	h1 := hashArgs(argsNYC)
	h2 := hashArgs(argsSF)
	if h1 == h2 {
		t.Error("different inputs should produce different hashes")
	}
}

// --- Window Trimming ---

func TestDoW_WindowTrimming(t *testing.T) {
	tracker := NewDoWTracker(DoWConfig{
		MaxRetriesPerTool:   100,
		LoopDetectionWindow: 5,
		Action:              actionBlock,
	})

	// Record 10 calls. Window should only keep the last 5.
	for i := range 10 {
		tracker.RecordToolCall(toolGetWeather, fmt.Sprintf(`{"i":%d}`, i))
	}

	tracker.mu.Lock()
	windowLen := len(tracker.toolCalls)
	tracker.mu.Unlock()

	if windowLen > 5 {
		t.Errorf("window size = %d, want <= 5", windowLen)
	}
}

// --- Unset Values ---

func TestDoW_UnsetWindowDoesNotRetainHistoryWithoutPatternBudget(t *testing.T) {
	tracker := NewDoWTracker(DoWConfig{
		MaxWallClockMinutes: 60,
		Action:              actionBlock,
	})

	for i := range 25 {
		tracker.RecordToolCall(toolGetWeather, fmt.Sprintf(`{"i":%d}`, i))
	}

	tracker.mu.Lock()
	windowLen := len(tracker.toolCalls)
	tracker.mu.Unlock()

	if windowLen != 0 {
		t.Errorf("unset window retained %d calls, want 0", windowLen)
	}
}

func TestDoWSubjectManager_IsolatesSubjectsAndBoundsMemory(t *testing.T) {
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	manager := NewDoWSubjectManager(DoWSubjectManagerConfig{
		TrackerConfig: DoWConfig{
			MaxToolCallsPerSession: 1,
			Action:                 actionBlock,
		},
		IdleTTL:     time.Minute,
		MaxSubjects: 2,
		Now: func() time.Time {
			return now
		},
	})

	if !manager.Check("subject-a", toolGetWeather, `{"turn":1}`).Allowed {
		t.Fatal("first subject-a call should be allowed")
	}
	if !manager.Check("subject-b", toolGetWeather, `{"turn":1}`).Allowed {
		t.Fatal("first subject-b call should be allowed independently")
	}
	if result := manager.Check("subject-a", toolGetWeather, `{"turn":2}`); result.Allowed {
		t.Fatal("second subject-a call should be blocked by its own budget")
	}

	now = now.Add(time.Second)
	if result := manager.Check("subject-c", toolGetWeather, `{"turn":1}`); result.Allowed || result.BudgetType != BudgetSubjectCap {
		t.Fatalf("new subject at cap = allowed:%v budget:%q reason:%q, want subject-cap block",
			result.Allowed, result.BudgetType, result.Reason)
	}
	if got := manager.SubjectCount(); got != 2 {
		t.Fatalf("SubjectCount after cap block = %d, want 2", got)
	}

	for i := range 10 {
		result := manager.Check(fmt.Sprintf("subject-extra-%02d", i), toolGetWeather, `{"turn":1}`)
		if result.Allowed || result.BudgetType != BudgetSubjectCap {
			t.Fatalf("bounded table admitted subject %d at cap: allowed:%v budget:%q reason:%q",
				i, result.Allowed, result.BudgetType, result.Reason)
		}
		if got := manager.SubjectCount(); got > 2 {
			t.Fatalf("SubjectCount = %d, want <= 2", got)
		}
	}
}

func TestDoWSubjectManager_WindowResetIsLegitimate(t *testing.T) {
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	manager := NewDoWSubjectManager(DoWSubjectManagerConfig{
		TrackerConfig: DoWConfig{
			MaxToolCallsPerSession: 1,
			Action:                 actionBlock,
		},
		IdleTTL:     time.Minute,
		MaxSubjects: 2,
		Now: func() time.Time {
			return now
		},
	})

	if !manager.Check("subject-s", toolGetWeather, `{"turn":1}`).Allowed {
		t.Fatal("first subject-s call should be allowed")
	}
	if result := manager.Check("subject-s", toolGetWeather, `{"turn":2}`); result.Allowed {
		t.Fatal("second subject-s call should consume the budget and block")
	}

	now = now.Add(30 * time.Second)
	if result := manager.Check("subject-s", toolGetWeather, `{"turn":3}`); result.Allowed {
		t.Fatal("subject received a fresh allowance before the window rolled")
	}

	now = now.Add(31 * time.Second)
	if result := manager.Check("subject-s", toolGetWeather, `{"turn":4}`); !result.Allowed {
		t.Fatalf("subject should receive a fresh allowance after the window: %s", result.Reason)
	}
}

func TestDoWSubjectManager_WindowExpiryPreventsPermanentWedge(t *testing.T) {
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	manager := NewDoWSubjectManager(DoWSubjectManagerConfig{
		TrackerConfig: DoWConfig{
			MaxToolCallsPerSession: 1,
			Action:                 actionBlock,
		},
		IdleTTL:     time.Minute,
		MaxSubjects: 5,
		Now: func() time.Time {
			return now
		},
	})

	for i := range 5 {
		subject := fmt.Sprintf("spent-subject-%d", i)
		if !manager.Check(subject, toolGetWeather, `{"turn":1}`).Allowed {
			t.Fatalf("%s first call should be allowed", subject)
		}
		if result := manager.Check(subject, toolGetWeather, `{"turn":2}`); result.Allowed {
			t.Fatalf("%s should be spent", subject)
		}
	}

	now = now.Add(time.Minute + time.Second)
	if got := manager.SubjectCount(); got != 0 {
		t.Fatalf("spent subjects should be dropped after the budget window; got %d", got)
	}
	if result := manager.Check("brand-new-subject", toolGetWeather, `{"turn":1}`); !result.Allowed {
		t.Fatalf("new subject should be allowed after spent table ages past window: %s", result.Reason)
	}
}

func TestDoWSubjectManager_SubjectCapFailsClosedForNewSubjects(t *testing.T) {
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	manager := NewDoWSubjectManager(DoWSubjectManagerConfig{
		TrackerConfig: DoWConfig{
			MaxToolCallsPerSession: 1,
			Action:                 actionBlock,
		},
		IdleTTL:     time.Minute,
		MaxSubjects: 2,
		Now: func() time.Time {
			return now
		},
	})

	if !manager.Check("subject-a", toolGetWeather, `{"turn":1}`).Allowed {
		t.Fatal("subject-a first call should be allowed")
	}
	now = now.Add(time.Second)
	if !manager.Check("subject-b", toolGetWeather, `{"turn":1}`).Allowed {
		t.Fatal("subject-b first call should be allowed")
	}
	now = now.Add(time.Second)
	if result := manager.Check("subject-c", toolGetWeather, `{"turn":1}`); result.Allowed || result.BudgetType != BudgetSubjectCap {
		t.Fatalf("new subject at cap = allowed:%v budget:%q reason:%q, want subject-cap block",
			result.Allowed, result.BudgetType, result.Reason)
	}
	if got := manager.SubjectCount(); got != 2 {
		t.Fatalf("SubjectCount = %d, want 2", got)
	}

	// A spent live subject must not be reset early by cap pressure from
	// attacker-rotated subjects. It remains blocked until its window expires.
	if result := manager.Check("subject-a", toolGetWeather, `{"turn":2}`); result.Allowed {
		t.Fatalf("spent subject was reset before the budget window expired")
	}

	now = now.Add(2 * time.Minute)
	if got := manager.SubjectCount(); got != 0 {
		t.Fatalf("subjects should expire after the budget window; got %d", got)
	}
	if result := manager.Check("subject-c", toolGetWeather, `{"turn":1}`); !result.Allowed {
		t.Fatalf("new subject should be admitted after the live windows expire: %s", result.Reason)
	}
}

func TestDoWSubjectManager_ConcurrentSubjectsRace(t *testing.T) {
	manager := NewDoWSubjectManager(DoWSubjectManagerConfig{
		TrackerConfig: DoWConfig{
			MaxToolCallsPerSession: 100000,
			Action:                 actionBlock,
		},
		MaxSubjects: 100,
	})

	const subjects = 25
	var wg sync.WaitGroup
	for i := range subjects {
		subjectKey := fmt.Sprintf("subject-%02d", i)
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range 100 {
				result := manager.Check(subjectKey, toolGetWeather, fmt.Sprintf(`{"turn":%d}`, j))
				if !result.Allowed {
					t.Errorf("%s call %d blocked: %s", subjectKey, j, result.Reason)
					return
				}
			}
		}()
	}
	wg.Wait()
}

// --- Integration-style test ---

func TestDoW_MixedBudgets(t *testing.T) {
	tracker := NewDoWTracker(defaultDoWConfig())

	// Normal tool calls should be fine.
	result := tracker.RecordToolCall(toolGetWeather, argsNYC)
	if !result.Allowed {
		t.Fatalf("first call should be allowed: %s", result.Reason)
	}

	// Concurrent acquire should be fine.
	result = tracker.AcquireConcurrent()
	if !result.Allowed {
		t.Fatalf("first concurrent should be allowed: %s", result.Reason)
	}
	tracker.ReleaseConcurrent()
}

func TestDoW_ZeroConfig(t *testing.T) {
	// All-zero config should use defaults and not panic.
	tracker := NewDoWTracker(DoWConfig{})

	result := tracker.RecordToolCall(toolGetWeather, argsNYC)
	if !result.Allowed {
		t.Errorf("zero config should allow first call: %s", result.Reason)
	}

	result = tracker.AcquireConcurrent()
	if !result.Allowed {
		t.Errorf("zero config should allow concurrent: %s", result.Reason)
	}
	tracker.ReleaseConcurrent()
}
