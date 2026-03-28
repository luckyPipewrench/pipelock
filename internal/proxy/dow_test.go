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
	domainExample  = "example.com"
	pathAPI        = "/api/v1/data"
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
		FanOutLimit:            5,
		FanOutWindowSeconds:    60,
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
	tracker := NewDoWTracker(DoWConfig{
		MaxConcurrentToolCalls: 50,
		Action:                 actionBlock,
	})

	var wg sync.WaitGroup
	allowed := make(chan bool, 100)

	// Launch 100 goroutines trying to acquire.
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result := tracker.AcquireConcurrent()
			allowed <- result.Allowed
			if result.Allowed {
				// Hold briefly then release.
				time.Sleep(time.Millisecond)
				tracker.ReleaseConcurrent()
			}
		}()
	}

	wg.Wait()
	close(allowed)

	allowedCount := 0
	for a := range allowed {
		if a {
			allowedCount++
		}
	}

	// At least some should succeed, and we should never exceed the limit.
	if allowedCount == 0 {
		t.Error("at least some concurrent acquires should succeed")
	}

	// Final inflight should be 0 (all released).
	if tracker.Inflight() != 0 {
		t.Errorf("inflight = %d after all released, want 0", tracker.Inflight())
	}
}

// --- Fan-Out Detection ---

func TestDoW_FanOut(t *testing.T) {
	tracker := NewDoWTracker(DoWConfig{
		FanOutLimit:         3,
		FanOutWindowSeconds: 60,
		Action:              actionBlock,
	})

	// Hit 3 unique endpoints -- OK.
	endpoints := []struct{ domain, path string }{
		{"a.com", "/1"},
		{"b.com", "/2"},
		{"c.com", "/3"},
	}
	for _, ep := range endpoints {
		result := tracker.RecordEndpoint(ep.domain, ep.path, 200)
		if !result.Allowed {
			t.Fatalf("endpoint %s%s should be allowed: %s", ep.domain, ep.path, result.Reason)
		}
	}

	// 4th unique endpoint = fan-out.
	result := tracker.RecordEndpoint("d.com", "/4", 200)
	if result.Allowed {
		t.Error("4th unique endpoint should trigger fan-out")
	}
	if result.BudgetType != BudgetFanOut {
		t.Errorf("BudgetType = %q, want %q", result.BudgetType, BudgetFanOut)
	}
}

func TestDoW_FanOut_SameEndpointOK(t *testing.T) {
	tracker := NewDoWTracker(DoWConfig{
		FanOutLimit:         3,
		FanOutWindowSeconds: 60,
		Action:              actionBlock,
	})

	// Same endpoint repeatedly should not trigger fan-out.
	for range 20 {
		result := tracker.RecordEndpoint(domainExample, pathAPI, 200)
		if !result.Allowed && result.BudgetType == BudgetFanOut {
			t.Fatalf("repeated same endpoint should not trigger fan-out: %s", result.Reason)
		}
	}
}

// --- Retry Storm Detection ---

func TestDoW_RetryStorm(t *testing.T) {
	tracker := NewDoWTracker(DoWConfig{
		FanOutLimit:         1000, // high so fan-out doesn't fire
		FanOutWindowSeconds: 60,
		Action:              actionBlock,
	})

	// 20 failures to the same endpoint should be OK (at limit).
	for range 20 {
		result := tracker.RecordEndpoint(domainExample, pathAPI, 500)
		if !result.Allowed && result.BudgetType == BudgetRetry {
			t.Fatalf("retry storm triggered early at count <= 20: %s", result.Reason)
		}
	}

	// 21st failure = retry storm.
	result := tracker.RecordEndpoint(domainExample, pathAPI, 500)
	if result.Allowed {
		t.Error("21st failure should trigger retry storm")
	}
	if result.BudgetType != BudgetRetry {
		t.Errorf("BudgetType = %q, want %q", result.BudgetType, BudgetRetry)
	}
}

func TestDoW_RetryStorm_ConfigurableLimit(t *testing.T) {
	tracker := NewDoWTracker(DoWConfig{
		FanOutLimit:           1000,
		FanOutWindowSeconds:   60,
		MaxRetriesPerEndpoint: 5, // custom limit of 5
		Action:                actionBlock,
	})

	// 5 failures should be OK (at limit).
	for range 5 {
		result := tracker.RecordEndpoint(domainExample, pathAPI, 500)
		if !result.Allowed && result.BudgetType == BudgetRetry {
			t.Fatalf("retry storm triggered at count <= 5: %s", result.Reason)
		}
	}

	// 6th failure = retry storm with custom limit.
	result := tracker.RecordEndpoint(domainExample, pathAPI, 500)
	if result.Allowed {
		t.Error("6th failure should trigger retry storm with limit of 5")
	}
	if result.BudgetType != BudgetRetry {
		t.Errorf("BudgetType = %q, want %q", result.BudgetType, BudgetRetry)
	}
	if !strings.Contains(result.Reason, "limit 5") {
		t.Errorf("Reason should mention limit 5, got: %s", result.Reason)
	}
}

func TestDoW_RetryStorm_SuccessNotCounted(t *testing.T) {
	tracker := NewDoWTracker(DoWConfig{
		FanOutLimit:         1000,
		FanOutWindowSeconds: 60,
		Action:              actionBlock,
	})

	// Mix of successes and failures -- only failures count.
	for range 30 {
		result := tracker.RecordEndpoint(domainExample, pathAPI, 200)
		if result.BudgetType == BudgetRetry {
			t.Fatalf("successful requests should not trigger retry storm: %s", result.Reason)
		}
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

	result = tracker.RecordEndpoint(domainExample, pathAPI, 200)
	if result.Allowed {
		t.Error("closed tracker should block endpoint recording")
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

// --- pruneEndpoints ---

func TestPruneEndpoints(t *testing.T) {
	now := time.Now()
	entries := []endpointEntry{
		{domain: "old.com", path: "/old", at: now.Add(-2 * time.Minute)},
		{domain: "new.com", path: "/new", at: now},
	}

	cutoff := now.Add(-time.Minute)
	pruned := pruneEndpoints(entries, cutoff)

	if len(pruned) != 1 {
		t.Fatalf("pruned length = %d, want 1", len(pruned))
	}
	if pruned[0].domain != "new.com" {
		t.Errorf("remaining entry = %q, want %q", pruned[0].domain, "new.com")
	}
}

func TestPruneEndpoints_AllExpired(t *testing.T) {
	now := time.Now()
	entries := []endpointEntry{
		{domain: "old.com", path: "/a", at: now.Add(-5 * time.Minute)},
		{domain: "old.com", path: "/b", at: now.Add(-3 * time.Minute)},
	}

	cutoff := now.Add(-time.Minute)
	pruned := pruneEndpoints(entries, cutoff)

	if len(pruned) != 0 {
		t.Errorf("all entries should be pruned, got %d", len(pruned))
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

// --- Default Values ---

func TestDoW_DefaultWindow(t *testing.T) {
	// Zero LoopDetectionWindow should use default of 20.
	tracker := NewDoWTracker(DoWConfig{
		MaxRetriesPerTool: 100,
		Action:            actionBlock,
	})

	// Record 25 calls. Should trim to 20.
	for i := range 25 {
		tracker.RecordToolCall(toolGetWeather, fmt.Sprintf(`{"i":%d}`, i))
	}

	tracker.mu.Lock()
	windowLen := len(tracker.toolCalls)
	tracker.mu.Unlock()

	if windowLen > 20 {
		t.Errorf("default window size = %d, want <= 20", windowLen)
	}
}

func TestDoW_DefaultFanOutWindow(t *testing.T) {
	// Zero FanOutWindowSeconds should use default of 60.
	tracker := NewDoWTracker(DoWConfig{
		FanOutLimit: 1000,
		Action:      actionBlock,
	})

	// Should not panic with zero config values.
	result := tracker.RecordEndpoint(domainExample, pathAPI, 200)
	if !result.Allowed {
		t.Errorf("should be allowed with defaults: %s", result.Reason)
	}
}

// --- Integration-style test ---

func TestDoW_MixedBudgets(t *testing.T) {
	tracker := NewDoWTracker(defaultDoWConfig())

	// Normal tool calls should be fine.
	result := tracker.RecordToolCall(toolGetWeather, argsNYC)
	if !result.Allowed {
		t.Fatalf("first call should be allowed: %s", result.Reason)
	}

	// Normal endpoint should be fine.
	result = tracker.RecordEndpoint(domainExample, pathAPI, 200)
	if !result.Allowed {
		t.Fatalf("first endpoint should be allowed: %s", result.Reason)
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

	result = tracker.RecordEndpoint(domainExample, pathAPI, 200)
	if !result.Allowed {
		t.Errorf("zero config should allow first endpoint: %s", result.Reason)
	}

	result = tracker.AcquireConcurrent()
	if !result.Allowed {
		t.Errorf("zero config should allow concurrent: %s", result.Reason)
	}
	tracker.ReleaseConcurrent()
}
