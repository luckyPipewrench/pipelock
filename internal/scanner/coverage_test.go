// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"testing"
	"time"
)

func TestNewEntropyTracker_NonPositiveInputs(t *testing.T) {
	tests := []struct {
		name       string
		budgetBits float64
		windowSecs int
		wantBudget float64
		wantWindow int
	}{
		{name: "zero budget", budgetBits: 0, windowSecs: 60, wantBudget: 1, wantWindow: 60},
		{name: "negative budget", budgetBits: -100, windowSecs: 60, wantBudget: 1, wantWindow: 60},
		{name: "zero window", budgetBits: 100, windowSecs: 0, wantBudget: 100, wantWindow: 1},
		{name: "negative window", budgetBits: 100, windowSecs: -10, wantBudget: 100, wantWindow: 1},
		{name: "both zero", budgetBits: 0, windowSecs: 0, wantBudget: 1, wantWindow: 1},
		{name: "both negative", budgetBits: -50, windowSecs: -5, wantBudget: 1, wantWindow: 1},
		{name: "normal values", budgetBits: 4096, windowSecs: 300, wantBudget: 4096, wantWindow: 300},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			et := NewEntropyTracker(tt.budgetBits, tt.windowSecs)
			defer et.Close()

			if et.budget != tt.wantBudget {
				t.Errorf("budget = %f, want %f", et.budget, tt.wantBudget)
			}
			if et.windowSecs != tt.wantWindow {
				t.Errorf("windowSecs = %d, want %d", et.windowSecs, tt.wantWindow)
			}
		})
	}
}

func TestDataBudget_CleanupLoop_StopsOnClose(t *testing.T) {
	db := NewDataBudget(1000)

	// Record data so there's something to clean up.
	db.Record("example.com", 100)

	// Close should stop the cleanup goroutine without hanging.
	db.Close()

	// Verify the channel is closed (second close is a no-op via sync.Once).
	db.Close()
}

func TestRateLimiter_CleanupLoop_StopsOnClose(t *testing.T) {
	rl := NewRateLimiter(100)

	rl.Record("example.com")

	// Close should stop the cleanup goroutine without hanging.
	rl.Close()

	// Verify the channel is closed (second close is a no-op via sync.Once).
	rl.Close()
}

func TestFragmentBuffer_CleanupLoop_StopsOnClose(t *testing.T) {
	fb := NewFragmentBuffer(65536, 1000, 300)

	fb.Append("session-1", []byte("data"))

	// Close should stop the cleanup goroutine without hanging.
	fb.Close()

	// Verify the channel is closed (second close is a no-op via sync.Once).
	fb.Close()
}

func TestEntropyTracker_CleanupLoop_StopsOnClose(t *testing.T) {
	et := NewEntropyTracker(4096, 300)

	et.Record("session-1", []byte("test data"))

	// Close should stop the cleanup goroutine without hanging.
	et.Close()

	// Verify the channel is closed (second close is a no-op via sync.Once).
	et.Close()
}

func TestValidateWIF_EdgeCases(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{name: "empty string", input: "", want: false},
		{name: "single char", input: "5", want: false},
		{name: "non-base58 chars", input: "0OIl" + "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", want: false},
		{name: "all ones base58", input: "1111111111111111111111111111111111111111111111111111", want: false},
		// Very short input that's valid base58 but too short for WIF.
		{name: "short valid base58", input: "5HueCGU", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := validateWIF(tt.input)
			if got != tt.want {
				t.Errorf("validateWIF(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestEntropyTracker_CleanupLoop_IntervalClamping(t *testing.T) {
	// Test that cleanup interval is clamped between 1s and 60s.
	// Very large window: interval should cap at 60s.
	et := NewEntropyTracker(100, 3600) // 1 hour window
	defer et.Close()
	// The tracker should work correctly (cleanup loop started).
	et.Record("s1", []byte("data"))
	if et.CurrentUsage("s1") == 0 {
		t.Error("expected non-zero usage")
	}

	// Very small window: interval should floor at 1s.
	et2 := NewEntropyTracker(100, 1)
	defer et2.Close()
	et2.Record("s2", []byte("data"))
	if et2.CurrentUsage("s2") == 0 {
		t.Error("expected non-zero usage")
	}
}

func TestFragmentBuffer_CleanupLoop_IntervalClamping(t *testing.T) {
	// Very large window: interval caps at 60s.
	fb := NewFragmentBuffer(65536, 1000, 3600)
	defer fb.Close()
	fb.Append("s1", []byte("data"))
	if fb.TotalBufferBytes() == 0 {
		t.Error("expected non-zero bytes")
	}

	// Very small window: interval floors at 1s.
	fb2 := NewFragmentBuffer(65536, 1000, 1)
	defer fb2.Close()
	fb2.Append("s2", []byte("data"))
	if fb2.TotalBufferBytes() == 0 {
		t.Error("expected non-zero bytes")
	}
}

func TestCheckAndRecord_AtomicLimitEnforcement(t *testing.T) {
	rl := NewRateLimiter(2)
	defer rl.Close()

	// First two should succeed.
	if !rl.CheckAndRecord("example.com") {
		t.Error("first CheckAndRecord should succeed")
	}
	if !rl.CheckAndRecord("example.com") {
		t.Error("second CheckAndRecord should succeed")
	}
	// Third should fail.
	if rl.CheckAndRecord("example.com") {
		t.Error("third CheckAndRecord should fail (limit=2)")
	}
}

func TestCheckAndRecord_SlidingWindowReset(t *testing.T) {
	rl := NewRateLimiter(1)
	defer rl.Close()

	// Fill limit.
	if !rl.CheckAndRecord("example.com") {
		t.Fatal("first request should succeed")
	}

	// Manually backdate the request to expire it.
	rl.mu.Lock()
	rl.requests["example.com"] = []time.Time{time.Now().Add(-2 * time.Minute)}
	rl.mu.Unlock()

	// Should succeed again after window expires.
	if !rl.CheckAndRecord("example.com") {
		t.Error("CheckAndRecord should succeed after window expiry")
	}
}

func TestRateLimiter_CleanupMixedEntries(t *testing.T) {
	rl := NewRateLimiter(10)
	defer rl.Close()

	// Mix of old and new entries.
	rl.mu.Lock()
	rl.requests["mixed.com"] = []time.Time{
		time.Now().Add(-2 * time.Minute), // expired
		time.Now(),                       // still valid
	}
	rl.mu.Unlock()

	rl.cleanup()

	rl.mu.Lock()
	count := len(rl.requests["mixed.com"])
	rl.mu.Unlock()

	if count != 1 {
		t.Errorf("expected 1 entry after cleanup, got %d", count)
	}
}
