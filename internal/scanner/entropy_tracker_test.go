// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

const (
	testSessionKey  = "session-001"
	testSessionKey2 = "session-002"
	// 4096 bits default budget.
	testDefaultBudget = 4096.0
	// 300 seconds = 5 minute default window.
	testDefaultWindow = 300
)

func TestEntropyTrackerRecord(t *testing.T) {
	et := NewEntropyTracker(testDefaultBudget, testDefaultWindow)
	defer et.Close()

	payload := []byte("Hello, this is a test payload with some entropy")
	bits := et.Record(testSessionKey, payload)

	if bits <= 0 {
		t.Fatalf("expected positive bits, got %f", bits)
	}

	// Verify usage matches what was recorded.
	usage := et.CurrentUsage(testSessionKey)
	if usage != bits {
		t.Fatalf("expected usage %f to match recorded bits %f", usage, bits)
	}
}

func TestEntropyTrackerRecordMatchesShannonEntropy(t *testing.T) {
	et := NewEntropyTracker(testDefaultBudget, testDefaultWindow)
	defer et.Close()

	payload := []byte("abcdefghijklmnopqrstuvwxyz0123456789")
	bits := et.Record(testSessionKey, payload)

	// Total bits = ShannonEntropy(string) * len(payload)
	expectedBits := ShannonEntropy(string(payload)) * float64(len(payload))
	if bits != expectedBits {
		t.Fatalf("expected %f bits, got %f", expectedBits, bits)
	}
}

func TestEntropyTrackerBudgetExceeded(t *testing.T) {
	// Use a very small budget so we exceed it quickly.
	smallBudget := 10.0
	et := NewEntropyTracker(smallBudget, testDefaultWindow)
	defer et.Close()

	// Record enough data to exceed the budget.
	payload := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz")
	et.Record(testSessionKey, payload)

	if !et.BudgetExceeded(testSessionKey) {
		t.Fatal("expected budget to be exceeded")
	}
}

func TestEntropyTrackerBudgetNotExceeded(t *testing.T) {
	et := NewEntropyTracker(testDefaultBudget, testDefaultWindow)
	defer et.Close()

	// A small payload should not exceed the default budget.
	et.Record(testSessionKey, []byte("hi"))

	if et.BudgetExceeded(testSessionKey) {
		t.Fatal("expected budget NOT to be exceeded")
	}
}

func TestEntropyTrackerEmptyPayload(t *testing.T) {
	et := NewEntropyTracker(testDefaultBudget, testDefaultWindow)
	defer et.Close()

	// Nil payload returns 0 bits.
	bits := et.Record(testSessionKey, nil)
	if bits != 0 {
		t.Fatalf("expected 0 bits for nil payload, got %f", bits)
	}

	// Empty slice returns 0 bits.
	bits = et.Record(testSessionKey, []byte{})
	if bits != 0 {
		t.Fatalf("expected 0 bits for empty payload, got %f", bits)
	}

	// Usage should be 0 after only empty recordings.
	usage := et.CurrentUsage(testSessionKey)
	if usage != 0 {
		t.Fatalf("expected 0 usage, got %f", usage)
	}
}

func TestEntropyTrackerSessionIsolation(t *testing.T) {
	et := NewEntropyTracker(testDefaultBudget, testDefaultWindow)
	defer et.Close()

	payload1 := []byte("session one data with some entropy content")
	payload2 := []byte("completely different payload for session two")

	bits1 := et.Record(testSessionKey, payload1)
	bits2 := et.Record(testSessionKey2, payload2)

	usage1 := et.CurrentUsage(testSessionKey)
	usage2 := et.CurrentUsage(testSessionKey2)

	if usage1 != bits1 {
		t.Fatalf("session 1 usage %f != recorded bits %f", usage1, bits1)
	}
	if usage2 != bits2 {
		t.Fatalf("session 2 usage %f != recorded bits %f", usage2, bits2)
	}
	if usage1 == usage2 {
		t.Fatal("expected different usage for different payloads")
	}
}

func TestEntropyTrackerWindowExpiry(t *testing.T) {
	// Use a 1-second window so entries expire quickly.
	et := NewEntropyTracker(testDefaultBudget, 1)
	defer et.Close()

	et.Record(testSessionKey, []byte("data that should expire"))

	usage := et.CurrentUsage(testSessionKey)
	if usage == 0 {
		t.Fatal("expected non-zero usage immediately after recording")
	}

	// Wait for the window to expire.
	time.Sleep(1200 * time.Millisecond) // 1.2s: comfortably past the 1s window

	usage = et.CurrentUsage(testSessionKey)
	if usage != 0 {
		t.Fatalf("expected 0 usage after window expiry, got %f", usage)
	}

	if et.BudgetExceeded(testSessionKey) {
		t.Fatal("expected budget NOT exceeded after window expiry")
	}
}

func TestEntropyTrackerConcurrentAccess(t *testing.T) {
	et := NewEntropyTracker(1_000_000, testDefaultWindow) // large budget so we don't exceed
	defer et.Close()

	const goroutines = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := range goroutines {
		go func(id int) {
			defer wg.Done()
			key := fmt.Sprintf("session-%d", id%10) // 10 sessions, 10 goroutines each
			payload := []byte(fmt.Sprintf("payload-%d-with-some-entropy-data", id))
			et.Record(key, payload)
			et.CurrentUsage(key)
			et.BudgetExceeded(key)
			et.Remaining(key)
		}(i)
	}

	wg.Wait()
}

func TestEntropyTrackerRemainingNeverNegative(t *testing.T) {
	smallBudget := 1.0
	et := NewEntropyTracker(smallBudget, testDefaultWindow)
	defer et.Close()

	// Record enough to far exceed the budget.
	et.Record(testSessionKey, []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"))

	remaining := et.Remaining(testSessionKey)
	if remaining < 0 {
		t.Fatalf("expected remaining >= 0, got %f", remaining)
	}
	if remaining != 0 {
		t.Fatalf("expected remaining = 0 when exceeded, got %f", remaining)
	}
}

func TestEntropyTrackerRemainingWithBudget(t *testing.T) {
	et := NewEntropyTracker(testDefaultBudget, testDefaultWindow)
	defer et.Close()

	// No recordings: remaining should equal full budget.
	remaining := et.Remaining(testSessionKey)
	if remaining != testDefaultBudget {
		t.Fatalf("expected remaining %f, got %f", testDefaultBudget, remaining)
	}

	bits := et.Record(testSessionKey, []byte("test"))
	remaining = et.Remaining(testSessionKey)
	expected := testDefaultBudget - bits
	if remaining != expected {
		t.Fatalf("expected remaining %f, got %f", expected, remaining)
	}
}

func TestEntropyTrackerBudget(t *testing.T) {
	et := NewEntropyTracker(testDefaultBudget, testDefaultWindow)
	defer et.Close()

	if et.Budget() != testDefaultBudget {
		t.Fatalf("expected budget %f, got %f", testDefaultBudget, et.Budget())
	}
}

func TestEntropyTrackerUnknownSession(t *testing.T) {
	et := NewEntropyTracker(testDefaultBudget, testDefaultWindow)
	defer et.Close()

	// Unknown session should report zero usage and not be exceeded.
	if et.CurrentUsage("nonexistent") != 0 {
		t.Fatal("expected 0 usage for unknown session")
	}
	if et.BudgetExceeded("nonexistent") {
		t.Fatal("expected budget not exceeded for unknown session")
	}
	if et.Remaining("nonexistent") != testDefaultBudget {
		t.Fatal("expected full budget remaining for unknown session")
	}
}

func TestEntropyTrackerCloseIdempotent(t *testing.T) {
	et := NewEntropyTracker(testDefaultBudget, testDefaultWindow)

	// Multiple Close calls should not panic.
	et.Close()
	et.Close()
	et.Close()
}

func TestEntropyTrackerMultipleRecordings(t *testing.T) {
	et := NewEntropyTracker(testDefaultBudget, testDefaultWindow)
	defer et.Close()

	bits1 := et.Record(testSessionKey, []byte("first payload"))
	bits2 := et.Record(testSessionKey, []byte("second payload"))

	usage := et.CurrentUsage(testSessionKey)
	expected := bits1 + bits2
	if usage != expected {
		t.Fatalf("expected cumulative usage %f, got %f", expected, usage)
	}
}

func TestEntropyTrackerCleanup(t *testing.T) {
	// Use a 1-second window so entries expire quickly for the cleanup test.
	et := NewEntropyTracker(testDefaultBudget, 1)
	defer et.Close()

	// Record data for two sessions.
	et.Record(testSessionKey, []byte("data for session one"))
	et.Record(testSessionKey2, []byte("data for session two"))

	// Both sessions should have non-zero usage now.
	if et.CurrentUsage(testSessionKey) == 0 {
		t.Fatal("expected non-zero usage for session 1 immediately after recording")
	}
	if et.CurrentUsage(testSessionKey2) == 0 {
		t.Fatal("expected non-zero usage for session 2 immediately after recording")
	}

	// Wait for the window to expire.
	time.Sleep(1200 * time.Millisecond) // 1.2s: comfortably past the 1s window

	// Call cleanup directly to evict expired entries without waiting
	// for the 60-second cleanup ticker.
	et.cleanup()

	// After cleanup, the expired sessions should be removed entirely.
	// Verify by checking that no entries exist (usage reports zero for
	// expired entries, and cleanup removes the map keys).
	et.mu.Lock()
	sessionCount := len(et.sessions)
	et.mu.Unlock()

	if sessionCount != 0 {
		t.Errorf("expected 0 sessions after cleanup, got %d", sessionCount)
	}
}

func TestEntropyTrackerCleanup_RetainsValidEntries(t *testing.T) {
	// Use a 2-second window.
	et := NewEntropyTracker(testDefaultBudget, 2)
	defer et.Close()

	// Record old data, let it expire.
	et.Record(testSessionKey, []byte("old data that will expire"))
	time.Sleep(2200 * time.Millisecond) // 2.2s: past the 2s window

	// Record fresh data for session 2 (still within window).
	et.Record(testSessionKey2, []byte("fresh data still valid"))

	// Run cleanup.
	et.cleanup()

	// Session 1 should be removed (all entries expired).
	et.mu.Lock()
	_, session1Exists := et.sessions[testSessionKey]
	_, session2Exists := et.sessions[testSessionKey2]
	et.mu.Unlock()

	if session1Exists {
		t.Error("expected session 1 to be removed after cleanup (all entries expired)")
	}
	if !session2Exists {
		t.Error("expected session 2 to be retained (has valid entries)")
	}
}
