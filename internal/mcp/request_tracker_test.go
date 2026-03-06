// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"encoding/json"
	"sync"
	"testing"
)

func TestRequestTracker_TrackAndValidate(t *testing.T) {
	tr := NewRequestTracker()
	id := json.RawMessage(`1`)
	tr.Track(id)

	if !tr.Validate(id) {
		t.Error("expected Validate to return true for tracked ID")
	}
	// One-shot: second validate should fail.
	if tr.Validate(id) {
		t.Error("expected Validate to return false after consumption")
	}
}

func TestRequestTracker_ValidateWithoutTrack(t *testing.T) {
	tr := NewRequestTracker()
	id := json.RawMessage(`42`)

	if tr.Validate(id) {
		t.Error("expected Validate to return false for untracked ID")
	}
}

func TestRequestTracker_NilID(t *testing.T) {
	tr := NewRequestTracker()

	// nil ID always passes (notifications).
	if !tr.Validate(nil) {
		t.Error("expected nil ID to pass validation")
	}
}

func TestRequestTracker_NullID(t *testing.T) {
	tr := NewRequestTracker()
	nullID := json.RawMessage(`null`)

	// "null" ID always passes.
	if !tr.Validate(nullID) {
		t.Error("expected null ID to pass validation")
	}
}

func TestRequestTracker_EmptyID(t *testing.T) {
	tr := NewRequestTracker()

	// Empty ID always passes.
	if !tr.Validate(json.RawMessage{}) {
		t.Error("expected empty ID to pass validation")
	}
}

func TestRequestTracker_NumericAndStringIDsDistinct(t *testing.T) {
	tr := NewRequestTracker()
	numericID := json.RawMessage(`1`)
	stringID := json.RawMessage(`"1"`)

	tr.Track(numericID)

	// String "1" should not match numeric 1.
	if tr.Validate(stringID) {
		t.Error("expected string ID to not match numeric ID")
	}
	// Numeric 1 should still be valid.
	if !tr.Validate(numericID) {
		t.Error("expected numeric ID to still be valid")
	}
}

func TestRequestTracker_DuplicateTrack(t *testing.T) {
	tr := NewRequestTracker()
	id := json.RawMessage(`"abc"`)

	tr.Track(id)
	tr.Track(id) // Duplicate — should be a no-op.

	if !tr.Validate(id) {
		t.Error("expected first Validate to succeed after duplicate Track")
	}
	if tr.Validate(id) {
		t.Error("expected second Validate to fail (consumed)")
	}
}

func TestRequestTracker_CapEviction(t *testing.T) {
	tr := NewRequestTracker()

	// Fill to capacity.
	for i := range maxTrackedRequests {
		id := json.RawMessage(`"id-` + itoa(i) + `"`)
		tr.Track(id)
	}

	// Track one more — should evict the oldest (id-0).
	overflowID := json.RawMessage(`"overflow"`)
	tr.Track(overflowID)

	// The oldest entry should have been evicted.
	firstID := json.RawMessage(`"id-0"`)
	if tr.Validate(firstID) {
		t.Error("expected id-0 to be evicted after cap overflow")
	}

	// The overflow entry should be valid.
	if !tr.Validate(overflowID) {
		t.Error("expected overflow ID to be valid")
	}

	// An entry near the end should still be valid.
	lastID := json.RawMessage(`"id-` + itoa(maxTrackedRequests-1) + `"`)
	if !tr.Validate(lastID) {
		t.Error("expected last pre-cap ID to still be valid")
	}
}

func TestRequestTracker_Concurrent(t *testing.T) {
	tr := NewRequestTracker()
	const n = 1000

	var wg sync.WaitGroup
	// Track n IDs concurrently.
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := json.RawMessage(`"c-` + itoa(i) + `"`)
			tr.Track(id)
		}(i)
	}
	wg.Wait()

	// Validate n IDs concurrently — each should succeed exactly once.
	results := make([]bool, n)
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := json.RawMessage(`"c-` + itoa(i) + `"`)
			results[i] = tr.Validate(id)
		}(i)
	}
	wg.Wait()

	for i, ok := range results {
		if !ok {
			t.Errorf("expected concurrent Validate(%d) to succeed", i)
		}
	}
}

func TestRequestTracker_NilTracker(t *testing.T) {
	var tr *RequestTracker

	// All operations on nil tracker should be safe.
	tr.Track(json.RawMessage(`1`))
	if !tr.Validate(json.RawMessage(`1`)) {
		t.Error("expected nil tracker Validate to return true")
	}
	if !tr.Validate(json.RawMessage(`999`)) {
		t.Error("expected nil tracker Validate to return true for any ID")
	}
}

func TestRequestTracker_TrackNilID(t *testing.T) {
	tr := NewRequestTracker()

	// Tracking nil ID should be a no-op (notifications don't get responses).
	tr.Track(nil)
	tr.Track(json.RawMessage(`null`))
	tr.Track(json.RawMessage{})

	// Pending set should be empty.
	tr.mu.Lock()
	count := len(tr.pending)
	tr.mu.Unlock()
	if count != 0 {
		t.Errorf("expected 0 pending after tracking nil/null IDs, got %d", count)
	}
}

func TestRequestTracker_Seeded(t *testing.T) {
	tr := NewRequestTracker()

	if tr.Seeded() {
		t.Error("new tracker should not be seeded")
	}

	tr.Track(json.RawMessage(`1`))
	if !tr.Seeded() {
		t.Error("tracker should be seeded after Track")
	}

	// Consuming all IDs doesn't un-seed the tracker.
	tr.Validate(json.RawMessage(`1`))
	if !tr.Seeded() {
		t.Error("tracker should remain seeded after all IDs consumed")
	}
}

func TestRequestTracker_NilSeeded(t *testing.T) {
	var tr *RequestTracker
	if tr.Seeded() {
		t.Error("nil tracker Seeded should return false")
	}
}

// itoa converts an int to a string without importing strconv.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
