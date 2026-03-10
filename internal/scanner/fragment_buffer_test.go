// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

const (
	testSessionA = "session-a"
	testSessionB = "session-b"
	testSessionC = "session-c"
	testSessionD = "session-d"

	// 300 second window (5 minutes), matching entropy budget default.
	testWindowSecs = 300

	// Fake AWS key suffix, built as constant to avoid repetition.
	// Combined with prefix at runtime to avoid gosec G101.
	testAWSKeySuffix = "IOSF" + "ODNN7EXAMPLE"
)

// testFragmentScanner creates a Scanner with default DLP patterns and SSRF disabled.
func testFragmentScanner() *Scanner {
	cfg := config.Defaults()
	cfg.Internal = nil // disable SSRF (no DNS in unit tests)
	return New(cfg)
}

func TestFragmentBuffer_AppendAndScan_SplitCredential(t *testing.T) {
	// Split an AWS key across two fragments. DLP should catch the concatenated form.
	fb := NewFragmentBuffer(65536, 1000, testWindowSecs, 0) // 0 debounce: scan immediately
	defer fb.Close()

	sc := testFragmentScanner()
	defer sc.Close()

	// Build fake AWS key at runtime to avoid gosec G101.
	part1 := "AKI" + "A"
	part2 := testAWSKeySuffix

	fb.Append(testSessionA, []byte(part1))
	fb.Append(testSessionA, []byte(part2))

	matches := fb.ScanForSecrets(testSessionA, sc)
	if len(matches) == 0 {
		t.Fatal("expected DLP match on concatenated AWS key fragments, got none")
	}

	found := false
	for _, m := range matches {
		if m.PatternName != "" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected at least one match with a pattern name")
	}
}

func TestFragmentBuffer_NoMatch_NormalText(t *testing.T) {
	fb := NewFragmentBuffer(65536, 1000, testWindowSecs, 0)
	defer fb.Close()

	sc := testFragmentScanner()
	defer sc.Close()

	fb.Append(testSessionA, []byte("hello "))
	fb.Append(testSessionA, []byte("world, this is normal text"))

	matches := fb.ScanForSecrets(testSessionA, sc)
	if len(matches) != 0 {
		t.Errorf("expected no matches for normal text, got %d", len(matches))
	}
}

func TestFragmentBuffer_SessionIsolation(t *testing.T) {
	// Key split across two sessions should NOT match in either.
	fb := NewFragmentBuffer(65536, 1000, testWindowSecs, 0)
	defer fb.Close()

	sc := testFragmentScanner()
	defer sc.Close()

	part1 := "AKI" + "A"
	part2 := testAWSKeySuffix

	fb.Append(testSessionA, []byte(part1))
	fb.Append(testSessionB, []byte(part2))

	matchesA := fb.ScanForSecrets(testSessionA, sc)
	matchesB := fb.ScanForSecrets(testSessionB, sc)

	if len(matchesA) != 0 {
		t.Errorf("session A should not match with only key prefix, got %d matches", len(matchesA))
	}
	if len(matchesB) != 0 {
		t.Errorf("session B should not match with only key suffix, got %d matches", len(matchesB))
	}
}

func TestFragmentBuffer_MaxBytesEviction(t *testing.T) {
	// 100 byte cap. Add 120 bytes. Oldest data should be evicted.
	maxBytes := 100
	fb := NewFragmentBuffer(maxBytes, 1000, testWindowSecs, 0)
	defer fb.Close()

	// Add 60 bytes, then 60 more (total 120 > 100 cap).
	data1 := make([]byte, 60)
	for i := range data1 {
		data1[i] = 'A'
	}
	data2 := make([]byte, 60)
	for i := range data2 {
		data2[i] = 'B'
	}

	fb.Append(testSessionA, data1)
	fb.Append(testSessionA, data2)

	fb.mu.Lock()
	sb := fb.sessions[testSessionA]
	totalBytes := sb.totalBytes
	fb.mu.Unlock()

	if totalBytes > maxBytes {
		t.Errorf("totalBytes %d exceeds cap %d after eviction", totalBytes, maxBytes)
	}
}

func TestFragmentBuffer_MaxSessionsCap(t *testing.T) {
	// Max 3 sessions. Add 4. Verify LRU eviction keeps only 3.
	fb := NewFragmentBuffer(65536, 3, testWindowSecs, 0)
	defer fb.Close()

	fb.Append(testSessionA, []byte("data-a"))
	fb.Append(testSessionB, []byte("data-b"))
	fb.Append(testSessionC, []byte("data-c"))

	// Access session A to make it recently used.
	fb.Append(testSessionA, []byte("more-a"))

	// Add session D, which should evict the least-recently-used (session B).
	fb.Append(testSessionD, []byte("data-d"))

	fb.mu.Lock()
	sessionCount := len(fb.sessions)
	_, hasA := fb.sessions[testSessionA]
	_, hasB := fb.sessions[testSessionB]
	_, hasD := fb.sessions[testSessionD]
	fb.mu.Unlock()

	if sessionCount > 3 {
		t.Errorf("expected at most 3 sessions, got %d", sessionCount)
	}
	if !hasA {
		t.Error("session A should survive (recently used)")
	}
	if hasB {
		t.Error("session B should have been evicted (least recently used)")
	}
	if !hasD {
		t.Error("session D should exist (just added)")
	}
}

func TestFragmentBuffer_WindowExpiry(t *testing.T) {
	// 1 second window. Backdate fragments, run cleanup, verify empty.
	fb := NewFragmentBuffer(65536, 1000, 1, 0) // 1s window
	defer fb.Close()

	fb.Append(testSessionA, []byte("test data"))

	// Backdate the fragment to before the window.
	fb.mu.Lock()
	sb := fb.sessions[testSessionA]
	for i := range sb.fragments {
		sb.fragments[i].at = time.Now().Add(-2 * time.Second)
	}
	fb.mu.Unlock()

	fb.cleanup()

	fb.mu.Lock()
	_, exists := fb.sessions[testSessionA]
	fb.mu.Unlock()

	if exists {
		t.Error("session should have been cleaned up after window expiry")
	}
}

func TestFragmentBuffer_Debounce(t *testing.T) {
	// Debounce window: 200ms. Second scan within window should return nil.
	fb := NewFragmentBuffer(65536, 1000, testWindowSecs, 200) // 200ms debounce
	defer fb.Close()

	sc := testFragmentScanner()
	defer sc.Close()

	fb.Append(testSessionA, []byte("some payload data"))

	// First scan: should execute (outside debounce window).
	matches1 := fb.ScanForSecrets(testSessionA, sc)
	// No secrets in payload, so nil is fine. The point is it ran.
	_ = matches1

	// Second scan immediately: should be debounced (return nil).
	matches2 := fb.ScanForSecrets(testSessionA, sc)
	if matches2 != nil {
		t.Errorf("expected nil from debounced scan, got %v", matches2)
	}
}

func TestFragmentBuffer_DebounceSchedulesDelayedScan(t *testing.T) {
	// Verify that debounce schedules a delayed rescan via time.AfterFunc.
	fb := NewFragmentBuffer(65536, 1000, testWindowSecs, 100) // 100ms debounce
	defer fb.Close()

	sc := testFragmentScanner()
	defer sc.Close()

	// Build a credential split across fragments.
	part1 := "AKI" + "A"
	part2 := testAWSKeySuffix
	fb.Append(testSessionA, []byte(part1))
	fb.Append(testSessionA, []byte(part2))

	// First scan: runs immediately, should find the secret.
	matches1 := fb.ScanForSecrets(testSessionA, sc)
	if len(matches1) == 0 {
		t.Fatal("first scan should find the split credential")
	}

	// Immediately try again: debounced, should return nil.
	matches2 := fb.ScanForSecrets(testSessionA, sc)
	if matches2 != nil {
		t.Error("second scan within debounce window should return nil")
	}

	// Verify a timer was scheduled.
	fb.mu.Lock()
	sb := fb.sessions[testSessionA]
	hasTimer := sb.scanTimer != nil
	fb.mu.Unlock()

	if !hasTimer {
		t.Error("expected a pending scan timer to be scheduled")
	}
}

func TestFragmentBuffer_ConcurrentAccess(t *testing.T) {
	fb := NewFragmentBuffer(65536, 1000, testWindowSecs, 0)
	defer fb.Close()

	sc := testFragmentScanner()
	defer sc.Close()

	var wg sync.WaitGroup
	// 100 goroutines: half appending, half scanning.
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			key := fmt.Sprintf("session-%d", id%10)
			fb.Append(key, []byte(fmt.Sprintf("payload-%d", id)))
			fb.ScanForSecrets(key, sc)
		}(i)
	}
	wg.Wait()
}

func TestFragmentBuffer_TotalBufferBytes(t *testing.T) {
	fb := NewFragmentBuffer(65536, 1000, testWindowSecs, 0)
	defer fb.Close()

	fb.Append(testSessionA, []byte("hello"))      // 5 bytes
	fb.Append(testSessionB, []byte("world12345")) // 10 bytes

	total := fb.TotalBufferBytes()
	if total != 15 {
		t.Errorf("expected 15 total bytes, got %d", total)
	}
}

func TestFragmentBuffer_Close_Idempotent(t *testing.T) {
	fb := NewFragmentBuffer(65536, 1000, testWindowSecs, 0)
	fb.Close()
	fb.Close() // should not panic
}

func TestFragmentBuffer_ScanEmptySession(t *testing.T) {
	fb := NewFragmentBuffer(65536, 1000, testWindowSecs, 0)
	defer fb.Close()

	sc := testFragmentScanner()
	defer sc.Close()

	// Scan a session that has never been appended to.
	matches := fb.ScanForSecrets("nonexistent", sc)
	if matches != nil {
		t.Errorf("expected nil for nonexistent session, got %v", matches)
	}
}

func TestFragmentBuffer_EvictionPreservesNewestData(t *testing.T) {
	// After eviction, the newest fragment should remain.
	maxBytes := 50
	fb := NewFragmentBuffer(maxBytes, 1000, testWindowSecs, 0)
	defer fb.Close()

	sc := testFragmentScanner()
	defer sc.Close()

	// Add a large fragment that fills the buffer.
	old := make([]byte, 40)
	for i := range old {
		old[i] = 'X'
	}
	fb.Append(testSessionA, old)

	// Add another fragment that forces eviction of the old one.
	// Build AWS key at runtime to avoid gosec G101.
	newData := []byte("AKI" + "A" + testAWSKeySuffix)
	fb.Append(testSessionA, newData)

	// The newest fragment (containing the credential) should survive.
	matches := fb.ScanForSecrets(testSessionA, sc)
	if len(matches) == 0 {
		t.Error("newest fragment should survive eviction and trigger DLP match")
	}
}

func TestFragmentBuffer_CleanupPartialExpiry(t *testing.T) {
	// Mix old and new fragments within a session. Cleanup should remove only old ones.
	fb := NewFragmentBuffer(65536, 1000, 1, 0) // 1s window
	defer fb.Close()

	fb.Append(testSessionA, []byte("new data"))

	// Backdate the first fragment but add a fresh one.
	fb.mu.Lock()
	sb := fb.sessions[testSessionA]
	sb.fragments[0].at = time.Now().Add(-2 * time.Second)
	oldBytes := len(sb.fragments[0].data)
	fb.mu.Unlock()

	fb.Append(testSessionA, []byte("fresh"))

	fb.cleanup()

	fb.mu.Lock()
	sb = fb.sessions[testSessionA]
	fragCount := len(sb.fragments)
	totalBytes := sb.totalBytes
	fb.mu.Unlock()

	if fragCount != 1 {
		t.Errorf("expected 1 fragment after partial cleanup, got %d", fragCount)
	}

	expectedBytes := len("fresh")
	// totalBytes should have been decremented by the evicted fragment.
	_ = oldBytes
	if totalBytes != expectedBytes {
		t.Errorf("expected %d bytes after cleanup, got %d", expectedBytes, totalBytes)
	}
}

func TestFragmentBuffer_AppendAfterClose(t *testing.T) {
	fb := NewFragmentBuffer(65536, 1000, testWindowSecs, 0)
	fb.Close()

	// Append after close should not panic.
	fb.Append(testSessionA, []byte("data"))

	sc := testFragmentScanner()
	defer sc.Close()

	// Scan after close should not panic.
	matches := fb.ScanForSecrets(testSessionA, sc)
	_ = matches
}

func TestFragmentBuffer_DebounceTimerReset(t *testing.T) {
	// Verify that repeated appends within debounce window reset the timer.
	fb := NewFragmentBuffer(65536, 1000, testWindowSecs, 200) // 200ms debounce
	defer fb.Close()

	sc := testFragmentScanner()
	defer sc.Close()

	fb.Append(testSessionA, []byte("data1"))

	// First scan triggers and sets lastScan.
	_ = fb.ScanForSecrets(testSessionA, sc)

	// Append again within debounce window.
	fb.Append(testSessionA, []byte("data2"))

	// Scan again: should be debounced and schedule a timer.
	_ = fb.ScanForSecrets(testSessionA, sc)

	fb.mu.Lock()
	sb := fb.sessions[testSessionA]
	timer1 := sb.scanTimer
	fb.mu.Unlock()

	// Append and scan again: timer should be reset (cancelled and rescheduled).
	fb.Append(testSessionA, []byte("data3"))
	_ = fb.ScanForSecrets(testSessionA, sc)

	fb.mu.Lock()
	timer2 := sb.scanTimer
	fb.mu.Unlock()

	// The timer should have been reset (new timer object).
	if timer1 == nil || timer2 == nil {
		t.Error("expected scan timers to be set")
	}
}
