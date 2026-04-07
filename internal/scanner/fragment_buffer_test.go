// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
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
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	return New(cfg)
}

func TestFragmentBuffer_AppendAndScan_SplitCredential(t *testing.T) {
	// Split an AWS key across two fragments. DLP should catch the concatenated form.
	fb := NewFragmentBuffer(65536, 1000, testWindowSecs)
	defer fb.Close()

	sc := testFragmentScanner()
	defer sc.Close()

	// Build fake AWS key at runtime to avoid gosec G101.
	part1 := "AKI" + "A"
	part2 := testAWSKeySuffix

	fb.Append(testSessionA, []byte(part1))
	fb.Append(testSessionA, []byte(part2))

	matches := fb.ScanForSecrets(context.Background(), testSessionA, sc)
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
	fb := NewFragmentBuffer(65536, 1000, testWindowSecs)
	defer fb.Close()

	sc := testFragmentScanner()
	defer sc.Close()

	fb.Append(testSessionA, []byte("hello "))
	fb.Append(testSessionA, []byte("world, this is normal text"))

	matches := fb.ScanForSecrets(context.Background(), testSessionA, sc)
	if len(matches) != 0 {
		t.Errorf("expected no matches for normal text, got %d", len(matches))
	}
}

func TestFragmentBuffer_SessionIsolation(t *testing.T) {
	// Key split across two sessions should NOT match in either.
	fb := NewFragmentBuffer(65536, 1000, testWindowSecs)
	defer fb.Close()

	sc := testFragmentScanner()
	defer sc.Close()

	part1 := "AKI" + "A"
	part2 := testAWSKeySuffix

	fb.Append(testSessionA, []byte(part1))
	fb.Append(testSessionB, []byte(part2))

	matchesA := fb.ScanForSecrets(context.Background(), testSessionA, sc)
	matchesB := fb.ScanForSecrets(context.Background(), testSessionB, sc)

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
	fb := NewFragmentBuffer(maxBytes, 1000, testWindowSecs)
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
	fb := NewFragmentBuffer(65536, 3, testWindowSecs)
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
	fb := NewFragmentBuffer(65536, 1000, 1) // 1s window
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

func TestFragmentBuffer_ScanAlwaysSynchronous(t *testing.T) {
	// Every call to ScanForSecrets runs a synchronous DLP scan. A secret
	// appended after the first scan must be detectable immediately on the
	// next call, with no debounce window.
	fb := NewFragmentBuffer(65536, 1000, testWindowSecs)
	defer fb.Close()

	sc := testFragmentScanner()
	defer sc.Close()

	fb.Append(testSessionA, []byte("harmless data"))
	matches1 := fb.ScanForSecrets(context.Background(), testSessionA, sc)
	if matches1 != nil {
		t.Fatal("first scan should find nothing")
	}

	// Immediately append credential fragments and scan again.
	part1 := "AKI" + "A"
	part2 := testAWSKeySuffix
	fb.Append(testSessionA, []byte(part1))
	fb.Append(testSessionA, []byte(part2))

	matches2 := fb.ScanForSecrets(context.Background(), testSessionA, sc)
	if len(matches2) == 0 {
		t.Fatal("second scan must detect secret synchronously, got nil (pre-forward guarantee broken)")
	}
}

func TestFragmentBuffer_ConcurrentAccess(t *testing.T) {
	fb := NewFragmentBuffer(65536, 1000, testWindowSecs)
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
			fb.ScanForSecrets(context.Background(), key, sc)
		}(i)
	}
	wg.Wait()
}

func TestFragmentBuffer_TotalBufferBytes(t *testing.T) {
	fb := NewFragmentBuffer(65536, 1000, testWindowSecs)
	defer fb.Close()

	fb.Append(testSessionA, []byte("hello"))      // 5 bytes
	fb.Append(testSessionB, []byte("world12345")) // 10 bytes

	total := fb.TotalBufferBytes()
	if total != 15 {
		t.Errorf("expected 15 total bytes, got %d", total)
	}
}

func TestFragmentBuffer_Close_Idempotent(t *testing.T) {
	fb := NewFragmentBuffer(65536, 1000, testWindowSecs)
	fb.Close()
	fb.Close() // should not panic
}

func TestFragmentBuffer_ScanEmptySession(t *testing.T) {
	fb := NewFragmentBuffer(65536, 1000, testWindowSecs)
	defer fb.Close()

	sc := testFragmentScanner()
	defer sc.Close()

	// Scan a session that has never been appended to.
	matches := fb.ScanForSecrets(context.Background(), "nonexistent", sc)
	if matches != nil {
		t.Errorf("expected nil for nonexistent session, got %v", matches)
	}
}

func TestFragmentBuffer_EvictionPreservesNewestData(t *testing.T) {
	// After eviction, the newest fragments should remain and a cross-fragment
	// secret should still be detected.
	maxBytes := 60
	fb := NewFragmentBuffer(maxBytes, 1000, testWindowSecs)
	defer fb.Close()

	sc := testFragmentScanner()
	defer sc.Close()

	// Add a large fragment that fills most of the buffer.
	old := make([]byte, 40)
	for i := range old {
		old[i] = 'X'
	}
	fb.Append(testSessionA, old)

	// Add two fragments that together form an AWS key (split across requests).
	// The old fragment gets evicted but these two survive and span the secret.
	fb.Append(testSessionA, []byte("AKI"+"A"))
	fb.Append(testSessionA, []byte(testAWSKeySuffix))

	// The secret spans two surviving fragments — should be detected.
	matches := fb.ScanForSecrets(context.Background(), testSessionA, sc)
	if len(matches) == 0 {
		t.Error("cross-fragment secret should survive eviction and trigger DLP match")
	}
}

func TestFragmentBuffer_SingleFragmentNotReported(t *testing.T) {
	// A complete secret in a single fragment should NOT fire fragment DLP.
	// Body DLP already catches it — double-scoring causes adaptive death spiral.
	fb := NewFragmentBuffer(65536, 1000, testWindowSecs)
	defer fb.Close()

	sc := testFragmentScanner()
	defer sc.Close()

	// Single fragment with complete secret.
	key := "AKI" + "A" + testAWSKeySuffix
	fb.Append(testSessionA, []byte(key))

	matches := fb.ScanForSecrets(context.Background(), testSessionA, sc)
	if len(matches) != 0 {
		t.Errorf("single-fragment secret should not trigger fragment DLP (body DLP handles it), got %d matches", len(matches))
	}
}

func TestFragmentBuffer_RepeatedIdenticalBodiesNotReported(t *testing.T) {
	// LLM context replay: same secret in every POST body. Each body is a
	// complete fragment. The secret is in each individual fragment, so it
	// should NOT trigger fragment DLP regardless of how many times it's sent.
	fb := NewFragmentBuffer(65536, 1000, testWindowSecs)
	defer fb.Close()

	sc := testFragmentScanner()
	defer sc.Close()

	key := "AKI" + "A" + testAWSKeySuffix
	body := "conversation context with " + key + " embedded"

	// Simulate 5 LLM API calls with same context.
	for range 5 {
		fb.Append(testSessionA, []byte(body))
	}

	matches := fb.ScanForSecrets(context.Background(), testSessionA, sc)
	if len(matches) != 0 {
		t.Errorf("repeated identical bodies should not trigger fragment DLP, got %d matches", len(matches))
	}
}

func TestFragmentBuffer_OldFragmentSecretNotReported(t *testing.T) {
	// A complete secret in an OLDER fragment (not the latest) should be
	// filtered by scanning all individual fragments, not just the latest.
	// Without this fix, the concatenated buffer would match but the latest-
	// only dedup wouldn't catch it, creating a false cross-request signal.
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	sc := New(cfg)
	defer sc.Close()

	fb := NewFragmentBuffer(65536, 1000, 300)
	defer fb.Close()

	// Fragment 1: contains a complete secret.
	fb.Append(testSessionA, []byte("key="+"AKIA"+"IOSFODNN7EXAMPLE"))

	// Fragment 2: clean content, no secret.
	fb.Append(testSessionA, []byte("ok no secrets here"))

	matches := fb.ScanForSecrets(context.Background(), testSessionA, sc)
	if len(matches) != 0 {
		t.Errorf("secret entirely in older fragment should not trigger cross-request signal, got %d matches: %v", len(matches), matches)
	}
}

func TestFragmentBuffer_CleanupPartialExpiry(t *testing.T) {
	// Mix old and new fragments within a session. Cleanup should remove only old ones.
	fb := NewFragmentBuffer(65536, 1000, 1) // 1s window
	defer fb.Close()

	fb.Append(testSessionA, []byte("new data"))

	// Backdate the first fragment but add a fresh one.
	fb.mu.Lock()
	sb := fb.sessions[testSessionA]
	sb.fragments[0].at = time.Now().Add(-2 * time.Second)
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
	if totalBytes != expectedBytes {
		t.Errorf("expected %d bytes after cleanup, got %d", expectedBytes, totalBytes)
	}
}

func TestFragmentBuffer_Delete(t *testing.T) {
	fb := NewFragmentBuffer(4096, 100, 60)
	defer fb.Close()

	fb.Append("sess-a", []byte("fragment-part-1"))
	fb.Append("sess-b", []byte("other-data"))

	fb.Delete("sess-a")

	// sess-a should be gone — verify via TotalBufferBytes reflecting only sess-b.
	fb.mu.Lock()
	_, sessAExists := fb.sessions["sess-a"]
	_, sessBExists := fb.sessions["sess-b"]
	fb.mu.Unlock()

	if sessAExists {
		t.Error("sess-a should not exist after delete")
	}
	if !sessBExists {
		t.Error("sess-b should be unaffected by deleting sess-a")
	}

	// Appending to sess-a again should work (creates fresh session).
	fb.Append("sess-a", []byte("new-data"))
}

func TestFragmentBuffer_Delete_NonExistent(t *testing.T) {
	fb := NewFragmentBuffer(4096, 100, 60)
	defer fb.Close()

	// Should not panic on missing key.
	fb.Delete("no-such-session")
}

func TestFragmentBuffer_AppendAfterClose(t *testing.T) {
	fb := NewFragmentBuffer(65536, 1000, testWindowSecs)
	fb.Close()

	// Append after close should not panic.
	fb.Append(testSessionA, []byte("data"))

	sc := testFragmentScanner()
	defer sc.Close()

	// Scan after close should not panic.
	matches := fb.ScanForSecrets(context.Background(), testSessionA, sc)
	_ = matches
}
