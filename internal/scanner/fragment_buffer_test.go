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
	return MustNew(cfg)
}

func TestFragmentBuffer_OpportunisticCleanup(t *testing.T) {
	fb := NewFragmentBuffer(1024, 10, 1)
	expiredAt := time.Now().Add(-2 * time.Second)
	fb.sessions["expired"] = &sessionBuffer{
		fragments:  []fragment{{data: []byte("old"), at: expiredAt}},
		totalBytes: 3,
	}
	fb.lastCleanup = time.Now().Add(-2 * time.Second)

	fb.Append("active", []byte("fresh"))

	if _, exists := fb.sessions["expired"]; exists {
		t.Fatal("expired fragment session survived opportunistic cleanup")
	}
	if _, exists := fb.sessions["active"]; !exists {
		t.Fatal("active fragment session was not preserved")
	}
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

func TestFragmentBuffer_GlobalCapacityDeniesAdditionalStreams(t *testing.T) {
	fb := NewFragmentBuffer(1024, 3, testWindowSecs)
	t.Cleanup(fb.Close)

	for _, stream := range []string{"first", "second", "third"} {
		if result := fb.AppendForSession(stream, []byte("ordinary")); result.CapacityExceeded {
			t.Fatalf("stream %q result = %+v, want admission", stream, result)
		}
	}
	if result := fb.AppendForSession("fourth", []byte("ordinary")); !result.CapacityExceeded {
		t.Fatalf("over-capacity result = %+v, want capacity denial", result)
	}
}

// A logical identity may hold many streams (raw body, one per JSON bucket,
// query keys, path positions) and they must cost ONE global ledger slot. The
// alternative was measured: charging the ledger per stream let one client take
// 4,099 of 10,000 slots, so roughly three clients denied everyone else.
func TestFragmentBuffer_OwnedStreamsShareOneLedgerSlot(t *testing.T) {
	fb := NewFragmentBuffer(1024, 1, testWindowSecs)
	t.Cleanup(fb.Close)

	for _, stream := range []string{"client-a|raw", "client-a|body-json/1", "client-a|body-json/2", "client-a|keys"} {
		if result := fb.AppendOwned("client-a", stream, []byte("ordinary")); result.CapacityExceeded || result.OwnerMismatch {
			t.Fatalf("owner stream %q result = %+v, want admission under one identity slot", stream, result)
		}
	}
	if result := fb.AppendPathSegmentsOwned("client-a", "client-a|path", [][]byte{[]byte("upload")}); result.CapacityExceeded || result.OwnerMismatch {
		t.Fatalf("owner path stream result = %+v, want admission under one identity slot", result)
	}
	// A SECOND identity needs a slot of its own, and the ledger holds one, so
	// it is refused rather than admitted or silently skipped.
	if result := fb.AppendOwned("client-b", "client-b|raw", []byte("ordinary")); !result.CapacityExceeded {
		t.Fatalf("second identity result = %+v, want capacity denial", result)
	}
	if result := fb.AppendOwned("client-a", "client-a|body-json/3", []byte("more")); result.CapacityExceeded || result.OwnerMismatch {
		t.Fatalf("established identity result = %+v, want continued admission", result)
	}
}

// The configured byte cap must bound a BUDGET GROUP, not each stream in it.
// JSON buckets are the one stream class whose cardinality an attacker chooses,
// The ledger admits identities, so a per-stream budget let one identity hold
// thousands of separately-capped streams: measured at 4,096 buckets times the
// 64 KiB stream cap, one client could retain 256 MiB and the fleet-wide
// ceiling became the configured figure times the bucket cardinality, roughly
// 2.5 TiB instead of 625 MiB. Partitioning has to improve detection inside
// the existing memory envelope, not widen it.
func TestFragmentBuffer_ByteBudgetBoundsTheGroupNotEachStream(t *testing.T) {
	const capBytes = 4096
	payload := make([]byte, capBytes)
	for i := range payload {
		payload[i] = 'A'
	}

	for _, streams := range []int{1, 10, 500} {
		fb := NewFragmentBuffer(capBytes, 10, testWindowSecs)
		for i := 0; i < streams; i++ {
			fb.AppendOwnedInGroup("client-a", "client-a|json", fmt.Sprintf("client-a|bucket/%d", i), payload)
		}
		if got := fb.TotalBufferBytes(); got > capBytes {
			t.Fatalf("one identity across %d streams retained %d bytes, want at most %d", streams, got, capBytes)
		}
		fb.Close()
	}

	// Separate identities are budgeted separately: the cap is per identity, so
	// one client cannot shrink another's retention window.
	fb := NewFragmentBuffer(capBytes, 10, testWindowSecs)
	t.Cleanup(fb.Close)
	for i := 0; i < 4; i++ {
		owner := fmt.Sprintf("client-%d", i)
		fb.AppendOwnedInGroup(owner, owner+"|json", owner+"|raw", payload)
	}
	if got := fb.TotalBufferBytes(); got != 4*capBytes {
		t.Fatalf("four identities retained %d bytes, want %d; the cap must apply per identity", got, 4*capBytes)
	}
}

// Eviction under the identity budget keeps the NEWEST bytes, because those are
// the ones that can complete a split secret, and it never reaches into another
// identity's evidence.
func TestFragmentBuffer_IdentityEvictionKeepsNewestAndSparesOthers(t *testing.T) {
	fb := NewFragmentBuffer(32, 10, testWindowSecs)
	t.Cleanup(fb.Close)

	victim := "client-victim"
	victimStream := victim + "|raw"
	fb.AppendOwned(victim, victimStream, []byte("victim-evidence"))
	fb.mu.Lock()
	victimBefore := fb.sessions[victimStream].totalBytes
	fb.mu.Unlock()

	greedy := "client-greedy"
	for i := 0; i < 20; i++ {
		fb.AppendOwnedInGroup(greedy, greedy+"|json", fmt.Sprintf("%s|bucket/%d", greedy, i), []byte("0123456789"))
	}

	// Assert the VICTIM's own retained bytes, not the aggregate. The buffer
	// total is the wrong instrument for an isolation claim: the greedy
	// identity's own retention can hold the total up while the victim's
	// fragments are evicted underneath it, so the aggregate check passes on
	// exactly the failure this test names.
	fb.mu.Lock()
	victimStreamAfter := fb.sessions[victimStream]
	fb.mu.Unlock()
	if victimStreamAfter == nil {
		t.Fatal("the victim's stream was deleted; eviction crossed an identity boundary")
	}
	if victimStreamAfter.totalBytes != victimBefore {
		t.Fatalf("victim retains %d bytes, want %d; eviction crossed an identity boundary", victimStreamAfter.totalBytes, victimBefore)
	}
}

// Ownership is enforced on the stream, not merely accounted for. Without this
// guard an append whose stream key already exists skipped the ownership check
// entirely and blended the two identities' fragments, which both manufactures
// a match from unrelated clients' data and lets one client pad another's
// evidence. Production keys embed the session key so this is unreachable
// today, but that invariant was held by convention at three call sites and by
// nothing at the boundary itself.
func TestFragmentBuffer_RefusesForeignOwnerOnExistingStream(t *testing.T) {
	t.Run("data stream", func(t *testing.T) {
		fb := NewFragmentBuffer(1024, 8, testWindowSecs)
		t.Cleanup(fb.Close)

		if result := fb.AppendOwned("client-a", "shared", []byte("AKI"+"AIOSFODNN")); result.OwnerMismatch {
			t.Fatalf("first owner result = %+v, want admission", result)
		}
		result := fb.AppendOwned("client-b", "shared", []byte("7EXAMPLE"))
		if !result.OwnerMismatch {
			t.Fatalf("foreign owner result = %+v, want OwnerMismatch; blending identities is never safe", result)
		}
		if result.CapacityExceeded {
			t.Fatalf("foreign owner result = %+v, want the mismatch reason alone; capacity is not why this was refused", result)
		}
	})

	t.Run("path stream", func(t *testing.T) {
		fb := NewFragmentBuffer(1024, 8, testWindowSecs)
		t.Cleanup(fb.Close)

		if result := fb.AppendPathSegmentsOwned("client-a", "shared", [][]byte{[]byte("first")}); result.OwnerMismatch {
			t.Fatalf("first owner result = %+v, want admission", result)
		}
		if result := fb.AppendPathSegmentsOwned("client-b", "shared", [][]byte{[]byte("second")}); !result.OwnerMismatch {
			t.Fatalf("foreign owner path result = %+v, want OwnerMismatch", result)
		}
	})

	// The refusal must not leak across identities in the other direction: the
	// rightful owner keeps working after a foreign append is refused.
	t.Run("owner unaffected by a refused foreign append", func(t *testing.T) {
		fb := NewFragmentBuffer(1024, 8, testWindowSecs)
		t.Cleanup(fb.Close)

		fb.AppendOwned("client-a", "shared", []byte("ordinary"))
		fb.AppendOwned("client-b", "shared", []byte("foreign"))
		if result := fb.AppendOwned("client-a", "shared", []byte("more")); result.OwnerMismatch || result.CapacityExceeded {
			t.Fatalf("rightful owner result = %+v, want continued admission", result)
		}
	})
}

func TestFragmentBuffer_PartitionKeyLivesWithBuffer(t *testing.T) {
	fb := NewFragmentBuffer(1024, 2, testWindowSecs)
	key := fb.PartitionKey()
	if len(key) != 32 {
		t.Fatalf("partition key length = %d, want 32", len(key))
	}
	fb.UpdateConfig(512, 2, testWindowSecs)
	afterReload := fb.PartitionKey()
	if string(afterReload) != string(key) {
		t.Fatal("UpdateConfig rotated the partition key while fragments can still exist")
	}
	// The key must survive Close. A hot reload swaps the buffer pointer and
	// then closes the old buffer, so a request still holding it would read an
	// empty key, decline to partition, and spend the rest of its life on the
	// raw stream alone, which cannot rejoin a padded split.
	fb.Close()
	if got := fb.PartitionKey(); string(got) != string(key) {
		t.Fatal("Close discarded the partition key; an in-flight request holding this buffer would stop partitioning")
	}
	if got := (*FragmentBuffer)(nil).PartitionKey(); got != nil {
		t.Fatalf("nil buffer partition key = %x", got)
	}
}

func TestFragmentBuffer_DeletesPrefixAcrossStreamsAndPaths(t *testing.T) {
	fb := NewFragmentBuffer(1024, 4, testWindowSecs)
	t.Cleanup(fb.Close)
	if result := fb.AppendForSession("owner/raw", []byte("raw")); result.CapacityExceeded {
		t.Fatalf("raw result = %+v", result)
	}
	if result := fb.AppendPathSegmentsForSession("owner/path", [][]byte{[]byte("route")}); result.CapacityExceeded {
		t.Fatalf("path result = %+v", result)
	}
	fb.UpdateConfig(512, 2, testWindowSecs)
	if fb.maxSessions != 2 {
		t.Fatalf("max sessions = %d, want 2", fb.maxSessions)
	}
	fb.DeletePrefix("owner/")
	if len(fb.sessions) != 0 || len(fb.pathSessions) != 0 {
		t.Fatalf("DeletePrefix retained streams: sessions=%d paths=%d", len(fb.sessions), len(fb.pathSessions))
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

func TestFragmentBuffer_MaxSessionsCapacityDeniesNewSession(t *testing.T) {
	// Max 3 sessions. A fourth session must be denied without discarding
	// accumulated state for any existing session.
	fb := NewFragmentBuffer(65536, 3, testWindowSecs)
	defer fb.Close()

	fb.Append(testSessionA, []byte("data-a"))
	fb.Append(testSessionB, []byte("data-b"))
	fb.Append(testSessionC, []byte("data-c"))

	// Add more state to session A to prove known sessions remain admissible.
	fb.Append(testSessionA, []byte("more-a"))

	// A new session at capacity must fail closed rather than evict session B.
	if result := fb.Append(testSessionD, []byte("data-d")); !result.CapacityExceeded {
		t.Fatal("new fragment session at capacity was admitted")
	}

	fb.mu.Lock()
	sessionCount := len(fb.sessions)
	sessionA, hasA := fb.sessions[testSessionA]
	sessionB, hasB := fb.sessions[testSessionB]
	sessionC, hasC := fb.sessions[testSessionC]
	_, hasD := fb.sessions[testSessionD]
	bytesA, bytesB, bytesC := 0, 0, 0
	if hasA {
		bytesA = sessionA.totalBytes
	}
	if hasB {
		bytesB = sessionB.totalBytes
	}
	if hasC {
		bytesC = sessionC.totalBytes
	}
	fb.mu.Unlock()

	if sessionCount != 3 {
		t.Errorf("expected exactly 3 sessions, got %d", sessionCount)
	}
	if !hasA {
		t.Error("session A must remain after a new-session capacity refusal")
	}
	if !hasB {
		t.Error("session B must remain after a new-session capacity refusal")
	}
	if hasD {
		t.Error("session D must not be created after capacity refusal")
	}
	if bytesA != len("data-a")+len("more-a") || bytesB != len("data-b") || bytesC != len("data-c") {
		t.Fatalf("preserved session bytes = A:%d B:%d C:%d", bytesA, bytesB, bytesC)
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

	// The secret spans two surviving fragments - should be detected.
	matches := fb.ScanForSecrets(context.Background(), testSessionA, sc)
	if len(matches) == 0 {
		t.Error("cross-fragment secret should survive eviction and trigger DLP match")
	}
}

func TestFragmentBuffer_SingleFragmentNotReported(t *testing.T) {
	// A complete secret in a single fragment should NOT fire fragment DLP.
	// Body DLP already catches it - double-scoring causes adaptive death spiral.
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
	sc := MustNew(cfg)
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

	// sess-a should be gone - verify via TotalBufferBytes reflecting only sess-b.
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

// A reload that LOWERS the byte cap has to bring already-retained grouped
// streams within it immediately. Enforcing only on the next append means a
// tightened memory limit does not apply to the traffic currently held, which is
// exactly the traffic the operator tightened the limit because of.
func TestFragmentBuffer_ReloadReenforcesTheGroupBudget(t *testing.T) {
	fb := NewFragmentBuffer(4096, 10, testWindowSecs)
	t.Cleanup(fb.Close)

	payload := make([]byte, 512)
	for i := range payload {
		payload[i] = 'A'
	}
	for i := 0; i < 8; i++ {
		fb.AppendOwnedInGroup("client-a", "client-a|json", fmt.Sprintf("client-a|bucket/%d", i), payload)
	}
	before := fb.TotalBufferBytes()
	if before <= 1024 {
		t.Fatalf("setup retained %d bytes, want more than the post-reload cap so the reload has work to do", before)
	}

	fb.UpdateConfig(1024, 10, testWindowSecs)

	// No append happens between the reload and this check on purpose.
	if got := fb.TotalBufferBytes(); got > 1024 {
		t.Fatalf("after lowering the cap to 1024 the buffer still holds %d bytes; the new limit did not apply until the next append", got)
	}
}

// Window expiry is per stream. A data stream and a path stream can share a key,
// and expiring the data half must not discard path evidence that is still live,
// because that silently drops the positions a later request could complete a
// split secret across.
func TestFragmentBuffer_ExpiryDeletesOnlyTheStreamKindThatAgedOut(t *testing.T) {
	fb := NewFragmentBuffer(1024, 10, testWindowSecs)
	t.Cleanup(fb.Close)

	const shared = "client-a|shared"
	fb.AppendOwned("client-a", shared, []byte("data-half"))
	fb.AppendPathSegmentsOwned("client-a", shared, [][]byte{[]byte("path-half")})

	fb.mu.Lock()
	// Age the DATA stream past the window while the path stream stays current.
	if sb := fb.sessions[shared]; sb != nil {
		for i := range sb.fragments {
			sb.fragments[i].at = time.Now().Add(-2 * time.Duration(testWindowSecs) * time.Second)
		}
	}
	fb.cleanupLocked(time.Now())
	_, dataLives := fb.sessions[shared]
	_, pathLives := fb.pathSessions[shared]
	fb.mu.Unlock()

	if dataLives {
		t.Fatal("the expired data stream survived cleanup")
	}
	if !pathLives {
		t.Fatal("cleanup deleted the live path stream because a data stream shared its key")
	}
}

// A nil FragmentBuffer must be safe for the delete methods, matching Close and
// AppendPathSegmentsOwned. ResetCEEState guards with a nil check today, but the
// buffer is the right place for the invariant so a future caller cannot panic.
func TestFragmentBufferNilDeletesAreSafe(t *testing.T) {
	var fb *FragmentBuffer
	fb.Delete("k")
	fb.DeletePrefix("k|body-json|")
}
