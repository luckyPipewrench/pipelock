// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// Test address patterns: ETH-style (0x + 40 hex chars).
var testAddrPatterns = []*regexp.Regexp{
	regexp.MustCompile(`0x[0-9a-fA-F]{40}`),
}

func TestAddressSimilarity_NoAddressesClean(t *testing.T) {
	tracker := NewAddressSimilarityTracker(testAddrPatterns)
	results := tracker.Check("sess1", "normal text with no blockchain addresses")
	if len(results) > 0 {
		t.Errorf("expected no results for clean text, got %d", len(results))
	}
}

func TestAddressSimilarity_SingleAddressNoAlert(t *testing.T) {
	tracker := NewAddressSimilarityTracker(testAddrPatterns)
	addr := "0x" + strings.Repeat("aB", 20) // 0x + 40 hex chars
	results := tracker.Check("sess1", fmt.Sprintf("send to %s", addr))
	if len(results) > 0 {
		t.Error("single address should not trigger alert")
	}
}

func TestAddressSimilarity_SameAddressRepeatNoAlert(t *testing.T) {
	tracker := NewAddressSimilarityTracker(testAddrPatterns)
	addr := "0x" + strings.Repeat("aB", 20)

	tracker.Check("sess1", fmt.Sprintf("send to %s", addr))
	results := tracker.Check("sess1", fmt.Sprintf("confirm send to %s", addr))
	if len(results) > 0 {
		t.Error("repeat of same address should not trigger alert")
	}
}

func TestAddressSimilarity_DifferentAddressDifferentFingerprintNoAlert(t *testing.T) {
	tracker := NewAddressSimilarityTracker(testAddrPatterns)
	addr1 := "0xAA" + strings.Repeat("11", 18) + "AA00" // 42 chars, fingerprint 0xAA...AA00
	addr2 := "0xBB" + strings.Repeat("22", 18) + "BB00" // 42 chars, fingerprint 0xBB...BB00

	tracker.Check("sess1", fmt.Sprintf("send to %s", addr1))
	results := tracker.Check("sess1", fmt.Sprintf("send to %s", addr2))
	if len(results) > 0 {
		t.Error("addresses with different fingerprints should not trigger alert")
	}
}

func TestAddressSimilarity_LookalikeDetected(t *testing.T) {
	tracker := NewAddressSimilarityTracker(testAddrPatterns)

	// Same first 4 and last 4 chars, different middle = poisoning.
	// 0x + 40 hex = 42 chars total. Fingerprint: first 4 = "0xAB", last 4 = "5678".
	legit := "0xAB" + strings.Repeat("11", 17) + "5678" // 0xAB + 34 chars + 5678 = 42
	fake := "0xAB" + strings.Repeat("99", 17) + "5678"  // same prefix+suffix, different middle

	tracker.Check("sess1", fmt.Sprintf("send to %s", legit))
	results := tracker.Check("sess1", fmt.Sprintf("send to %s", fake))
	if len(results) == 0 {
		t.Fatal("expected lookalike alert for address poisoning")
	}
	// Canonicalized to lowercase.
	legitLower := strings.ToLower(legit)
	fakeLower := strings.ToLower(fake)
	if results[0].KnownAddress != legitLower {
		t.Errorf("expected known address %s, got %s", legitLower, results[0].KnownAddress)
	}
	if results[0].NewAddress != fakeLower {
		t.Errorf("expected new address %s, got %s", fakeLower, results[0].NewAddress)
	}
	expectedPrefix := legitLower[:fingerprintLen]
	expectedSuffix := legitLower[len(legitLower)-fingerprintLen:]
	if results[0].Prefix != expectedPrefix {
		t.Errorf("expected prefix %q, got %q", expectedPrefix, results[0].Prefix)
	}
	if results[0].Suffix != expectedSuffix {
		t.Errorf("expected suffix %q, got %q", expectedSuffix, results[0].Suffix)
	}
}

func TestAddressSimilarity_CrossSessionIsolation(t *testing.T) {
	tracker := NewAddressSimilarityTracker(testAddrPatterns)

	legit := "0xAB" + strings.Repeat("11", 17) + "5678"
	fake := "0xAB" + strings.Repeat("99", 17) + "5678"

	// Different sessions: no alert even with same fingerprint.
	tracker.Check("sess1", fmt.Sprintf("send to %s", legit))
	results := tracker.Check("sess2", fmt.Sprintf("send to %s", fake))
	if len(results) > 0 {
		t.Error("addresses in different sessions should not trigger cross-session alerts")
	}
}

func TestAddressSimilarity_MultipleAddressesInOneRequest(t *testing.T) {
	tracker := NewAddressSimilarityTracker(testAddrPatterns)

	legit := "0xAB" + strings.Repeat("11", 17) + "5678"
	fake := "0xAB" + strings.Repeat("99", 17) + "5678"

	// Both addresses in the same request text.
	text := fmt.Sprintf("send %s to %s", legit, fake)
	results := tracker.Check("sess1", text)
	if len(results) == 0 {
		t.Fatal("expected lookalike alert when both addresses appear in same request")
	}
}

func TestAddressSimilarity_AddressInToolArguments(t *testing.T) {
	tracker := NewAddressSimilarityTracker(testAddrPatterns)

	legit := "0xAB" + strings.Repeat("11", 17) + "5678"
	fake := "0xAB" + strings.Repeat("99", 17) + "5678"

	// Simulate MCP tool call arguments.
	tracker.Check("sess1", fmt.Sprintf(`{"to":"%s","value":"1000000000000000000"}`, legit))
	results := tracker.Check("sess1", fmt.Sprintf(`{"to":"%s","value":"1000000000000000000"}`, fake))
	if len(results) == 0 {
		t.Fatal("expected lookalike alert in tool arguments")
	}
}

func TestAddressSimilarity_MaxSessionEviction(t *testing.T) {
	tracker := NewAddressSimilarityTracker(testAddrPatterns)
	tracker.maxSessions = 3

	addr := "0x" + strings.Repeat("aB", 20)
	for i := 0; i < 5; i++ {
		tracker.Check(fmt.Sprintf("sess%d", i), fmt.Sprintf("send to %s", addr))
	}

	if tracker.SessionCount() > 3 {
		t.Errorf("expected max 3 sessions, got %d", tracker.SessionCount())
	}
}

func TestAddressSimilarity_Reset(t *testing.T) {
	tracker := NewAddressSimilarityTracker(testAddrPatterns)
	addr := "0x" + strings.Repeat("aB", 20)
	tracker.Check("sess1", fmt.Sprintf("send to %s", addr))

	if tracker.SessionCount() != 1 {
		t.Fatalf("expected 1 session, got %d", tracker.SessionCount())
	}

	tracker.Reset()
	if tracker.SessionCount() != 0 {
		t.Errorf("expected 0 sessions after reset, got %d", tracker.SessionCount())
	}
}

func TestAddressSimilarity_NoPatterns(t *testing.T) {
	tracker := NewAddressSimilarityTracker(nil)
	results := tracker.Check("sess1", "0x"+strings.Repeat("aB", 20))
	if len(results) > 0 {
		t.Error("tracker with no patterns should return no results")
	}
}

func TestAddressSimilarity_CaseCanonicalizedNoFalsePositive(t *testing.T) {
	tracker := NewAddressSimilarityTracker(testAddrPatterns)

	// EIP-55 checksum vs lowercase: same logical address, different case.
	// Canonicalization lowercases both, so they match as the same address
	// and should NOT alert.
	addr1 := "0xAb" + strings.Repeat("aA", 17) + "1234" // 42 chars, mixed case
	addr2 := "0xab" + strings.Repeat("aa", 17) + "1234" // same address, all lowercase

	tracker.Check("sess1", fmt.Sprintf("send to %s", addr1))
	results := tracker.Check("sess1", fmt.Sprintf("send to %s", addr2))

	if len(results) > 0 {
		t.Error("case-different versions of the same address should NOT alert after canonicalization")
	}
}

func TestAddressSimilarity_EvictionOnlyOnNewSession(t *testing.T) {
	tracker := NewAddressSimilarityTracker(testAddrPatterns)
	tracker.maxSessions = 2

	// addr and poisoned share fingerprint (first 4 + last 4) but differ in middle.
	addr := "0xab" + strings.Repeat("11", 17) + "cd00"     // fingerprint: 0xab...cd00
	poisoned := "0xab" + strings.Repeat("99", 17) + "cd00" // same fingerprint, different middle

	// Fill two sessions.
	tracker.Check("sess1", fmt.Sprintf("send to %s", addr))
	tracker.Check("sess2", fmt.Sprintf("send to %s", addr))

	// Access existing session at capacity: should NOT evict anything.
	tracker.Check("sess1", fmt.Sprintf("confirm %s", addr))
	if tracker.SessionCount() != 2 {
		t.Fatalf("expected 2 sessions after accessing existing, got %d", tracker.SessionCount())
	}

	// Verify sess1 fingerprints survived: a lookalike should still alert.
	results := tracker.Check("sess1", fmt.Sprintf("send to %s", poisoned))
	if len(results) == 0 {
		t.Error("expected lookalike alert — sess1 fingerprints should not have been evicted")
	}
}

func TestAddressSimilarity_PerSessionCap(t *testing.T) {
	tracker := NewAddressSimilarityTracker(testAddrPatterns)

	// Feed more than maxFingerprintsPerSession unique addresses.
	for i := 0; i < maxFingerprintsPerSession+100; i++ {
		// Each address has a unique fingerprint.
		hex := fmt.Sprintf("%04x", i)
		addr := fmt.Sprintf("0x%s%s%s", hex[:4], strings.Repeat("00", 16), hex[:4])
		if len(addr) != 42 {
			// Pad to exactly 42 chars.
			addr = fmt.Sprintf("0x%04x%s%04x", i, strings.Repeat("0", 32), i)
		}
		tracker.Check("sess1", addr)
	}

	// The session's index should be capped.
	tracker.mu.Lock()
	sess := tracker.sessions["sess1"]
	indexSize := len(sess.index)
	tracker.mu.Unlock()

	if indexSize > maxFingerprintsPerSession {
		t.Errorf("per-session index should be capped at %d, got %d", maxFingerprintsPerSession, indexSize)
	}
}

func TestAddressSimilarity_ConcurrentAccess(t *testing.T) {
	tracker := NewAddressSimilarityTracker(testAddrPatterns)
	addr := "0x" + strings.Repeat("aB", 20)

	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func(id int) {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 100; j++ {
				tracker.Check(fmt.Sprintf("sess%d", id), fmt.Sprintf("send to %s", addr))
			}
		}(i)
	}
	for i := 0; i < 10; i++ {
		<-done
	}
	// No race detector failures = pass.
}
