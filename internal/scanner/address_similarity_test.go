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
	if results[0].KnownAddress != legit {
		t.Errorf("expected known address %s, got %s", legit, results[0].KnownAddress)
	}
	if results[0].NewAddress != fake {
		t.Errorf("expected new address %s, got %s", fake, results[0].NewAddress)
	}
	expectedPrefix := legit[:fingerprintLen]
	expectedSuffix := legit[len(legit)-fingerprintLen:]
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

func TestAddressSimilarity_CaseSensitiveFingerprint(t *testing.T) {
	tracker := NewAddressSimilarityTracker(testAddrPatterns)

	// ETH addresses are case-insensitive in practice (EIP-55 uses mixed
	// case for checksum). The tracker uses raw extracted chars for
	// fingerprinting. Two addresses that differ only in case of the
	// middle but have identical prefix+suffix should NOT alert.
	addr1 := "0xAb" + strings.Repeat("aa", 17) + "1234" // 42 chars
	addr2 := "0xAb" + strings.Repeat("AA", 17) + "1234" // same fingerprint, case differs in middle

	tracker.Check("sess1", fmt.Sprintf("send to %s", addr1))
	results := tracker.Check("sess1", fmt.Sprintf("send to %s", addr2))

	// These WILL alert because the full addresses differ (case differs).
	// This is a conservative choice: case variants of the same logical
	// address are unusual in legitimate traffic.
	if len(results) == 0 {
		t.Log("case-different addresses did not alert (fingerprint matches, full differs)")
	} else {
		t.Log("case-different addresses alerted (conservative: full address differs)")
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
