// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// Adversarial regression tests for the flood-to-evict bypass (named bypass #3).
//
// Both CEE trackers LRU-evict when the global session cap is reached. Under a
// pure-LRU policy an attacker can flood the cap with fresh dummy sessions to
// evict a victim's in-progress accumulation BEFORE the threshold trips, so the
// completing fragment / final entropy payload lands in a clean bucket and the
// secret leaks. These tests encode the secure invariant: an in-progress
// (near-threshold) victim survives a flood of fresh, low-progress sessions,
// and fail against pure-LRU eviction, pass after least-progress-biased
// eviction.
//
// Defense-in-depth note: at the proxy layer the session-key partitioning fix
// (bypass #1) already collapses a single source to ONE bucket, so a
// single-IP attacker cannot create the thousands of dummy sessions a flood
// needs. These tracker-level tests exercise the eviction policy directly
// (arbitrary keys) and cover the residual multi-source case.

const (
	floodAWSKeyPrefix = "AKI" + "A"      // split to avoid gosec G101
	floodAWSKeyMid    = "IOSF" + "ODNN7" // split to avoid gosec G101
	floodAWSKeyTail   = "EXAMP" + "LE"   // split to avoid gosec G101
	floodVictimKey    = "victim-session" // the accumulating victim bucket
)

// TestFragmentBuffer_FloodEvictDoesNotDropVictim proves that flooding the
// session cap with fresh single-fragment dummy sessions cannot evict a victim
// that already holds an in-progress multi-fragment split secret.
func TestFragmentBuffer_FloodEvictDoesNotDropVictim(t *testing.T) {
	const maxSessions = 8
	fb := NewFragmentBuffer(65536, maxSessions, testWindowSecs)
	defer fb.Close()

	sc := testFragmentScanner()
	defer sc.Close()

	ctx := context.Background()

	// Victim accumulates the first two pieces of a 3-piece split AWS key.
	// Two in-window fragments make this an in-progress cross-request secret.
	fb.Append(floodVictimKey, []byte(floodAWSKeyPrefix))
	fb.Append(floodVictimKey, []byte(floodAWSKeyMid))

	// Attacker floods well past the cap with fresh single-fragment dummies.
	for i := range maxSessions * 3 {
		fb.Append(fmt.Sprintf("dummy-%d", i), []byte("noise"))
	}

	// Victim sends the completing piece. If the victim bucket survived the
	// flood, the concatenation reassembles the full key and DLP matches.
	fb.Append(floodVictimKey, []byte(floodAWSKeyTail))

	matches := fb.ScanForSecrets(ctx, floodVictimKey, sc)
	if len(matches) == 0 {
		t.Fatalf("BYPASS: flood evicted the victim's in-progress fragments; " +
			"the completing fragment landed in a clean bucket and the split secret leaked")
	}
}

// TestEntropyTracker_FloodEvictDoesNotDropVictim proves the same for the
// entropy budget: a victim that has accumulated past the protection threshold
// survives a flood of fresh, low-entropy dummy sessions, so the final payload
// still pushes it over budget.
func TestEntropyTracker_FloodEvictDoesNotDropVictim(t *testing.T) {
	const maxSessions = 8

	et := NewEntropyTracker(1, testDefaultWindow)
	defer et.Close()
	et.maxSessions = maxSessions

	// High-entropy payload; measure its bits and set the budget so one record
	// puts the victim above the protection threshold (>=50% of budget) but
	// below the budget, and two records exceed it.
	victimPayload := []byte("x7k9mQ2pR4wL8nJ5vB3cT6yH0aZ")
	bits := ShannonEntropy(string(victimPayload)) * float64(len(victimPayload))
	et.budget = bits * 1.6 // one record is about 62% (protected); two records exceed.

	et.Record(floodVictimKey, victimPayload)
	if et.BudgetExceeded(floodVictimKey) {
		t.Fatal("setup: single victim record should not exceed budget")
	}

	// Flood fresh, low-entropy dummy sessions past the cap.
	for i := range maxSessions * 3 {
		et.Record(fmt.Sprintf("dummy-%d", i), []byte("aa"))
	}

	// Final victim payload. If the victim survived, accumulated + final
	// exceeds the budget; if it was evicted, the final alone stays under.
	et.Record(floodVictimKey, victimPayload)
	if !et.BudgetExceeded(floodVictimKey) {
		t.Fatalf("BYPASS: flood evicted the victim's accumulated entropy; " +
			"the final payload landed in a fresh bucket and stayed under budget")
	}
}

// --- Boundary cases ------------------------------------------------------

// TestFragmentBuffer_WindowExpiryStopsReassembly documents the window-boundary
// timing behavior: a fragment that ages out of the retention window before the
// completing fragment arrives is not reassembled. This is the bounded-memory
// tradeoff: an attacker dripping fragments slower than window_minutes evades,
// and the mitigation is operator tuning of the window, not unbounded buffering.
func TestFragmentBuffer_WindowExpiryStopsReassembly(t *testing.T) {
	fb := NewFragmentBuffer(65536, 1000, testWindowSecs)
	defer fb.Close()
	sc := testFragmentScanner()
	defer sc.Close()
	ctx := context.Background()

	fb.Append(floodVictimKey, []byte(floodAWSKeyPrefix))
	// Backdate the first fragment beyond the retention window.
	fb.mu.Lock()
	fb.sessions[floodVictimKey].fragments[0].at = time.Now().Add(-2 * time.Duration(testWindowSecs) * time.Second)
	fb.mu.Unlock()

	fb.Append(floodVictimKey, []byte(floodAWSKeyMid+floodAWSKeyTail))
	if matches := fb.ScanForSecrets(ctx, floodVictimKey, sc); len(matches) != 0 {
		t.Fatalf("expired fragment must not reassemble across the window boundary (got %d matches)", len(matches))
	}
}

// TestFragmentBuffer_EmptyAndSingleFragmentNoMatch covers the empty-fragment and
// under-minimum boundaries: an empty append is a no-op, and a session holding a
// single fragment never reports a cross-request match (one-request secrets are
// body-DLP's job, not CEE's).
func TestFragmentBuffer_EmptyAndSingleFragmentNoMatch(t *testing.T) {
	fb := NewFragmentBuffer(65536, 1000, testWindowSecs)
	defer fb.Close()
	sc := testFragmentScanner()
	defer sc.Close()
	ctx := context.Background()

	// Empty append must not panic or create a phantom match. Use a dedicated
	// key so this check leaves no fragment behind in the single-fragment key
	// below (which would otherwise make that session hold two fragments).
	const emptyKey = "empty-only"
	fb.Append(emptyKey, []byte{})
	if matches := fb.ScanForSecrets(ctx, emptyKey, sc); len(matches) != 0 {
		t.Fatalf("empty fragment produced %d matches, want 0", len(matches))
	}

	// A single fragment that IS a full key must not report a cross-request
	// match: with only one in-window fragment the scan returns on the
	// activeCount < minFragmentsForMatch fast path (body DLP handles it).
	const singleKey = "single-fragment"
	fb.Append(singleKey, []byte(floodAWSKeyPrefix+floodAWSKeyMid+floodAWSKeyTail))
	if matches := fb.ScanForSecrets(ctx, singleKey, sc); len(matches) != 0 {
		t.Fatalf("single-fragment full key reported %d cross-request matches, want 0 (body DLP handles it)", len(matches))
	}
}

// TestFragmentBuffer_AllProtectedStillBoundsMemory proves least-progress
// eviction never becomes an unbounded-memory hole: when EVERY session is an
// in-progress (protected) accumulation, the cap still holds via global-LRU
// fallback.
func TestFragmentBuffer_AllProtectedStillBoundsMemory(t *testing.T) {
	const maxSessions = 4
	fb := NewFragmentBuffer(65536, maxSessions, testWindowSecs)
	defer fb.Close()

	for i := range maxSessions + 3 {
		key := fmt.Sprintf("prot-%d", i)
		fb.Append(key, []byte("alpha")) // two in-window fragments => protected
		fb.Append(key, []byte("beta"))
	}

	fb.mu.Lock()
	count := len(fb.sessions)
	fb.mu.Unlock()
	if count > maxSessions {
		t.Fatalf("session cap breached: %d sessions > cap %d (protection became unbounded memory)", count, maxSessions)
	}
}

// TestEntropyTracker_AllProtectedStillBoundsMemory is the entropy-tracker
// counterpart: even when every session is near-threshold (protected), the
// global cap is enforced.
func TestEntropyTracker_AllProtectedStillBoundsMemory(t *testing.T) {
	const maxSessions = 4
	et := NewEntropyTracker(1, testDefaultWindow)
	defer et.Close()
	et.maxSessions = maxSessions

	hi := []byte("x7k9mQ2pR4wL8nJ5vB3cT6yH0aZ")
	bits := ShannonEntropy(string(hi)) * float64(len(hi))
	et.budget = bits // one record => usage >= protect threshold (all protected)

	for i := range maxSessions + 3 {
		et.Record(fmt.Sprintf("prot-%d", i), hi)
	}

	et.mu.Lock()
	count := len(et.sessions)
	et.mu.Unlock()
	if count > maxSessions {
		t.Fatalf("entropy session cap breached: %d > cap %d", count, maxSessions)
	}
}
