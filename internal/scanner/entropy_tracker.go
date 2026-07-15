// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"sync"
	"time"
)

// entropyEntry tracks bits of entropy recorded at a point in time.
type entropyEntry struct {
	bits      float64
	timestamp time.Time
}

// entropySession holds entropy entries for a single session with LRU tracking.
type entropySession struct {
	entries    []entropyEntry
	lastAccess time.Time
}

// EntropyTracker tracks cumulative Shannon entropy of outbound data per session
// within a sliding window. High entropy is a scored signal (not proof of
// exfiltration): legitimate traffic like JWTs, base64 uploads, and code can
// also produce high entropy. Bounded by maxSessions to prevent unbounded memory
// growth under session churn.
type EntropyTracker struct {
	mu          sync.Mutex
	budget      float64 // bits per window
	windowSecs  int     // sliding window duration in seconds
	maxSessions int     // global session count cap (LRU eviction)
	sessions    map[string]*entropySession
	lastCleanup time.Time
}

// NewEntropyTracker creates an entropy tracker with the given budget (bits per
// window) and window duration (seconds). Expired entries are pruned
// opportunistically at an interval derived from the window size.
func NewEntropyTracker(budgetBits float64, windowSecs int) *EntropyTracker {
	// Guard non-positive inputs to avoid silent misbehavior outside
	// config-validated paths (e.g. tests with hand-built trackers).
	if budgetBits <= 0 {
		budgetBits = 1
	}
	if windowSecs <= 0 {
		windowSecs = 1
	}
	et := &EntropyTracker{
		budget:      budgetBits,
		windowSecs:  windowSecs,
		maxSessions: 10000, // match FragmentBuffer and proxy maxCEESessions
		sessions:    make(map[string]*entropySession),
		lastCleanup: time.Now(),
	}
	return et
}

// Record adds a payload's entropy to the session's running total and returns
// the bits recorded. Total bits = ShannonEntropy(payload) * len(payload).
// Returns 0 for nil or empty payloads. Inline-prunes expired entries on the
// hot path to keep currentUsageLocked O(active) instead of O(total).
func (et *EntropyTracker) Record(sessionKey string, payload []byte) float64 {
	if len(payload) == 0 {
		return 0
	}

	s := string(payload)
	bits := ShannonEntropy(s) * float64(len(payload))

	et.mu.Lock()
	defer et.mu.Unlock()
	et.maybeCleanupLocked(time.Now())

	sess, exists := et.sessions[sessionKey]
	if !exists {
		// Check global session cap before creating a new session.
		if len(et.sessions) >= et.maxSessions {
			et.evictLRUSession()
		}
		sess = &entropySession{}
		et.sessions[sessionKey] = sess
	}

	now := time.Now()
	sess.lastAccess = now

	// Inline-prune expired entries to bound memory and scan cost.
	cutoff := now.Add(-time.Duration(et.windowSecs) * time.Second)
	valid := sess.entries[:0]
	for _, e := range sess.entries {
		if e.timestamp.After(cutoff) {
			valid = append(valid, e)
		}
	}
	sess.entries = valid

	sess.entries = append(sess.entries, entropyEntry{
		bits:      bits,
		timestamp: now,
	})

	return bits
}

// CurrentUsage returns the total entropy bits recorded for a session within the
// current sliding window.
func (et *EntropyTracker) CurrentUsage(sessionKey string) float64 {
	et.mu.Lock()
	defer et.mu.Unlock()
	et.maybeCleanupLocked(time.Now())

	return et.currentUsageLocked(sessionKey)
}

// Remaining returns the entropy budget remaining for a session. Returns 0 (not
// negative) when the budget is exceeded.
func (et *EntropyTracker) Remaining(sessionKey string) float64 {
	et.mu.Lock()
	defer et.mu.Unlock()
	et.maybeCleanupLocked(time.Now())

	usage := et.currentUsageLocked(sessionKey)
	remaining := et.budget - usage
	if remaining < 0 {
		return 0
	}
	return remaining
}

// BudgetExceeded returns true if the session's entropy usage within the sliding
// window exceeds the configured budget.
func (et *EntropyTracker) BudgetExceeded(sessionKey string) bool {
	et.mu.Lock()
	defer et.mu.Unlock()
	et.maybeCleanupLocked(time.Now())

	return et.currentUsageLocked(sessionKey) >= et.budget
}

// Budget returns the configured entropy budget in bits per window.
func (et *EntropyTracker) Budget() float64 {
	return et.budget
}

// Delete removes all entropy tracking state for the given session key.
func (et *EntropyTracker) Delete(key string) {
	et.mu.Lock()
	defer et.mu.Unlock()
	delete(et.sessions, key)
}

// Close is retained for scanner lifecycle symmetry. EntropyTracker owns no
// background resources, so closing it is intentionally a no-op.
func (et *EntropyTracker) Close() {}

// currentUsageLocked sums entropy bits within the sliding window.
// Caller must hold et.mu.
func (et *EntropyTracker) currentUsageLocked(sessionKey string) float64 {
	sess := et.sessions[sessionKey]
	if sess == nil {
		return 0
	}
	cutoff := time.Now().Add(-time.Duration(et.windowSecs) * time.Second)
	var total float64
	for _, e := range sess.entries {
		if e.timestamp.After(cutoff) {
			total += e.bits
		}
	}
	return total
}

// evictionProtectFraction is the share of the entropy budget at or above which
// a session counts as an in-progress (near-threshold) accumulation and is
// protected from flood-to-evict. Eviction prefers low-progress sessions so an
// attacker cannot flood the session cap with fresh dummy sessions to drop a
// victim's accumulated entropy before the budget trips. Bounded memory is
// preserved: when every session is near-threshold, eviction falls back to
// global LRU.
const evictionProtectFraction = 0.5

// evictLRUSession removes a session to stay within the global cap. To resist
// the flood-to-evict bypass, it evicts the least-recently-used session AMONG
// those below the protection threshold; only if every session is near-threshold
// does it fall back to evicting the global LRU. Must be called with et.mu held.
func (et *EntropyTracker) evictLRUSession() {
	cutoff := time.Now().Add(-time.Duration(et.windowSecs) * time.Second)
	protectAt := et.budget * evictionProtectFraction

	var lruKey, lruProtectedKey string
	var lruTime, lruProtectedTime time.Time

	for key, sess := range et.sessions {
		var usage float64
		for _, e := range sess.entries {
			if e.timestamp.After(cutoff) {
				usage += e.bits
			}
		}
		if usage >= protectAt {
			// Near-threshold: only a candidate if no unprotected session exists.
			if lruProtectedKey == "" || sess.lastAccess.Before(lruProtectedTime) {
				lruProtectedKey, lruProtectedTime = key, sess.lastAccess
			}
			continue
		}
		if lruKey == "" || sess.lastAccess.Before(lruTime) {
			lruKey, lruTime = key, sess.lastAccess
		}
	}

	victim := lruKey
	if victim == "" {
		victim = lruProtectedKey // all sessions near-threshold; bound memory anyway
	}
	if victim != "" {
		delete(et.sessions, victim)
	}
}

// cleanupInterval is derived from the configured window: at most 60s and at
// least 1s, so short windows get prompt reclamation on the next operation.
func (et *EntropyTracker) cleanupInterval() time.Duration {
	interval := time.Duration(et.windowSecs) * time.Second
	if interval > 60*time.Second {
		interval = 60 * time.Second
	}
	if interval < 1*time.Second {
		interval = 1 * time.Second
	}
	return interval
}

func (et *EntropyTracker) cleanup() {
	et.mu.Lock()
	defer et.mu.Unlock()
	et.cleanupLocked(time.Now())
}

func (et *EntropyTracker) maybeCleanupLocked(now time.Time) {
	if now.Sub(et.lastCleanup) < et.cleanupInterval() {
		return
	}
	et.cleanupLocked(now)
	et.lastCleanup = now
}

func (et *EntropyTracker) cleanupLocked(now time.Time) {
	cutoff := now.Add(-time.Duration(et.windowSecs) * time.Second)
	for key, sess := range et.sessions {
		valid := sess.entries[:0]
		for _, e := range sess.entries {
			if e.timestamp.After(cutoff) {
				valid = append(valid, e)
			}
		}
		if len(valid) == 0 {
			delete(et.sessions, key)
		} else {
			sess.entries = valid
		}
	}
}
