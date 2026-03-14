// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"regexp"
	"sync"
	"time"
)

// addressFingerprint is the prefix+suffix of a blockchain address used
// for lookalike comparison. Address poisoning attacks generate addresses
// where the first and last few characters match a known-good address
// because UIs and agents display truncated addresses.
type addressFingerprint struct {
	prefix string // first fingerprintLen chars
	suffix string // last fingerprintLen chars
}

// addressEntry records a full address and when it was first seen.
type addressEntry struct {
	full      string
	timestamp time.Time
}

// addressSession tracks addresses seen in a single agent session.
type addressSession struct {
	// index maps fingerprint → first address seen with that fingerprint.
	// When a second address with the same fingerprint but different full
	// value appears, that's a potential poisoning attack.
	index      map[addressFingerprint]*addressEntry
	lastAccess time.Time
}

// AddressSimilarityResult describes a detected lookalike address pair.
type AddressSimilarityResult struct {
	// NewAddress is the address that triggered the alert.
	NewAddress string `json:"new_address"`
	// KnownAddress is the previously-seen address with matching fingerprint.
	KnownAddress string `json:"known_address"`
	// Prefix is the shared prefix.
	Prefix string `json:"prefix"`
	// Suffix is the shared suffix.
	Suffix string `json:"suffix"`
}

// AddressSimilarityTracker detects address poisoning attacks by tracking
// blockchain addresses seen per session and flagging lookalikes where
// prefix+suffix match but the full address differs.
//
// Bounded by maxSessions to prevent unbounded memory growth.
// Thread-safe via mutex.
type AddressSimilarityTracker struct {
	mu          sync.Mutex
	sessions    map[string]*addressSession
	maxSessions int
	patterns    []*regexp.Regexp // compiled address format regexes
}

// fingerprintLen is the number of characters compared at each end of
// an address. 4 chars matches how most UIs truncate addresses
// (e.g., "0xAbCd...xYzW"). Attackers target this display convention.
const fingerprintLen = 4

// NewAddressSimilarityTracker creates a tracker with the given address
// format patterns. Each pattern should match a full blockchain address
// (e.g., ETH: `0x[0-9a-fA-F]{40}`, BTC: `[13][a-km-zA-HJ-NP-Z1-9]{25,34}`).
func NewAddressSimilarityTracker(patterns []*regexp.Regexp) *AddressSimilarityTracker {
	return &AddressSimilarityTracker{
		sessions:    make(map[string]*addressSession),
		maxSessions: 10000, // match CEE and entropy tracker caps
		patterns:    patterns,
	}
}

// Check extracts blockchain addresses from text and compares them against
// previously-seen addresses in the same session. Returns results for any
// lookalike pairs found (same prefix+suffix, different full address).
//
// The sessionID should be the agent's session identifier (from header,
// listener binding, or CIDR match).
func (t *AddressSimilarityTracker) Check(sessionID, text string) []AddressSimilarityResult {
	if len(t.patterns) == 0 {
		return nil
	}

	// Extract all addresses from the text.
	var addresses []string
	for _, p := range t.patterns {
		matches := p.FindAllString(text, -1)
		addresses = append(addresses, matches...)
	}
	if len(addresses) == 0 {
		return nil
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	// Evict oldest session if at capacity.
	if len(t.sessions) >= t.maxSessions {
		t.evictOldest()
	}

	sess, ok := t.sessions[sessionID]
	if !ok {
		sess = &addressSession{
			index: make(map[addressFingerprint]*addressEntry),
		}
		t.sessions[sessionID] = sess
	}
	sess.lastAccess = time.Now()

	var results []AddressSimilarityResult
	for _, addr := range addresses {
		if len(addr) < fingerprintLen*2 {
			continue // too short for meaningful fingerprint
		}

		fp := addressFingerprint{
			prefix: addr[:fingerprintLen],
			suffix: addr[len(addr)-fingerprintLen:],
		}

		existing, seen := sess.index[fp]
		if !seen {
			// First address with this fingerprint in this session.
			sess.index[fp] = &addressEntry{
				full:      addr,
				timestamp: time.Now(),
			}
			continue
		}

		// Same fingerprint, check if it's actually a different address.
		if existing.full != addr {
			results = append(results, AddressSimilarityResult{
				NewAddress:   addr,
				KnownAddress: existing.full,
				Prefix:       fp.prefix,
				Suffix:       fp.suffix,
			})
		}
		// If same full address, it's a repeat — no alert.
	}

	return results
}

// evictOldest removes the session with the oldest lastAccess time.
// Caller must hold t.mu.
func (t *AddressSimilarityTracker) evictOldest() {
	var oldestID string
	var oldestTime time.Time
	first := true
	for id, sess := range t.sessions {
		if first || sess.lastAccess.Before(oldestTime) {
			oldestID = id
			oldestTime = sess.lastAccess
			first = false
		}
	}
	if oldestID != "" {
		delete(t.sessions, oldestID)
	}
}

// Reset clears all tracked sessions. Used during config reload.
func (t *AddressSimilarityTracker) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sessions = make(map[string]*addressSession)
}

// SessionCount returns the number of active sessions being tracked.
func (t *AddressSimilarityTracker) SessionCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.sessions)
}
