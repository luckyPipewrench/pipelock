// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"sync"
	"time"
)

// DLPMatch describes a single DLP pattern match found in reassembled fragments.
type DLPMatch struct {
	PatternName string
	Matched     string
	Warn        bool // true for warn-mode patterns (informational only)
}

// fragment holds a single outbound payload chunk with its arrival time.
type fragment struct {
	data []byte
	at   time.Time
}

// sessionBuffer accumulates outbound fragments for a single session.
type sessionBuffer struct {
	fragments  []fragment
	totalBytes int
	lastAccess time.Time // for LRU eviction across sessions
}

// FragmentBuffer accumulates outbound payloads per session in rolling buffers.
// On each call to ScanForSecrets, the concatenated buffer is scanned against
// DLP patterns synchronously. This guarantees pre-forward detection: a request
// that completes a split secret is blocked before egress. Thread-safe.
type FragmentBuffer struct {
	mu          sync.Mutex
	maxBytes    int // per-session byte cap
	maxSessions int // global session count cap (LRU eviction)
	windowSecs  int // fragment retention window in seconds
	sessions    map[string]*sessionBuffer
	lastCleanup time.Time
}

// NewFragmentBuffer creates a fragment buffer with the given per-session byte cap,
// global session cap, and fragment retention window.
func NewFragmentBuffer(maxBytesPerSession, maxSessions, windowSecs int) *FragmentBuffer {
	fb := &FragmentBuffer{
		maxBytes:    maxBytesPerSession,
		maxSessions: maxSessions,
		windowSecs:  windowSecs,
		sessions:    make(map[string]*sessionBuffer),
		lastCleanup: time.Now(),
	}
	return fb
}

// Append adds a payload fragment to the session's rolling buffer.
// Evicts oldest fragments when the per-session byte cap is exceeded.
// Evicts the least-recently-used session when the global session cap is exceeded.
func (fb *FragmentBuffer) Append(sessionKey string, payload []byte) {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	fb.maybeCleanupLocked(time.Now())

	sb, exists := fb.sessions[sessionKey]
	if !exists {
		// Check global session cap before creating a new session.
		if len(fb.sessions) >= fb.maxSessions {
			fb.evictLRUSession()
		}
		sb = &sessionBuffer{}
		fb.sessions[sessionKey] = sb
	}

	// Copy payload to prevent caller mutation of buffered data.
	copied := make([]byte, len(payload))
	copy(copied, payload)

	now := time.Now()
	sb.lastAccess = now
	sb.fragments = append(sb.fragments, fragment{
		data: copied,
		at:   now,
	})
	sb.totalBytes += len(copied)

	// Evict oldest fragments until within per-session byte cap.
	// A single fragment larger than maxBytes is truncated to maxBytes.
	for sb.totalBytes > fb.maxBytes && len(sb.fragments) > 1 {
		sb.totalBytes -= len(sb.fragments[0].data)
		sb.fragments = sb.fragments[1:]
	}
	if sb.totalBytes > fb.maxBytes && len(sb.fragments) == 1 {
		// Keep the newest suffix bytes: the most recent data is more likely
		// to complete a split secret spanning multiple requests.
		sb.fragments[0].data = sb.fragments[0].data[len(sb.fragments[0].data)-fb.maxBytes:]
		sb.totalBytes = fb.maxBytes
	}
}

// ScanForSecrets runs DLP on the concatenated fragment buffer for the given session.
// Always scans synchronously to guarantee pre-forward detection. Returns nil if
// no matches are found or the session doesn't exist.
//
// Only reports matches that span multiple fragments (true cross-request secrets).
// If a secret is entirely within the latest fragment (single request body), it's
// already caught by body DLP and doesn't need a second +3 CEE signal. This prevents
// LLM conversation context from generating repeated fragment DLP signals on every
// API call (the context carries the same secrets in every POST body).
func (fb *FragmentBuffer) ScanForSecrets(ctx context.Context, sessionKey string, sc *Scanner) []DLPMatch {
	fb.mu.Lock()
	fb.maybeCleanupLocked(time.Now())
	sb, exists := fb.sessions[sessionKey]
	if !exists || len(sb.fragments) == 0 {
		fb.mu.Unlock()
		return nil
	}

	// Need at least 2 non-expired fragments for a cross-request match.
	// A single fragment means the secret is in one request - body DLP handles it.
	cutoff := time.Now().Add(-time.Duration(fb.windowSecs) * time.Second)
	activeCount := 0
	for _, f := range sb.fragments {
		if !f.at.Before(cutoff) {
			activeCount++
		}
	}
	if activeCount < minFragmentsForMatch {
		fb.mu.Unlock()
		return nil
	}

	// Concatenate all fragments under lock, then release lock for DLP scan.
	buf := fb.concatenateFragments(sb)

	// Collect each individual fragment's data for dedup scanning.
	var individualFragments [][]byte
	for _, f := range sb.fragments {
		if !f.at.Before(cutoff) {
			individualFragments = append(individualFragments, f.data)
		}
	}
	fb.mu.Unlock()

	// Scan the concatenated buffer.
	result := sc.ScanTextForDLP(ctx, string(buf))
	if result.Clean && len(result.InformationalMatches) == 0 {
		return nil
	}

	// Scan each individual fragment to identify single-request matches.
	// A pattern that matches entirely within ANY single fragment is handled
	// by body DLP and should not generate a cross-request signal.
	singleFragment := make(map[string]bool)
	for _, frag := range individualFragments {
		if len(frag) > 0 {
			fragResult := sc.ScanTextForDLP(ctx, string(frag))
			for _, m := range fragResult.Matches {
				singleFragment[m.PatternName] = true
			}
			for _, m := range fragResult.InformationalMatches {
				singleFragment[m.PatternName] = true
			}
		}
	}

	// Only report matches NOT found in any individual fragment.
	// These are true cross-request matches (secret spans fragment boundaries).
	// Warn-mode matches are NOT included here - they are already emitted
	// via DLPWarnHook inside ScanTextForDLP. Including them would cause
	// CEE callers to treat informational warn matches as enforcement signals.
	var matches []DLPMatch
	for _, m := range result.Matches {
		if !singleFragment[m.PatternName] {
			matches = append(matches, DLPMatch{
				PatternName: m.PatternName,
			})
		}
	}
	if len(matches) == 0 {
		return nil
	}
	return matches
}

// TotalBufferBytes returns the total bytes across all sessions, for Prometheus gauges.
func (fb *FragmentBuffer) TotalBufferBytes() int {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	fb.maybeCleanupLocked(time.Now())

	total := 0
	for _, sb := range fb.sessions {
		total += sb.totalBytes
	}
	return total
}

// Delete removes all fragment state for the given session key.
func (fb *FragmentBuffer) Delete(key string) {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	delete(fb.sessions, key)
}

// Close is retained for scanner lifecycle symmetry. FragmentBuffer owns no
// background resources, so closing it is intentionally a no-op.
func (fb *FragmentBuffer) Close() {}

// concatenateFragments builds a single byte slice from non-expired session
// fragments. Filters by windowSecs so scans never include stale data, even
// if the 60-second cleanup ticker hasn't run yet. Must be called with fb.mu held.
func (fb *FragmentBuffer) concatenateFragments(sb *sessionBuffer) []byte {
	cutoff := time.Now().Add(-time.Duration(fb.windowSecs) * time.Second)
	buf := make([]byte, 0, sb.totalBytes)
	for _, f := range sb.fragments {
		if f.at.Before(cutoff) {
			continue
		}
		buf = append(buf, f.data...)
	}
	return buf
}

// minFragmentsForMatch is the minimum number of in-window fragments a session
// must hold to be a candidate cross-request secret (a single fragment is a
// one-request secret handled by body DLP). A session at or above this count is
// an in-progress accumulation and is protected from flood-to-evict.
const minFragmentsForMatch = 2

// evictLRUSession removes a session to stay within the global cap. To resist
// the flood-to-evict bypass, it evicts the least-recently-used session AMONG
// those that are NOT an in-progress multi-fragment accumulation; only if every
// session is in-progress does it fall back to evicting the global LRU. Bounded
// memory is preserved either way. Must be called with fb.mu held.
func (fb *FragmentBuffer) evictLRUSession() {
	cutoff := time.Now().Add(-time.Duration(fb.windowSecs) * time.Second)

	var lruKey, lruProtectedKey string
	var lruTime, lruProtectedTime time.Time

	for key, sb := range fb.sessions {
		active := 0
		for _, f := range sb.fragments {
			if !f.at.Before(cutoff) {
				active++
			}
		}
		if active >= minFragmentsForMatch {
			// In-progress secret: only a candidate if nothing else can be evicted.
			if lruProtectedKey == "" || sb.lastAccess.Before(lruProtectedTime) {
				lruProtectedKey, lruProtectedTime = key, sb.lastAccess
			}
			continue
		}
		if lruKey == "" || sb.lastAccess.Before(lruTime) {
			lruKey, lruTime = key, sb.lastAccess
		}
	}

	victim := lruKey
	if victim == "" {
		victim = lruProtectedKey // all sessions in-progress; bound memory anyway
	}
	if victim != "" {
		delete(fb.sessions, victim)
	}
}

// cleanupInterval is derived from the configured window: at most 60s and at
// least 1s, so short windows get prompt reclamation on the next operation.
func (fb *FragmentBuffer) cleanupInterval() time.Duration {
	interval := time.Duration(fb.windowSecs) * time.Second
	if interval > 60*time.Second {
		interval = 60 * time.Second
	}
	if interval < 1*time.Second {
		interval = 1 * time.Second
	}
	return interval
}

// cleanup removes fragments older than the retention window and prunes
// empty sessions. Front-pops expired fragments from each session's deque.
func (fb *FragmentBuffer) cleanup() {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	fb.cleanupLocked(time.Now())
}

func (fb *FragmentBuffer) maybeCleanupLocked(now time.Time) {
	if now.Sub(fb.lastCleanup) < fb.cleanupInterval() {
		return
	}
	fb.cleanupLocked(now)
	fb.lastCleanup = now
}

func (fb *FragmentBuffer) cleanupLocked(now time.Time) {
	cutoff := now.Add(-time.Duration(fb.windowSecs) * time.Second)

	for key, sb := range fb.sessions {
		// Front-pop expired fragments.
		for len(sb.fragments) > 0 && sb.fragments[0].at.Before(cutoff) {
			sb.totalBytes -= len(sb.fragments[0].data)
			sb.fragments = sb.fragments[1:]
		}

		// Remove empty sessions entirely.
		if len(sb.fragments) == 0 {
			delete(fb.sessions, key)
		}
	}
}
