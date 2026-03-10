// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"sync"
	"time"
)

// DLPMatch describes a single DLP pattern match found in reassembled fragments.
type DLPMatch struct {
	PatternName string
	Matched     string
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
	lastScan   time.Time
	lastAccess time.Time   // for LRU eviction across sessions
	scanTimer  *time.Timer // delayed rescan at debounce expiry
}

// FragmentBuffer accumulates outbound payloads per session in rolling buffers.
// Periodically runs DLP on the concatenated buffer to catch secrets split
// across multiple requests. Thread-safe for concurrent access.
type FragmentBuffer struct {
	mu          sync.Mutex
	maxBytes    int           // per-session byte cap
	maxSessions int           // global session count cap (LRU eviction)
	windowSecs  int           // fragment retention window in seconds
	debounceDur time.Duration // minimum interval between DLP re-scans
	sessions    map[string]*sessionBuffer
	stopCleanup chan struct{}
	closeOnce   sync.Once
}

// NewFragmentBuffer creates a fragment buffer with the given per-session byte cap,
// global session cap, fragment retention window, and debounce interval.
func NewFragmentBuffer(maxBytesPerSession, maxSessions, windowSecs int, debounceMs int) *FragmentBuffer {
	fb := &FragmentBuffer{
		maxBytes:    maxBytesPerSession,
		maxSessions: maxSessions,
		windowSecs:  windowSecs,
		debounceDur: time.Duration(debounceMs) * time.Millisecond,
		sessions:    make(map[string]*sessionBuffer),
		stopCleanup: make(chan struct{}),
	}
	go fb.cleanupLoop()
	return fb
}

// Append adds a payload fragment to the session's rolling buffer.
// Evicts oldest fragments when the per-session byte cap is exceeded.
// Evicts the least-recently-used session when the global session cap is exceeded.
func (fb *FragmentBuffer) Append(sessionKey string, payload []byte) {
	fb.mu.Lock()
	defer fb.mu.Unlock()

	sb, exists := fb.sessions[sessionKey]
	if !exists {
		// Check global session cap before creating a new session.
		if len(fb.sessions) >= fb.maxSessions {
			fb.evictLRUSession()
		}
		sb = &sessionBuffer{}
		fb.sessions[sessionKey] = sb
	}

	sb.lastAccess = time.Now()
	sb.fragments = append(sb.fragments, fragment{
		data: payload,
		at:   time.Now(),
	})
	sb.totalBytes += len(payload)

	// Evict oldest fragments until within per-session byte cap.
	for sb.totalBytes > fb.maxBytes && len(sb.fragments) > 1 {
		sb.totalBytes -= len(sb.fragments[0].data)
		sb.fragments = sb.fragments[1:]
	}
}

// ScanForSecrets runs DLP on the concatenated fragment buffer for the given session.
// Returns nil if no matches are found, the session doesn't exist, or the scan is
// debounced (within the debounce window from the last scan). When debounced, a
// delayed rescan is scheduled via time.AfterFunc at the debounce expiry.
func (fb *FragmentBuffer) ScanForSecrets(sessionKey string, sc *Scanner) []DLPMatch {
	fb.mu.Lock()
	sb, exists := fb.sessions[sessionKey]
	if !exists || len(sb.fragments) == 0 {
		fb.mu.Unlock()
		return nil
	}

	// Two-phase debounce: if within debounce window, schedule delayed rescan.
	if fb.debounceDur > 0 && !sb.lastScan.IsZero() {
		elapsed := time.Since(sb.lastScan)
		if elapsed < fb.debounceDur {
			fb.scheduleDelayedScan(sessionKey, sb, sc)
			fb.mu.Unlock()
			return nil
		}
	}

	// Update lastScan timestamp.
	sb.lastScan = time.Now()

	// Cancel any pending delayed scan since we're scanning now.
	if sb.scanTimer != nil {
		sb.scanTimer.Stop()
		sb.scanTimer = nil
	}

	// Concatenate all fragments under lock, then release lock for DLP scan.
	buf := fb.concatenateFragments(sb)
	fb.mu.Unlock()

	// Run DLP scan outside the lock (may be expensive).
	result := sc.ScanTextForDLP(string(buf))
	if result.Clean {
		return nil
	}

	matches := make([]DLPMatch, 0, len(result.Matches))
	for _, m := range result.Matches {
		matches = append(matches, DLPMatch{
			PatternName: m.PatternName,
		})
	}
	return matches
}

// TotalBufferBytes returns the total bytes across all sessions, for Prometheus gauges.
func (fb *FragmentBuffer) TotalBufferBytes() int {
	fb.mu.Lock()
	defer fb.mu.Unlock()

	total := 0
	for _, sb := range fb.sessions {
		total += sb.totalBytes
	}
	return total
}

// Close stops the cleanup goroutine and cancels all pending scan timers.
// Safe to call multiple times.
func (fb *FragmentBuffer) Close() {
	fb.closeOnce.Do(func() {
		close(fb.stopCleanup)
		fb.mu.Lock()
		defer fb.mu.Unlock()
		for _, sb := range fb.sessions {
			if sb.scanTimer != nil {
				sb.scanTimer.Stop()
				sb.scanTimer = nil
			}
		}
	})
}

// scheduleDelayedScan sets up a time.AfterFunc to run a DLP scan after the
// debounce window expires. Cancels any existing pending timer first.
// Must be called with fb.mu held.
func (fb *FragmentBuffer) scheduleDelayedScan(sessionKey string, sb *sessionBuffer, sc *Scanner) {
	if sb.scanTimer != nil {
		sb.scanTimer.Stop()
	}
	remaining := fb.debounceDur - time.Since(sb.lastScan)
	if remaining <= 0 {
		remaining = fb.debounceDur
	}
	sb.scanTimer = time.AfterFunc(remaining, func() {
		// Delayed scan: just call ScanForSecrets which handles its own locking.
		// Results are discarded here; the scan updates internal state and any
		// future caller of ScanForSecrets will get fresh results.
		_ = fb.ScanForSecrets(sessionKey, sc)
	})
}

// concatenateFragments builds a single byte slice from all session fragments.
// Must be called with fb.mu held.
func (fb *FragmentBuffer) concatenateFragments(sb *sessionBuffer) []byte {
	buf := make([]byte, 0, sb.totalBytes)
	for _, f := range sb.fragments {
		buf = append(buf, f.data...)
	}
	return buf
}

// evictLRUSession removes the least-recently-used session.
// Must be called with fb.mu held.
func (fb *FragmentBuffer) evictLRUSession() {
	var oldestKey string
	var oldestTime time.Time

	for key, sb := range fb.sessions {
		if oldestKey == "" || sb.lastAccess.Before(oldestTime) {
			oldestKey = key
			oldestTime = sb.lastAccess
		}
	}

	if oldestKey != "" {
		sb := fb.sessions[oldestKey]
		if sb.scanTimer != nil {
			sb.scanTimer.Stop()
		}
		delete(fb.sessions, oldestKey)
	}
}

// cleanupLoop periodically prunes expired fragments from all sessions.
// Runs every 60 seconds until Close() is called.
func (fb *FragmentBuffer) cleanupLoop() {
	// 60s cleanup interval, matching databudget.go pattern.
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			fb.cleanup()
		case <-fb.stopCleanup:
			return
		}
	}
}

// cleanup removes fragments older than the retention window and prunes
// empty sessions. Front-pops expired fragments from each session's deque.
func (fb *FragmentBuffer) cleanup() {
	fb.mu.Lock()
	defer fb.mu.Unlock()

	cutoff := time.Now().Add(-time.Duration(fb.windowSecs) * time.Second)

	for key, sb := range fb.sessions {
		// Front-pop expired fragments.
		for len(sb.fragments) > 0 && sb.fragments[0].at.Before(cutoff) {
			sb.totalBytes -= len(sb.fragments[0].data)
			sb.fragments = sb.fragments[1:]
		}

		// Remove empty sessions entirely.
		if len(sb.fragments) == 0 {
			if sb.scanTimer != nil {
				sb.scanTimer.Stop()
			}
			delete(fb.sessions, key)
		}
	}
}
