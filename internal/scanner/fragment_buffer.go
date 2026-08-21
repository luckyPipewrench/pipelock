// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"bytes"
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
}

// MaxPathPositions is the largest URL path depth that CEE tracks. It bounds
// attacker-controlled position cardinality while leaving ample room for normal
// application routes. A path that exceeds this bound is not safely
// reconstructable and is reported to the caller as a capacity-style failure.
const MaxPathPositions = 64

// pathPositionBuffer holds one zero-based URL path position. The first value
// is retained so a position that remains static adds only one fragment. Once a
// position changes, every subsequent value is retained in arrival order.
//
// This is deliberately position-scoped rather than value-scoped. A value sent
// early at a position cannot suppress its later occurrence after that position
// has become dynamic.
type pathPositionBuffer struct {
	initial    []byte
	varied     bool
	fragments  []fragment
	totalBytes int
}

// pathSessionBuffer groups every tracked path position for one logical CEE
// session. It is one global FragmentBuffer session regardless of path depth,
// and its positions share the ordinary per-session byte cap.
type pathSessionBuffer struct {
	positions  map[int]*pathPositionBuffer
	totalBytes int
}

// FragmentAppendResult describes whether a fragment became representable in the
// cross-request session ledger.
type FragmentAppendResult struct {
	// CapacityExceeded means a new session could not be admitted without
	// discarding another session's accumulated detection state.
	CapacityExceeded bool
	// PathDepthExceeded means a URL carried more than MaxPathPositions
	// non-empty segments. The caller must not treat the request as fully
	// inspected: untracked positions could otherwise carry split fragments.
	PathDepthExceeded bool
}

// FragmentBuffer accumulates outbound payloads per session in rolling buffers.
// On each call to ScanForSecrets, the concatenated buffer is scanned against
// DLP patterns synchronously. This guarantees pre-forward detection: a request
// that completes a split secret is blocked before egress. Thread-safe.
type FragmentBuffer struct {
	mu           sync.Mutex
	maxBytes     int // per-session byte cap
	maxSessions  int // global session count cap (new sessions are denied at capacity)
	windowSecs   int // fragment retention window in seconds
	sessions     map[string]*sessionBuffer
	pathSessions map[string]*pathSessionBuffer
	lastCleanup  time.Time
}

// NewFragmentBuffer creates a fragment buffer with the given per-session byte cap,
// global session cap, and fragment retention window.
func NewFragmentBuffer(maxBytesPerSession, maxSessions, windowSecs int) *FragmentBuffer {
	fb := &FragmentBuffer{
		maxBytes:     maxBytesPerSession,
		maxSessions:  maxSessions,
		windowSecs:   windowSecs,
		sessions:     make(map[string]*sessionBuffer),
		pathSessions: make(map[string]*pathSessionBuffer),
		lastCleanup:  time.Now(),
	}
	return fb
}

// Append adds a payload fragment to the session's rolling buffer.
// Evicts oldest fragments when the per-session byte cap is exceeded.
// Refuses a new session when the global session cap is reached: accumulated
// fragment state is security evidence and must not be silently evicted.
func (fb *FragmentBuffer) Append(sessionKey string, payload []byte) FragmentAppendResult {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	fb.maybeCleanupLocked(time.Now())
	return fb.appendLocked(sessionKey, payload)
}

// appendLocked performs the buffer append. Must be called with fb.mu held and
// after any due cleanup, so callers that must decide something about existing
// buffer contents can do so atomically with the append itself.
func (fb *FragmentBuffer) appendLocked(sessionKey string, payload []byte) FragmentAppendResult {
	sb, exists := fb.sessions[sessionKey]
	if !exists {
		// Check global session cap before creating a new session. Do not evict
		// another session: a later fragment could otherwise complete a secret
		// in an empty bucket and pass uninspected.
		if fb.sessionCountLocked() >= fb.maxSessions {
			return FragmentAppendResult{CapacityExceeded: true}
		}
		sb = &sessionBuffer{}
		fb.sessions[sessionKey] = sb
	}

	// Copy payload to prevent caller mutation of buffered data.
	copied := make([]byte, len(payload))
	copy(copied, payload)

	now := time.Now()
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
	return FragmentAppendResult{}
}

func (fb *FragmentBuffer) sessionCountLocked() int {
	return len(fb.sessions) + len(fb.pathSessions)
}

// minFragmentsForMatch is the minimum number of in-window fragments a session
// must hold to be a candidate cross-request secret. A single fragment is a
// one-request secret handled by body DLP.
const minFragmentsForMatch = 2

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
	if !exists {
		fb.mu.Unlock()
		return nil
	}
	fragments := fb.activeFragmentsLocked(sb.fragments)
	fb.mu.Unlock()
	return scanFragmentsForSecrets(ctx, sc, fragments)
}

// AppendPathSegments records a URL path as bounded, position-aware CEE state.
// Static positions contribute their first value only. Once a position has ever
// varied, every value at that position is appended in order, including exact
// repeats. Therefore a suffix-first, prefix, suffix replay produces the stream
// suffix-prefix-suffix and cannot prime away the completing suffix.
//
// Path state shares one logical buffer session and one byte cap across all
// positions. A path depth cannot consume the global session cap one position at
// a time.
func (fb *FragmentBuffer) AppendPathSegments(sessionKey string, segments [][]byte) FragmentAppendResult {
	if fb == nil || len(segments) == 0 {
		return FragmentAppendResult{}
	}
	if len(segments) > MaxPathPositions {
		return FragmentAppendResult{PathDepthExceeded: true}
	}
	hasSegment := false
	for _, segment := range segments {
		if len(segment) > 0 {
			hasSegment = true
			break
		}
	}
	if !hasSegment {
		return FragmentAppendResult{}
	}

	fb.mu.Lock()
	defer fb.mu.Unlock()
	fb.maybeCleanupLocked(time.Now())

	ps, exists := fb.pathSessions[sessionKey]
	if !exists {
		if fb.sessionCountLocked() >= fb.maxSessions {
			return FragmentAppendResult{CapacityExceeded: true}
		}
		ps = &pathSessionBuffer{positions: make(map[int]*pathPositionBuffer)}
		fb.pathSessions[sessionKey] = ps
	}

	for position, segment := range segments {
		if len(segment) == 0 {
			continue
		}
		pb, exists := ps.positions[position]
		if !exists {
			copied := append([]byte(nil), segment...)
			pb = &pathPositionBuffer{initial: copied}
			ps.positions[position] = pb
			fb.appendPathFragmentLocked(ps, pb, segment)
			continue
		}

		if !pb.varied {
			if bytes.Equal(pb.initial, segment) {
				// This position has still never varied. Repeating its fixed route
				// text carries no new cross-request ordering information.
				continue
			}
			pb.varied = true
		}
		// Once varied, never suppress by value: a duplicate may be the final
		// half of a split secret after an attacker primed it earlier.
		fb.appendPathFragmentLocked(ps, pb, segment)
	}
	fb.enforcePathMaxBytesLocked(ps)
	return FragmentAppendResult{}
}

func (fb *FragmentBuffer) appendPathFragmentLocked(ps *pathSessionBuffer, pb *pathPositionBuffer, payload []byte) {
	copied := append([]byte(nil), payload...)
	pb.fragments = append(pb.fragments, fragment{data: copied, at: time.Now()})
	pb.totalBytes += len(copied)
	ps.totalBytes += len(copied)
}

// ScanPathForSecrets scans every path position independently. Combining
// different positions would reintroduce static route text and would falsely
// make a single-request secret appear to span requests.
func (fb *FragmentBuffer) ScanPathForSecrets(ctx context.Context, sessionKey string, sc *Scanner) []DLPMatch {
	fb.mu.Lock()
	fb.maybeCleanupLocked(time.Now())
	ps, exists := fb.pathSessions[sessionKey]
	if !exists {
		fb.mu.Unlock()
		return nil
	}

	streams := make([][]fragment, 0, len(ps.positions))
	for _, pb := range ps.positions {
		if fragments := fb.activeFragmentsLocked(pb.fragments); len(fragments) >= minFragmentsForMatch {
			streams = append(streams, fragments)
		}
	}
	fb.mu.Unlock()

	var matches []DLPMatch
	for _, fragments := range streams {
		matches = append(matches, scanFragmentsForSecrets(ctx, sc, fragments)...)
	}
	return matches
}

func (fb *FragmentBuffer) activeFragmentsLocked(fragments []fragment) []fragment {
	cutoff := time.Now().Add(-time.Duration(fb.windowSecs) * time.Second)
	active := make([]fragment, 0, len(fragments))
	for _, f := range fragments {
		if !f.at.Before(cutoff) {
			active = append(active, f)
		}
	}
	return active
}

func scanFragmentsForSecrets(ctx context.Context, sc *Scanner, fragments []fragment) []DLPMatch {
	if len(fragments) < minFragmentsForMatch {
		return nil
	}

	buf := make([]byte, 0)
	for _, f := range fragments {
		buf = append(buf, f.data...)
	}

	var individualFragments [][]byte
	for _, f := range fragments {
		individualFragments = append(individualFragments, f.data)
	}

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
	for _, ps := range fb.pathSessions {
		total += ps.totalBytes
	}
	return total
}

// UpdateConfig applies new fragment limits without discarding fragments that
// remain valid under them. It removes expired data first, then retains each
// session's newest suffix within the new byte cap. This lets a reload tighten
// limits immediately without creating a fresh split-secret window.
func (fb *FragmentBuffer) UpdateConfig(maxBytesPerSession, windowSecs int) {
	if maxBytesPerSession <= 0 {
		maxBytesPerSession = 1
	}
	if windowSecs <= 0 {
		windowSecs = 1
	}

	fb.mu.Lock()
	defer fb.mu.Unlock()

	fb.maxBytes = maxBytesPerSession
	fb.windowSecs = windowSecs
	now := time.Now()
	fb.cleanupLocked(now)
	for _, sb := range fb.sessions {
		fb.enforceMaxBytesLocked(sb)
	}
	for _, ps := range fb.pathSessions {
		fb.enforcePathMaxBytesLocked(ps)
	}
	fb.lastCleanup = now
}

func (fb *FragmentBuffer) enforceMaxBytesLocked(sb *sessionBuffer) {
	for sb.totalBytes > fb.maxBytes && len(sb.fragments) > 1 {
		sb.totalBytes -= len(sb.fragments[0].data)
		sb.fragments = sb.fragments[1:]
	}
	if sb.totalBytes > fb.maxBytes && len(sb.fragments) == 1 {
		last := &sb.fragments[0]
		last.data = last.data[len(last.data)-fb.maxBytes:]
		sb.totalBytes = fb.maxBytes
	}
}

// enforcePathMaxBytesLocked applies the ordinary logical-session cap across
// every path position. It evicts the globally oldest retained position
// fragment, rather than allowing each position to claim a separate 64 KiB
// budget. MaxPathPositions keeps this bounded scan small.
func (fb *FragmentBuffer) enforcePathMaxBytesLocked(ps *pathSessionBuffer) {
	for ps.totalBytes > fb.maxBytes {
		var oldestPosition int
		var oldest *pathPositionBuffer
		var oldestAt time.Time
		found := false
		for position, pb := range ps.positions {
			if len(pb.fragments) == 0 {
				continue
			}
			candidate := pb.fragments[0]
			if !found || candidate.at.Before(oldestAt) || (candidate.at.Equal(oldestAt) && position < oldestPosition) {
				oldestPosition, oldest, oldestAt, found = position, pb, candidate.at, true
			}
		}
		if !found {
			return
		}

		overage := ps.totalBytes - fb.maxBytes
		first := &oldest.fragments[0]
		if len(first.data) <= overage {
			removed := len(first.data)
			oldest.fragments = oldest.fragments[1:]
			oldest.totalBytes -= removed
			ps.totalBytes -= removed
			if len(oldest.fragments) == 0 {
				delete(ps.positions, oldestPosition)
			}
			continue
		}
		first.data = first.data[overage:]
		oldest.totalBytes -= overage
		ps.totalBytes -= overage
	}
}

// Delete removes all fragment state for the given session key.
func (fb *FragmentBuffer) Delete(key string) {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	delete(fb.sessions, key)
	delete(fb.pathSessions, key)
}

// Close retires all buffered fragments. It is safe to call more than once.
func (fb *FragmentBuffer) Close() {
	if fb == nil {
		return
	}
	fb.mu.Lock()
	defer fb.mu.Unlock()
	fb.sessions = make(map[string]*sessionBuffer)
	fb.pathSessions = make(map[string]*pathSessionBuffer)
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

	for key, ps := range fb.pathSessions {
		for position, pb := range ps.positions {
			for len(pb.fragments) > 0 && pb.fragments[0].at.Before(cutoff) {
				removed := len(pb.fragments[0].data)
				pb.fragments = pb.fragments[1:]
				pb.totalBytes -= removed
				ps.totalBytes -= removed
			}
			if len(pb.fragments) == 0 {
				// Once a position has no retained evidence, discard its stability
				// classification as well. A later request starts a fresh window.
				delete(ps.positions, position)
			}
		}
		if len(ps.positions) == 0 {
			delete(fb.pathSessions, key)
		}
	}
}
