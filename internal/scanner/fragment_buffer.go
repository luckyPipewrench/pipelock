// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"bytes"
	"context"
	"crypto/rand"
	"strings"
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
	// OwnerMismatch means the stream already holds another identity's
	// evidence. Appending anyway would join two clients' fragments, which
	// both manufactures a match from unrelated data and lets one client pad
	// another's stream, so the caller must treat the request as uninspected.
	OwnerMismatch bool
}

// FragmentBuffer accumulates outbound payloads per session in rolling buffers.
// On each call to ScanForSecrets, the concatenated buffer is scanned against
// DLP patterns synchronously. This guarantees pre-forward detection: a request
// that completes a split secret is blocked before egress. Thread-safe.
type FragmentBuffer struct {
	mu           sync.Mutex
	maxBytes     int // per-session byte cap
	maxSessions  int // global owner cap (new identities are denied at capacity)
	windowSecs   int // fragment retention window in seconds
	sessions     map[string]*sessionBuffer
	pathSessions map[string]*pathSessionBuffer
	owners       map[string]*ownerState // logical identity -> its live streams
	streamOwners map[string]string      // stream id -> logical identity
	partitionKey [32]byte
	lastCleanup  time.Time
}

const (
	fragmentStreamKindData = "d\x00"
	fragmentStreamKindPath = "p\x00"
)

// ownerState is one logical identity's footprint. The ledger admits identities
// rather than streams, so the byte budget has to live here too: enforcing it
// per stream would let one identity hold thousands of separately-capped
// streams, which turns the configured memory ceiling into that ceiling times
// the bucket cardinality.
type ownerState struct {
	streams map[string]struct{}
	// budgets maps a budget group to the stream ids sharing its byte cap.
	// Grouping exists because ONE class of stream has attacker-controlled
	// cardinality: JSON buckets. The fixed classes (raw body, query keys, path
	// positions) are at most one stream each, so each keeps its own cap and the
	// identity's ceiling stays a small stated multiple of the configured figure
	// rather than that figure times the bucket count.
	budgets map[string]map[string]struct{}
	groupOf map[string]string
}

// NewFragmentBuffer creates a fragment buffer with the given per-session byte cap,
// global identity cap, and fragment retention window. The partition key is
// generated once and kept for the life of this buffer so JSON bucket mapping
// cannot rotate while fragments still exist.
func NewFragmentBuffer(maxBytesPerSession, maxSessions, windowSecs int) *FragmentBuffer {
	fb := &FragmentBuffer{
		maxBytes:     maxBytesPerSession,
		maxSessions:  maxSessions,
		windowSecs:   windowSecs,
		sessions:     make(map[string]*sessionBuffer),
		pathSessions: make(map[string]*pathSessionBuffer),
		owners:       make(map[string]*ownerState),
		streamOwners: make(map[string]string),
		lastCleanup:  time.Now(),
	}
	// crypto/rand.Read is documented never to return an error: it fills the
	// buffer entirely and crashes the program irrecoverably if the operating
	// system source fails. Branching on an error here would be dead code that
	// reads like a handled degradation, so the key is unconditional and a
	// buffer always has one.
	_, _ = rand.Read(fb.partitionKey[:])
	return fb
}

// PartitionKey returns the buffer-lifetime secret used to map JSON paths into
// fragment buckets. Every constructed buffer has one, and it survives both
// UpdateConfig and Close so a bucket map cannot change under fragments that
// are still retained. It is empty only for a nil buffer, and a caller with no
// key must decline to partition rather than fall back to a public digest,
// which an attacker can grind offline.
func (fb *FragmentBuffer) PartitionKey() []byte {
	if fb == nil {
		return nil
	}
	fb.mu.Lock()
	defer fb.mu.Unlock()
	key := make([]byte, len(fb.partitionKey))
	copy(key, fb.partitionKey[:])
	return key
}

// Append adds a payload fragment to the session's rolling buffer.
// Evicts oldest fragments when the per-session byte cap is exceeded.
// Refuses a new session when the global session cap is reached: accumulated
// fragment state is security evidence and must not be silently evicted.
func (fb *FragmentBuffer) Append(sessionKey string, payload []byte) FragmentAppendResult {
	return fb.AppendForSession(sessionKey, payload)
}

// AppendForSession appends an independently scanned stream. The stream key is
// also the ledger identity, which is what unit tests and callers that still
// buffer one stream per client use.
func (fb *FragmentBuffer) AppendForSession(streamKey string, payload []byte) FragmentAppendResult {
	return fb.AppendOwned(streamKey, streamKey, payload)
}

// AppendOwned appends an independently scanned stream under a logical identity.
// Additional streams for an identity that already holds evidence do not consume
// another global ledger slot. A new identity is refused at capacity rather than
// evicting someone else's fragments or skipping this identity's inspection.
func (fb *FragmentBuffer) AppendOwned(owner, streamKey string, payload []byte) FragmentAppendResult {
	return fb.AppendOwnedInGroup(owner, streamKey, streamKey, payload)
}

// AppendOwnedInGroup appends a stream that shares a byte budget with the other
// streams in group. Streams whose cardinality the caller fixes (one raw body,
// one query-key stream, one path stream) pass their own key and keep the plain
// per-stream cap. Streams whose cardinality an attacker chooses, such as the
// JSON buckets a request body maps into, pass a shared group so the identity's
// retention stays a small stated multiple of the configured figure instead of
// that figure times the bucket count.
func (fb *FragmentBuffer) AppendOwnedInGroup(owner, group, streamKey string, payload []byte) FragmentAppendResult {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	fb.maybeCleanupLocked(time.Now())
	return fb.appendLocked(owner, group, streamKey, payload)
}

// appendLocked performs the buffer append. Must be called with fb.mu held and
// after any due cleanup, so callers that must decide something about existing
// buffer contents can do so atomically with the append itself.
func (fb *FragmentBuffer) appendLocked(owner, group, streamKey string, payload []byte) FragmentAppendResult {
	streamID := fragmentStreamID(fragmentStreamKindData, streamKey)
	// Normalized once here so everything below can assume a non-empty owner:
	// a caller that keeps one stream per client passes no owner, and that
	// stream is then its own identity.
	if owner == "" {
		owner = streamID
	}
	if group == "" {
		group = streamID
	}
	sb, exists := fb.sessions[streamKey]
	if !exists {
		if !fb.canAdmitOwnerLocked(owner) {
			return FragmentAppendResult{CapacityExceeded: true}
		}
		sb = &sessionBuffer{}
		fb.sessions[streamKey] = sb
		fb.trackOwnerStreamLocked(owner, group, streamID)
	} else if !fb.streamOwnedByLocked(streamID, owner) {
		return FragmentAppendResult{OwnerMismatch: true}
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
	// The per-stream cap above bounds one stream; this bounds the identity that
	// owns it, which is the unit the ledger admits.
	fb.enforceOwnerBudgetLocked(owner, streamID)
	return FragmentAppendResult{}
}

func (fb *FragmentBuffer) sessionCountLocked() int {
	return len(fb.owners)
}

func fragmentStreamID(kind, streamKey string) string {
	return kind + streamKey
}

func (fb *FragmentBuffer) canAdmitOwnerLocked(owner string) bool {
	if owner != "" && fb.owners[owner] != nil {
		return true
	}
	return fb.sessionCountLocked() < fb.maxSessions
}

// streamOwnedByLocked reports whether an existing stream may accept a fragment
// from owner. Every live stream carries a recorded owner: creation tracks it
// and every deletion path routes through deleteStreamLocked, which untracks it.
// An untracked live stream is therefore an invariant violation rather than a
// legacy stream, and it is refused for the same reason a mismatch is: the safe
// answer when ownership cannot be established is to report the request as
// uninspected, never to blend two identities' evidence.
func (fb *FragmentBuffer) streamOwnedByLocked(streamID, owner string) bool {
	recorded, ok := fb.streamOwners[streamID]
	if !ok {
		return false
	}
	return recorded == owner
}

func (fb *FragmentBuffer) trackOwnerStreamLocked(owner, group, streamID string) {
	fb.streamOwners[streamID] = owner
	state := fb.owners[owner]
	if state == nil {
		state = &ownerState{
			streams: make(map[string]struct{}),
			budgets: make(map[string]map[string]struct{}),
			groupOf: make(map[string]string),
		}
		fb.owners[owner] = state
	}
	state.streams[streamID] = struct{}{}
	state.groupOf[streamID] = group
	if state.budgets[group] == nil {
		state.budgets[group] = make(map[string]struct{})
	}
	state.budgets[group][streamID] = struct{}{}
}

func (fb *FragmentBuffer) untrackStreamLocked(streamID string) {
	owner, ok := fb.streamOwners[streamID]
	if !ok {
		return
	}
	delete(fb.streamOwners, streamID)
	state := fb.owners[owner]
	if state == nil {
		return
	}
	delete(state.streams, streamID)
	if group, ok := state.groupOf[streamID]; ok {
		delete(state.groupOf, streamID)
		delete(state.budgets[group], streamID)
		if len(state.budgets[group]) == 0 {
			delete(state.budgets, group)
		}
	}
	if len(state.streams) == 0 {
		delete(fb.owners, owner)
	}
}

// recomputeOwnerBytesLocked re-derives an identity's footprint from its live
// streams. Deletion paths (window expiry, operator reset) remove whole streams
// without reporting how many bytes went with them, so the total is rebuilt
// rather than decremented, which cannot drift below the real figure and then
// admit unbounded retention.
func (fb *FragmentBuffer) groupBytesLocked(members map[string]struct{}) int {
	total := 0
	for streamID := range members {
		total += fb.streamBytesLocked(streamID)
	}
	return total
}

// streamBytesLocked reports one grouped stream's retained bytes. Only data
// streams are ever grouped: a session has exactly one path stream, so it keeps
// the plain per-stream cap and never shares a budget.
func (fb *FragmentBuffer) streamBytesLocked(streamID string) int {
	if sb := fb.sessions[strings.TrimPrefix(streamID, fragmentStreamKindData)]; sb != nil {
		return sb.totalBytes
	}
	return 0
}

// enforceOwnerBudgetLocked keeps one identity's retained bytes within the
// configured cap by evicting its OWN oldest fragment until it fits. Evicting
// within an identity is the same trade the per-stream cap already makes, and
// the newest bytes are kept because they are the ones most likely to complete
// a split secret. It never touches another identity's evidence: a fragment
// dropped from a stranger's stream could let a later request complete a secret
// in an emptied stream and pass uninspected.
func (fb *FragmentBuffer) enforceOwnerBudgetLocked(owner, streamID string) {
	state := fb.owners[owner]
	if state == nil {
		return
	}
	group, ok := state.groupOf[streamID]
	if !ok {
		return
	}
	members := state.budgets[group]
	// A group of one is already held by the per-stream cap; only a group whose
	// membership an attacker can grow needs this.
	if len(members) <= 1 {
		return
	}
	for fb.groupBytesLocked(members) > fb.maxBytes {
		if !fb.evictOldestOwnerFragmentLocked(members) {
			return
		}
	}
}

// evictOldestOwnerFragmentLocked drops the single oldest fragment held by one
// identity and reports whether anything was removed. A false return means the
// identity holds nothing further that can be released, which stops the caller
// from spinning.
func (fb *FragmentBuffer) evictOldestOwnerFragmentLocked(members map[string]struct{}) bool {
	var (
		oldest   *sessionBuffer
		oldestAt time.Time
	)
	for streamID := range members {
		sb := fb.sessions[strings.TrimPrefix(streamID, fragmentStreamKindData)]
		if sb == nil || len(sb.fragments) == 0 {
			continue
		}
		if oldest == nil || sb.fragments[0].at.Before(oldestAt) {
			oldest, oldestAt = sb, sb.fragments[0].at
		}
	}
	if oldest == nil {
		return false
	}
	oldest.totalBytes -= len(oldest.fragments[0].data)
	oldest.fragments = oldest.fragments[1:]
	return true
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
	return fb.AppendPathSegmentsForSession(sessionKey, segments)
}

// AppendPathSegmentsForSession appends a position-aware stream. The stream key
// is also the ledger identity.
func (fb *FragmentBuffer) AppendPathSegmentsForSession(streamKey string, segments [][]byte) FragmentAppendResult {
	return fb.AppendPathSegmentsOwned(streamKey, streamKey, segments)
}

// AppendPathSegmentsOwned appends a position-aware stream under a logical
// identity. Path state shares that identity's ledger slot with any sibling
// JSON or raw streams rather than competing with them one key at a time.
func (fb *FragmentBuffer) AppendPathSegmentsOwned(owner, streamKey string, segments [][]byte) FragmentAppendResult {
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

	pathStreamID := fragmentStreamID(fragmentStreamKindPath, streamKey)
	if owner == "" {
		owner = pathStreamID
	}
	ps, exists := fb.pathSessions[streamKey]
	if !exists {
		if !fb.canAdmitOwnerLocked(owner) {
			return FragmentAppendResult{CapacityExceeded: true}
		}
		ps = &pathSessionBuffer{positions: make(map[int]*pathPositionBuffer)}
		fb.pathSessions[streamKey] = ps
		fb.trackOwnerStreamLocked(owner, pathStreamID, pathStreamID)
	} else if !fb.streamOwnedByLocked(pathStreamID, owner) {
		return FragmentAppendResult{OwnerMismatch: true}
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
	// A session has exactly one path stream, so enforcePathMaxBytesLocked above
	// is already its whole budget; there is no group for it to share.
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
func (fb *FragmentBuffer) UpdateConfig(maxBytesPerSession, maxSessions, windowSecs int) {
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
	if maxSessions > 0 {
		fb.maxSessions = maxSessions
	}
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
	fb.deleteStreamLocked(key)
}

// DeletePrefix clears every ordinary and position-aware stream whose key
// begins with prefix. It supports bounded families of hashed child streams
// (for example, JSON body fields) when the parent CEE session is reset.
func (fb *FragmentBuffer) DeletePrefix(prefix string) {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	for key := range fb.sessions {
		if strings.HasPrefix(key, prefix) {
			fb.deleteStreamLocked(key)
		}
	}
	for key := range fb.pathSessions {
		if strings.HasPrefix(key, prefix) {
			fb.deleteStreamLocked(key)
		}
	}
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
	fb.owners = make(map[string]*ownerState)
	fb.streamOwners = make(map[string]string)
	// The partition key deliberately SURVIVES Close. A hot reload swaps the
	// buffer pointer and then closes the old buffer, so a request already
	// holding it would otherwise read an empty key, decline to partition, and
	// fall back to the raw stream alone for the rest of its life. The key is
	// process-local and labels no persisted evidence, so retaining it costs
	// nothing and removes that silent degradation.
}

func (fb *FragmentBuffer) deleteStreamLocked(key string) {
	_, hadData := fb.sessions[key]
	_, hadPath := fb.pathSessions[key]
	delete(fb.sessions, key)
	delete(fb.pathSessions, key)
	if hadData {
		fb.untrackStreamLocked(fragmentStreamID(fragmentStreamKindData, key))
	}
	if hadPath {
		fb.untrackStreamLocked(fragmentStreamID(fragmentStreamKindPath, key))
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
			fb.deleteStreamLocked(key)
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
			fb.deleteStreamLocked(key)
		}
	}
}
