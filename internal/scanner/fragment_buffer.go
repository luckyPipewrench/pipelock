// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"bytes"
	"context"
	"crypto/rand"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/identitykey"
	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

// DLPMatch describes a single DLP pattern match found in reassembled fragments.
type DLPMatch struct {
	PatternName string
	Matched     string
	Warn        bool // true for warn-mode patterns (informational only)
	// Contributors identifies only the retained source requests whose bytes
	// overlap this occurrence. Values are opaque, caller-sanitized identifiers.
	Contributors [][]byte
}

// MaxFragmentSourceRequestIDBytes bounds provenance metadata independently of
// caller behavior. It matches the MCP capture RPC-ID ceiling; keeping the
// guard here prevents another FragmentAppend caller from turning a small
// retained payload into arbitrarily large ledger metadata.
const MaxFragmentSourceRequestIDBytes = 128

const (
	maxFragmentDLPNormalizationPasses = 3
	fragmentDLPNormalizationFailure   = "DLP normalization did not converge"
)

// fragment holds a single outbound payload chunk with its arrival time.
// continuity is empty for a stream whose bytes are one secret. A non-empty
// value joins only with fragments that carry the same identity, so unrelated
// leaves that share a retention stream cannot sit between two halves.
type fragment struct {
	data            []byte
	at              time.Time
	sourceRequestID []byte
	continuity      []byte
}

// sessionBuffer accumulates outbound fragments for a single session.
type sessionBuffer struct {
	streamID     string
	groupMembers map[string]struct{}
	fragments    []fragment
	storage      []fragment
	totalBytes   int
}

// appendFragmentReusingStorage keeps the active descriptors contiguous and in
// their original order. Front eviction can leave reusable capacity before the
// active slice; compact into that capacity only when the tail fills. Payload
// and request-ID bytes are immutable, and scan snapshots own descriptor copies.
// Callers hold the FragmentBuffer lock.
func appendFragmentReusingStorage(active, storage []fragment, next fragment) ([]fragment, []fragment) {
	if len(active) == cap(active) {
		// After a large trim, let normal append replace the oversized backing
		// array instead of retaining historical high-water capacity forever.
		if len(storage) > len(active) && len(storage)-len(active) <= len(active) {
			n := copy(storage, active)
			clear(storage[n:])
			active = storage[:n]
		} else {
			active = append(active, next)
			return active, active[:cap(active)]
		}
	}
	return append(active, next), storage
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
	storage    []fragment
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
	cleanMemo    fragmentCleanMemo
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
func (fb *FragmentBuffer) Append(sessionKey identitykey.CEEIdentity, payload []byte) FragmentAppendResult {
	return fb.AppendForSession(sessionKey.Stream(""), payload)
}

// AppendForSession appends an independently scanned stream. The stream key is
// also the ledger identity, which is what unit tests and callers that still
// buffer one stream per client use.
func (fb *FragmentBuffer) AppendForSession(streamKey identitykey.CEEStream, payload []byte) FragmentAppendResult {
	return fb.AppendOwned(streamKey.Owner(), streamKey, payload)
}

// AppendOwned appends an independently scanned stream under a logical identity.
// Additional streams for an identity that already holds evidence do not consume
// another global ledger slot. A new identity is refused at capacity rather than
// evicting someone else's fragments or skipping this identity's inspection.
func (fb *FragmentBuffer) AppendOwned(owner identitykey.CEEIdentity, streamKey identitykey.CEEStream, payload []byte) FragmentAppendResult {
	return fb.AppendOwnedInGroup(owner, streamKey, streamKey, payload)
}

// AppendOwnedInGroup appends a stream that shares a byte budget with the other
// streams in group. Streams whose cardinality the caller fixes (one raw body,
// one query-key stream, one path stream) pass their own key and keep the plain
// per-stream cap. Streams whose cardinality an attacker chooses, such as the
// JSON buckets a request body maps into, pass a shared group so the identity's
// retention stays a small stated multiple of the configured figure instead of
// that figure times the bucket count.
func (fb *FragmentBuffer) AppendOwnedInGroup(owner identitykey.CEEIdentity, group, streamKey identitykey.CEEStream, payload []byte) FragmentAppendResult {
	if group.Owner() != owner || streamKey.Owner() != owner {
		return FragmentAppendResult{OwnerMismatch: true}
	}
	fb.mu.Lock()
	defer fb.mu.Unlock()
	fb.maybeCleanupLocked(time.Now())
	return fb.appendLocked(owner.Key(), group.Key(), streamKey.Key(), payload)
}

// AppendAndScanOwnedInGroup captures the completed stream before retention
// eviction, then scans that immutable snapshot after releasing the ledger lock.
// A completing request must not evict the bytes needed to inspect itself. The
// retained ledger still obeys maxBytes; the scan holds at most the previous
// retained stream plus the current request's already-bounded payload.
func (fb *FragmentBuffer) AppendAndScanOwnedInGroup(ctx context.Context, owner identitykey.CEEIdentity, group, streamKey identitykey.CEEStream, payload []byte, sc *Scanner) (FragmentAppendResult, []DLPMatch) {
	if group.Owner() != owner || streamKey.Owner() != owner {
		return FragmentAppendResult{OwnerMismatch: true}, nil
	}
	var snapshot []fragment
	fb.mu.Lock()
	fb.maybeCleanupLocked(time.Now())
	result := fb.appendWithSnapshotLocked(owner.Key(), group.Key(), streamKey.Key(), FragmentPiece{Data: payload}, nil, &snapshot)
	fb.mu.Unlock()
	return result, fb.scanBatchWithCleanMemo(ctx, sc, snapshot, fragmentStreamKindData+streamKey.Key())
}

// FragmentPiece is one leaf inside a stream. Continuity is the identity that
// reassembly must keep contiguous. Empty Continuity means the piece joins
// every other empty-continuity fragment in the stream, which is the legacy
// single-payload behavior. Pieces with the same continuity in one append are
// stored as one fragment, even when another leaf sits between them, so a
// single request cannot look like a cross-request match.
type FragmentPiece struct {
	Continuity []byte
	Data       []byte
}

// FragmentAppend identifies one stream carried by a request. Streams can share
// a retention group without allowing one field to evict another before scanning.
// When Pieces is non-empty it is the stream contents and Payload is ignored.
type FragmentAppend struct {
	Group   identitykey.CEEStream
	Stream  identitykey.CEEStream
	Payload []byte
	Pieces  []FragmentPiece
	// SourceRequestID is an optional opaque request identity. The ledger retains
	// it only when it is non-empty and no larger than
	// MaxFragmentSourceRequestIDBytes. Legacy or oversized identities do not
	// weaken detection, but a later match cannot claim complete request-level
	// provenance when one of its contributing fragments is unidentified.
	SourceRequestID []byte
}

// AppendAndScanOwnedBatch snapshots every request stream before applying any
// retention limit. Results retain input order. An admission failure returns no
// findings and must be handled as a refusal by the caller.
func (fb *FragmentBuffer) AppendAndScanOwnedBatch(ctx context.Context, owner identitykey.CEEIdentity, appends []FragmentAppend, sc *Scanner) (FragmentAppendResult, [][]DLPMatch) {
	for _, item := range appends {
		if item.Group.Owner() != owner || item.Stream.Owner() != owner {
			return FragmentAppendResult{OwnerMismatch: true}, nil
		}
	}
	snapshots := make([][]fragment, len(appends))
	fb.mu.Lock()
	fb.maybeCleanupLocked(time.Now())
	// Check the recorded binding for every stream before changing any state.
	// Distinct classified identities can still derive colliding string keys.
	for _, item := range appends {
		streamID := fragmentStreamID(fragmentStreamKindData, item.Stream.Key())
		recordedOwner := owner.Key()
		if recordedOwner == "" {
			recordedOwner = streamID
		}
		if fb.sessions[item.Stream.Key()] != nil && !fb.streamOwnedByLocked(streamID, recordedOwner) {
			fb.mu.Unlock()
			return FragmentAppendResult{OwnerMismatch: true}, nil
		}
	}
	var result FragmentAppendResult
	appended := 0
	for i, item := range appends {
		if len(item.Pieces) > 0 {
			result = fb.appendPiecesSnapshotLocked(owner.Key(), item.Group.Key(), item.Stream.Key(), item.Pieces, item.SourceRequestID, &snapshots[i])
		} else {
			result = fb.appendSnapshotLocked(owner.Key(), item.Group.Key(), item.Stream.Key(), FragmentPiece{Data: item.Payload}, item.SourceRequestID, &snapshots[i])
		}
		if result != (FragmentAppendResult{}) {
			break
		}
		appended++
	}
	for _, item := range appends[:appended] {
		fb.retainStreamLocked(owner.Key(), item.Stream.Key())
	}
	fb.mu.Unlock()
	if result != (FragmentAppendResult{}) {
		return result, nil
	}
	matches := make([][]DLPMatch, len(snapshots))
	for i, item := range appends {
		matches[i] = fb.scanBatchWithCleanMemo(ctx, sc, snapshots[i], fragmentStreamKindData+item.Stream.Key())
	}
	return FragmentAppendResult{}, matches
}

// appendLocked performs the buffer append. Must be called with fb.mu held and
// after any due cleanup, so callers that must decide something about existing
// buffer contents can do so atomically with the append itself.
func (fb *FragmentBuffer) appendLocked(owner, group, streamKey string, payload []byte) FragmentAppendResult {
	return fb.appendWithSnapshotLocked(owner, group, streamKey, FragmentPiece{Data: payload}, nil, nil)
}

func (fb *FragmentBuffer) appendWithSnapshotLocked(owner, group, streamKey string, piece FragmentPiece, sourceRequestID []byte, snapshot *[]fragment) FragmentAppendResult {
	result := fb.appendSnapshotLocked(owner, group, streamKey, piece, sourceRequestID, snapshot)
	if result == (FragmentAppendResult{}) {
		fb.retainStreamLocked(owner, streamKey)
	}
	return result
}

func (fb *FragmentBuffer) appendPiecesSnapshotLocked(owner, group, streamKey string, pieces []FragmentPiece, sourceRequestID []byte, snapshot *[]fragment) FragmentAppendResult {
	merged := mergeFragmentPieces(pieces)
	var result FragmentAppendResult
	for _, piece := range merged {
		result = fb.appendSnapshotLocked(owner, group, streamKey, piece, sourceRequestID, nil)
		if result != (FragmentAppendResult{}) {
			return result
		}
	}
	if snapshot != nil {
		if sb := fb.sessions[streamKey]; sb != nil {
			*snapshot = fb.activeFragmentsLocked(sb.fragments)
		}
	}
	return FragmentAppendResult{}
}

func mergeFragmentPieces(pieces []FragmentPiece) []FragmentPiece {
	merged := make([]FragmentPiece, 0, len(pieces))
	index := make(map[string]int, len(pieces))
	for _, piece := range pieces {
		if len(piece.Data) == 0 {
			continue
		}
		key := string(piece.Continuity)
		if at, ok := index[key]; ok {
			merged[at].Data = append(merged[at].Data, piece.Data...)
			continue
		}
		index[key] = len(merged)
		merged = append(merged, FragmentPiece{
			Continuity: append([]byte(nil), piece.Continuity...),
			Data:       append([]byte(nil), piece.Data...),
		})
	}
	return merged
}

func (fb *FragmentBuffer) appendSnapshotLocked(owner, group, streamKey string, piece FragmentPiece, sourceRequestID []byte, snapshot *[]fragment) FragmentAppendResult {
	sb, exists := fb.sessions[streamKey]
	streamID := ""
	if sb != nil {
		streamID = sb.streamID
	}
	if streamID == "" {
		streamID = fragmentStreamID(fragmentStreamKindData, streamKey)
	}
	// Normalized once here so everything below can assume a non-empty owner:
	// a caller that keeps one stream per client passes no owner, and that
	// stream is then its own identity.
	if owner == "" {
		owner = streamID
	}
	if group == "" {
		group = streamID
	}
	if !exists {
		if !fb.canAdmitOwnerLocked(owner) {
			return FragmentAppendResult{CapacityExceeded: true}
		}
		sb = &sessionBuffer{streamID: streamID}
		fb.sessions[streamKey] = sb
		fb.trackOwnerStreamLocked(owner, group, streamID)
		sb.groupMembers = fb.owners[owner].budgets[group]
	} else if !fb.streamOwnedByLocked(streamID, owner) {
		return FragmentAppendResult{OwnerMismatch: true}
	}

	// Copy payload to prevent caller mutation of buffered data.
	copied := append([]byte(nil), piece.Data...)
	var continuity []byte
	if len(piece.Continuity) > 0 {
		continuity = append([]byte(nil), piece.Continuity...)
	}
	var requestID []byte
	if len(copied) > 0 && len(sourceRequestID) > 0 && len(sourceRequestID) <= MaxFragmentSourceRequestIDBytes {
		requestID = append([]byte(nil), sourceRequestID...)
	}

	now := time.Now()
	sb.fragments, sb.storage = appendFragmentReusingStorage(sb.fragments, sb.storage, fragment{
		data:            copied,
		at:              now,
		sourceRequestID: requestID,
		continuity:      continuity,
	})
	sb.totalBytes += len(copied)
	if snapshot != nil {
		// activeFragmentsLocked copies descriptors; payload bytes were copied
		// on entry and remain immutable even if the ledger evicts or resets.
		*snapshot = fb.activeFragmentsLocked(sb.fragments)
	}
	return FragmentAppendResult{}
}

func (fb *FragmentBuffer) retainStreamLocked(owner, streamKey string) {
	sb := fb.sessions[streamKey]
	if sb == nil {
		return // another stream's shared budget already evicted this stream
	}
	streamID := sb.streamID
	if streamID == "" {
		streamID = fragmentStreamID(fragmentStreamKindData, streamKey)
	}
	if owner == "" {
		owner = streamID
	}
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
	// The per-stream cap also bounds a singleton budget group. Shared groups
	// need the same group-budget enforcement as enforceOwnerBudgetLocked below.
	// Keep the membership map, never its size: another request can add a
	// sibling stream to the group while this stream remains live.
	if sb.groupMembers != nil && len(sb.groupMembers) <= 1 {
		return
	}
	fb.enforceOwnerBudgetLocked(owner, streamID)
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

// enforceOwnerBudgetLocked keeps the stream's budget group within the configured
// cap by evicting its oldest fragments. Independent groups retain their own caps.
// The newest bytes are kept because they are the ones most likely to complete a
// split secret. It never touches another group's evidence.
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

// evictOldestOwnerFragmentLocked drops the single oldest fragment in the budget
// group and reports whether anything was removed. A false return means the
// group holds nothing further that can be released, which stops the caller
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
func (fb *FragmentBuffer) ScanForSecrets(ctx context.Context, sessionKey identitykey.CEEStream, sc *Scanner) []DLPMatch {
	fb.mu.Lock()
	fb.maybeCleanupLocked(time.Now())
	sb, exists := fb.sessions[sessionKey.Key()]
	if !exists {
		fb.mu.Unlock()
		return nil
	}
	fragments := fb.activeFragmentsLocked(sb.fragments)
	fb.mu.Unlock()
	return fb.scanBatchWithCleanMemo(ctx, sc, fragments, fragmentStreamKindData+sessionKey.Key())
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
func (fb *FragmentBuffer) AppendPathSegments(sessionKey identitykey.CEEIdentity, segments [][]byte) FragmentAppendResult {
	return fb.AppendPathSegmentsForSession(sessionKey.Stream(""), segments)
}

// AppendPathSegmentsForSession appends a position-aware stream. The stream key
// is also the ledger identity.
func (fb *FragmentBuffer) AppendPathSegmentsForSession(streamKey identitykey.CEEStream, segments [][]byte) FragmentAppendResult {
	return fb.AppendPathSegmentsOwned(streamKey.Owner(), streamKey, segments)
}

// AppendPathSegmentsOwned appends a position-aware stream under a logical
// identity. Path state shares that identity's ledger slot with any sibling
// JSON or raw streams rather than competing with them one key at a time.
func (fb *FragmentBuffer) AppendPathSegmentsOwned(owner identitykey.CEEIdentity, streamKey identitykey.CEEStream, segments [][]byte) FragmentAppendResult {
	return fb.appendPathSegmentsWithSnapshot(owner, streamKey, segments, nil, nil)
}

// AppendAndScanPathSegmentsOwned inspects each completed position before the
// shared path retention budget evicts its earlier fragments.
func (fb *FragmentBuffer) AppendAndScanPathSegmentsOwned(ctx context.Context, owner identitykey.CEEIdentity, streamKey identitykey.CEEStream, segments [][]byte, sc *Scanner) (FragmentAppendResult, []DLPMatch) {
	var snapshots [][]fragment
	var snapshotKeys []string
	result := fb.appendPathSegmentsWithSnapshot(owner, streamKey, segments, &snapshots, &snapshotKeys)
	var matches []DLPMatch
	for i, fragments := range snapshots {
		matches = append(matches, fb.scanBatchWithCleanMemo(ctx, sc, fragments, snapshotKeys[i])...)
	}
	return result, matches
}

func (fb *FragmentBuffer) appendPathSegmentsWithSnapshot(owner identitykey.CEEIdentity, streamKey identitykey.CEEStream, segments [][]byte, snapshots *[][]fragment, snapshotKeys *[]string) FragmentAppendResult {
	if streamKey.Owner() != owner {
		return FragmentAppendResult{OwnerMismatch: true}
	}
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

	pathStreamID := fragmentStreamID(fragmentStreamKindPath, streamKey.Key())
	ownerKey := owner.Key()
	if ownerKey == "" {
		ownerKey = pathStreamID
	}
	ps, exists := fb.pathSessions[streamKey.Key()]
	if !exists {
		if !fb.canAdmitOwnerLocked(ownerKey) {
			return FragmentAppendResult{CapacityExceeded: true}
		}
		ps = &pathSessionBuffer{positions: make(map[int]*pathPositionBuffer)}
		fb.pathSessions[streamKey.Key()] = ps
		fb.trackOwnerStreamLocked(ownerKey, pathStreamID, pathStreamID)
	} else if !fb.streamOwnedByLocked(pathStreamID, ownerKey) {
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
	if snapshots != nil {
		for position, pb := range ps.positions {
			if fragments := fb.activeFragmentsLocked(pb.fragments); len(fragments) >= minFragmentsForMatch {
				*snapshots = append(*snapshots, fragments)
				*snapshotKeys = append(*snapshotKeys, fragmentStreamKindPath+streamKey.Key()+"\x00"+strconv.Itoa(position))
			}
		}
	}
	// A session has exactly one path stream, so enforcePathMaxBytesLocked below
	// is already its whole budget; there is no group for it to share.
	fb.enforcePathMaxBytesLocked(ps)
	return FragmentAppendResult{}
}

func (fb *FragmentBuffer) appendPathFragmentLocked(ps *pathSessionBuffer, pb *pathPositionBuffer, payload []byte) {
	copied := append([]byte(nil), payload...)
	pb.fragments, pb.storage = appendFragmentReusingStorage(pb.fragments, pb.storage, fragment{data: copied, at: time.Now()})
	pb.totalBytes += len(copied)
	ps.totalBytes += len(copied)
}

// ScanPathForSecrets scans every path position independently. Combining
// different positions would reintroduce static route text and would falsely
// make a single-request secret appear to span requests.
func (fb *FragmentBuffer) ScanPathForSecrets(ctx context.Context, sessionKey identitykey.CEEStream, sc *Scanner) []DLPMatch {
	fb.mu.Lock()
	fb.maybeCleanupLocked(time.Now())
	ps, exists := fb.pathSessions[sessionKey.Key()]
	if !exists {
		fb.mu.Unlock()
		return nil
	}

	streams := make([][]fragment, 0, len(ps.positions))
	var streamKeys []string
	for position, pb := range ps.positions {
		if fragments := fb.activeFragmentsLocked(pb.fragments); len(fragments) >= minFragmentsForMatch {
			streams = append(streams, fragments)
			streamKeys = append(streamKeys, fragmentStreamKindPath+sessionKey.Key()+"\x00"+strconv.Itoa(position))
		}
	}
	fb.mu.Unlock()

	var matches []DLPMatch
	for i, fragments := range streams {
		matches = append(matches, fb.scanBatchWithCleanMemo(ctx, sc, fragments, streamKeys[i])...)
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
	groups := fragmentContinuityGroups(fragments)
	if len(groups) <= 1 {
		if len(groups) == 0 {
			return nil
		}
		return scanOneFragmentContinuity(ctx, sc, groups[0])
	}
	var matches []DLPMatch
	for _, group := range groups {
		matches = append(matches, scanOneFragmentContinuity(ctx, sc, group)...)
	}
	return matches
}

// fragmentContinuityGroups keeps the legacy stream as one group. A stream
// that carries path identity is scanned once per identity, in first-seen
// order, so a sibling leaf cannot interrupt a split value.
func fragmentContinuityGroups(fragments []fragment) [][]fragment {
	if len(fragments) == 0 {
		return nil
	}
	keyed := false
	for _, item := range fragments {
		if len(item.continuity) > 0 {
			keyed = true
			break
		}
	}
	if !keyed {
		return [][]fragment{fragments}
	}
	index := make(map[string]int)
	groups := make([][]fragment, 0)
	for _, item := range fragments {
		key := string(item.continuity)
		at, ok := index[key]
		if !ok {
			index[key] = len(groups)
			groups = append(groups, nil)
			at = len(groups) - 1
		}
		groups[at] = append(groups[at], item)
	}
	return groups
}

func scanOneFragmentContinuity(ctx context.Context, sc *Scanner, fragments []fragment) []DLPMatch {
	return scanOneFragmentContinuityMemo(ctx, sc, fragments, nil, "")
}

func scanOneFragmentContinuityMemo(ctx context.Context, sc *Scanner, fragments []fragment, memo *fragmentCleanMemo, stream string) []DLPMatch {
	if len(fragments) < minFragmentsForMatch {
		return nil
	}

	buf := make([]byte, 0)
	ranges := make([]fragmentRange, 0, len(fragments))
	for _, f := range fragments {
		normalized, stable := normalizeFragmentForDLP(f.data)
		if !stable {
			// Scanner spans index another normalization pass. If the bounded
			// pipeline does not reach a fixed point, no fragment boundary can be
			// trusted; block without claiming contributor provenance.
			return []DLPMatch{{PatternName: fragmentDLPNormalizationFailure}}
		}
		start := len(buf)
		buf = append(buf, normalized...)
		ranges = append(ranges, fragmentRange{start: start, end: len(buf), normalized: normalized, fragment: f})
	}

	text := string(buf)
	key := fragmentCleanKey{scanner: sc, stream: stream, continuity: string(fragments[0].continuity)}
	if memo != nil && memo.lookup(key, text) {
		return nil
	}
	result := sc.ScanTextForDLP(ctx, text)
	if result.Clean && len(result.InformationalMatches) == 0 {
		if memo != nil {
			memo.store(key, text)
		}
		return nil
	}

	// Only report matches NOT found in any individual fragment.
	// These are true cross-request matches (secret spans fragment boundaries).
	// Warn-mode matches are NOT included here - they are already emitted
	// via DLPWarnHook inside ScanTextForDLP. Including them would cause
	// CEE callers to treat informational warn matches as enforcement signals.
	var matches []DLPMatch
	// Image excision splices decoded bytes into the scanned text, so match
	// offsets no longer line up with fragment ranges. Map positions back
	// through the removed image spans instead.
	if excised, decoded, removed := stripVerifiedImageDataURLSpans(text, true); len(removed) > 0 {
		return imageSplicedFragmentMatches(ctx, sc, excised, decoded, removed, ranges, result.Matches)
	}
	complete := completeFragmentOccurrences(ctx, sc, ranges)
	patternSet := make(map[string]struct{}, len(result.Matches))
	patternNames := make([]string, 0, len(result.Matches))
	for _, match := range result.Matches {
		if _, duplicate := patternSet[match.PatternName]; duplicate {
			continue
		}
		patternSet[match.PatternName] = struct{}{}
		patternNames = append(patternNames, match.PatternName)
	}
	sort.Strings(patternNames)
	for _, patternName := range patternNames {
		masked := append([]byte(nil), buf...)
		for _, occurrence := range complete[patternName] {
			_ = maskFragmentOccurrence(masked, occurrence.start, occurrence.end)
		}
		// Mask only complete occurrences of this pattern. Masking every rule at
		// once could erase a longer cross-fragment match from a different rule.
		// The scanner can report one occurrence per rule, so keep removing
		// complete occurrences until the next one crosses a request boundary or
		// the rule disappears.
		for {
			maskedResult := sc.ScanTextForDLPQuiet(ctx, string(masked))
			remasked := false
			crossed := false
			var rawTargets []TextDLPMatch
			invalidTargetFound := false
			for _, match := range maskedResult.Matches {
				if match.PatternName != patternName {
					continue
				}
				span := match.Span()
				if match.Encoded != "" || span.ViewLabel != ViewDLPNormalized || span.ByteStart < 0 || span.ByteEnd > len(masked) || span.ByteStart >= span.ByteEnd {
					invalidTargetFound = true
					continue
				}
				rawTargets = append(rawTargets, match)
			}
			for _, match := range rawTargets {
				span := match.Span()
				if spanIsWithinOneFragment(ranges, span.ByteStart, span.ByteEnd) && spanHoldsRule(ctx, sc, masked, span.ByteStart, span.ByteEnd, match.PatternName) {
					if maskFragmentOccurrence(masked, span.ByteStart, span.ByteEnd) {
						remasked = true
					} else {
						// A rule that matches the replacement bytes cannot make
						// progress. Report rather than loop forever or drop it.
						matches = append(matches, DLPMatch{PatternName: match.PatternName})
						crossed = true
					}
					continue
				}
				if spanIsWithinOneFragment(ranges, span.ByteStart, span.ByteEnd) {
					// The span claims one request but its bytes do not match
					// the rule there: the scanner rewrote text before recording
					// positions. The location is unknown, so report the rule.
					matches = append(matches, DLPMatch{PatternName: match.PatternName})
					crossed = true
					continue
				}
				matches = appendCrossFragmentMatch(matches, match, ranges, len(buf))
				crossed = true
			}
			if len(rawTargets) == 0 && invalidTargetFound {
				matches = append(matches, DLPMatch{PatternName: patternName})
				crossed = true
			}
			if crossed || len(rawTargets) == 0 || !remasked {
				break
			}
		}
	}
	if len(matches) == 0 {
		return nil
	}
	return matches
}

func normalizeFragmentForDLP(payload []byte) ([]byte, bool) {
	current := string(payload)
	// ForDLP has two stages that can expose input to a later stage: NFKC and
	// the trailing NFD used to remove combining marks. Two changing passes plus
	// one equality check therefore cover the current pipeline. A future change
	// that needs more passes fails closed instead of reviving coordinate drift.
	for range maxFragmentDLPNormalizationPasses {
		next := normalize.ForDLP(current)
		if next == current {
			return []byte(next), true
		}
		current = next
	}
	return nil, false
}

func maskFragmentOccurrence(buf []byte, start, end int) bool {
	changed := false
	for i := start; i < end; i++ {
		if buf[i] != ' ' {
			buf[i] = ' '
			changed = true
		}
	}
	return changed
}

type fragmentOccurrence struct {
	start int
	end   int
}

// imageSplicedFragmentMatches attributes joined-window findings after image
// excision has rewritten the text. Excision only removes byte ranges and
// appends decoded image bytes after the surrounding text, so a position in the
// surrounding text maps back to the original exactly. For each rule, a match
// that maps inside one fragment is blanked in place and the window rescanned,
// so a whole copy cannot hide a split copy. A match in the decoded image bytes,
// or one without a raw position, has no original location and is reported.
func imageSplicedFragmentMatches(ctx context.Context, sc *Scanner, excised, decoded string, removed []textByteSpan, ranges []fragmentRange, joined []TextDLPMatch) []DLPMatch {
	// Scanner spans are in DLP-normalized coordinates. If normalizing the
	// surrounding text would move bytes, positions cannot be trusted, so
	// every joined rule is reported without attribution.
	if normalized, stable := normalizeFragmentForDLP([]byte(excised)); !stable || string(normalized) != excised {
		return unattributedFragmentMatches(joined)
	}
	window := excised
	if len(decoded) > 0 {
		window = excised + "\n" + decoded
	}
	toOriginal := func(pos int, isEnd bool) int {
		shift := 0
		for _, gap := range removed {
			at := pos + shift
			if gap.start < at || (!isEnd && gap.start == at) {
				shift += gap.end - gap.start
				continue
			}
			break
		}
		return pos + shift
	}
	var matches []DLPMatch
	reported := make(map[string]struct{})
	budget := maxImageSpliceRescansTotal
	for _, first := range joined {
		name := first.PatternName
		if _, ok := reported[name]; ok {
			continue
		}
		reported[name] = struct{}{}
		masked := []byte(window)
		for attempt := 0; ; attempt++ {
			// Each single-request copy costs a full rescan. Bound the work and
			// report the rule rather than loop on attacker-supplied copies.
			if attempt == maxImageSpliceRescans || budget == 0 {
				matches = append(matches, DLPMatch{PatternName: name})
				break
			}
			budget--
			var target *TextDLPMatch
			for _, m := range sc.ScanTextForDLPQuiet(ctx, string(masked)).Matches {
				if m.PatternName == name {
					target = &m
					break
				}
			}
			if target == nil {
				// The joined scan found this rule. If the first rescan does
				// not, or the scan was cut short, keep the finding.
				if attempt == 0 || ctx.Err() != nil {
					matches = append(matches, DLPMatch{PatternName: name})
				}
				break
			}
			span := target.Span()
			if target.Encoded != "" || span.ViewLabel != ViewDLPNormalized || span.ByteStart < 0 || span.ByteStart >= span.ByteEnd || span.ByteEnd > len(excised) {
				matches = append(matches, DLPMatch{PatternName: name})
				break
			}
			origStart, origEnd := toOriginal(span.ByteStart, false), toOriginal(span.ByteEnd, true)
			if !spanHoldsRule(ctx, sc, masked, span.ByteStart, span.ByteEnd, name) {
				// The span does not hold the rule where it points, so its
				// position cannot name contributors. Report it unattributed.
				matches = append(matches, DLPMatch{PatternName: name})
				break
			}
			if !spanIsWithinOneFragment(ranges, origStart, origEnd) {
				matches = append(matches, DLPMatch{
					PatternName:  name,
					Contributors: contributorsForSpan(ranges, origStart, origEnd),
				})
				break
			}
			// Blank only the first byte: the match no longer starts there, but
			// an overlapping occurrence that crosses a boundary keeps its bytes.
			if !maskFragmentOccurrence(masked, span.ByteStart, span.ByteStart+1) {
				matches = append(matches, DLPMatch{PatternName: name})
				break
			}
		}
	}
	return matches
}

// maxImageSpliceRescans bounds per-rule rescans on the image-excision path,
// and maxImageSpliceRescansTotal bounds them across all rules in one window.
// Reaching either reports the rule instead of scanning further.
const (
	maxImageSpliceRescans      = 8
	maxImageSpliceRescansTotal = 24
)

// unattributedFragmentMatches reports each distinct joined rule once with no
// contributor attribution.
func unattributedFragmentMatches(joined []TextDLPMatch) []DLPMatch {
	var matches []DLPMatch
	seen := make(map[string]struct{})
	for _, m := range joined {
		if _, ok := seen[m.PatternName]; ok {
			continue
		}
		seen[m.PatternName] = struct{}{}
		matches = append(matches, DLPMatch{PatternName: m.PatternName})
	}
	return matches
}

func completeFragmentOccurrences(ctx context.Context, sc *Scanner, ranges []fragmentRange) map[string][]fragmentOccurrence {
	complete := make(map[string][]fragmentOccurrence)
	for _, r := range ranges {
		fragmentResult := sc.ScanTextForDLPQuiet(ctx, string(r.normalized))
		for _, match := range fragmentResult.Matches {
			span := match.Span()
			if match.Encoded != "" || span.ViewLabel != ViewDLPNormalized || span.ByteStart < 0 || span.ByteEnd > len(r.normalized) || span.ByteStart >= span.ByteEnd {
				continue
			}
			complete[match.PatternName] = append(complete[match.PatternName], fragmentOccurrence{
				start: r.start + span.ByteStart,
				end:   r.start + span.ByteEnd,
			})
		}
	}
	return complete
}

func appendCrossFragmentMatch(matches []DLPMatch, match TextDLPMatch, ranges []fragmentRange, bufferLen int) []DLPMatch {
	span := match.Span()
	if span.ViewLabel != ViewDLPNormalized || span.ByteStart < 0 || span.ByteEnd > bufferLen || span.ByteStart >= span.ByteEnd {
		// The scanner found a real DLP match but did not expose a raw-view
		// coordinate that could prove it was wholly inspected in one request.
		// Do not turn missing provenance into an allow decision.
		return append(matches, DLPMatch{PatternName: match.PatternName})
	}
	if spanIsWithinOneFragment(ranges, span.ByteStart, span.ByteEnd) {
		return matches
	}
	return append(matches, DLPMatch{
		PatternName:  match.PatternName,
		Contributors: contributorsForSpan(ranges, span.ByteStart, span.ByteEnd),
	})
}

// spanHoldsRule reports whether the bytes at a scanner span match the rule by
// themselves. The scanner rewrites text before recording positions (image
// excision, documentation-placeholder redaction, normalization), so a span can
// point at the wrong bytes. Only a span that still matches where it points may
// be treated as one request's own copy; anything else is reported.
func spanHoldsRule(ctx context.Context, sc *Scanner, buf []byte, start, end int, rule string) bool {
	if start < 0 || end > len(buf) || start >= end {
		return false
	}
	// The rule must match the whole candidate, not a shorter piece inside it,
	// or a partial match could stand in for a credential that crosses requests.
	candidateLen := end - start
	for _, m := range sc.ScanTextForDLPQuiet(ctx, string(buf[start:end])).Matches {
		span := m.Span()
		if m.PatternName == rule && span.ViewLabel == ViewDLPNormalized && span.ByteStart == 0 && span.ByteEnd == candidateLen {
			return true
		}
	}
	return false
}

func spanIsWithinOneFragment(ranges []fragmentRange, start, end int) bool {
	for _, r := range ranges {
		if start >= r.start && end <= r.end {
			return true
		}
	}
	return false
}

type fragmentRange struct {
	start      int
	end        int
	normalized []byte
	fragment   fragment
}

func contributorsForSpan(ranges []fragmentRange, start, end int) [][]byte {
	contributors := make([][]byte, 0, len(ranges))
	seen := make(map[string]struct{})
	for _, r := range ranges {
		if r.start >= r.end {
			// This fragment normalized to no bytes, so it cannot contribute to
			// a match or make real contributors look unidentified.
			continue
		}
		if start >= r.end || end <= r.start {
			continue
		}
		if len(r.fragment.sourceRequestID) == 0 {
			// A partial list would look complete to a consumer. Omit the field
			// unless every byte-contributing fragment has a retained identity.
			return nil
		}
		id := string(r.fragment.sourceRequestID)
		if _, duplicate := seen[id]; duplicate {
			continue
		}
		seen[id] = struct{}{}
		contributors = append(contributors, append([]byte(nil), r.fragment.sourceRequestID...))
	}
	return contributors
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
	// A reload that LOWERS the cap has to bring grouped streams within it now.
	// The per-stream loops above cannot: a JSON bucket group is over budget as a
	// SUM, and nothing would notice until that identity's next append, so a
	// tightened memory limit would not take effect on the traffic already held.
	fb.enforceAllOwnerBudgetsLocked()
	fb.lastCleanup = now
}

// enforceAllOwnerBudgetsLocked brings every budget group within the current cap.
// Used on reload, where the cap can drop underneath streams that are already
// retained.
func (fb *FragmentBuffer) enforceAllOwnerBudgetsLocked() {
	for _, state := range fb.owners {
		for _, members := range state.budgets {
			if len(members) <= 1 {
				continue
			}
			for fb.groupBytesLocked(members) > fb.maxBytes {
				if !fb.evictOldestOwnerFragmentLocked(members) {
					break
				}
			}
		}
	}
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
func (fb *FragmentBuffer) Delete(key identitykey.CEEStream) {
	if fb == nil {
		return
	}
	fb.mu.Lock()
	defer fb.mu.Unlock()
	fb.deleteStreamLocked(key.Key())
}

// DeletePrefix clears every ordinary and position-aware stream whose key
// begins with prefix. It supports bounded families of hashed child streams
// (for example, JSON body fields) when the parent CEE session is reset.
//
// Cost: it scans every stream key under the write lock, so it is O(total
// sessions), not O(matched streams). That is acceptable because the only caller
// is the operator reset/terminate admin path, a rare deliberate action; it must
// not be called on the per-request hot path. There is no prefix index to bound
// the scan; see BenchmarkFragmentBufferDeletePrefix for the measured cost.
func (fb *FragmentBuffer) DeletePrefix(prefix identitykey.CEEStream) {
	if fb == nil {
		return
	}
	fb.mu.Lock()
	defer fb.mu.Unlock()
	for key := range fb.sessions {
		if strings.HasPrefix(key, prefix.Key()) {
			fb.deleteStreamLocked(key)
		}
	}
	for key := range fb.pathSessions {
		if strings.HasPrefix(key, prefix.Key()) {
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
	fb.cleanMemo.mu.Lock()
	clear(fb.cleanMemo.entries)
	fb.cleanMemo.bytes = 0
	fb.cleanMemo.mu.Unlock()
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

// deleteDataStreamLocked removes only the data stream for key, leaving any path
// stream that still holds evidence under the same key untouched.
func (fb *FragmentBuffer) deleteDataStreamLocked(key string) {
	if _, ok := fb.sessions[key]; !ok {
		return
	}
	delete(fb.sessions, key)
	fb.untrackStreamLocked(fragmentStreamID(fragmentStreamKindData, key))
}

// deletePathStreamLocked is deleteDataStreamLocked for the path half.
func (fb *FragmentBuffer) deletePathStreamLocked(key string) {
	if _, ok := fb.pathSessions[key]; !ok {
		return
	}
	delete(fb.pathSessions, key)
	fb.untrackStreamLocked(fragmentStreamID(fragmentStreamKindPath, key))
}

// deleteStreamLocked removes BOTH stream kinds for a key. That is right for the
// operator reset and prefix delete, which mean "drop this identity's evidence",
// and wrong for window expiry, which is per stream.
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

		// Remove empty sessions entirely. Kind-scoped on purpose: a data stream
		// and a path stream can share a key, and deleting both here would
		// discard live path evidence because the data half aged out.
		if len(sb.fragments) == 0 {
			fb.deleteDataStreamLocked(key)
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
			fb.deletePathStreamLocked(key)
		}
	}
}

// A memo entry certifies only a warning-free full scan of identical normalized
// text within one buffer, stream, continuity and immutable scanner generation.
type fragmentCleanKey struct {
	scanner            *Scanner
	stream, continuity string
}
type fragmentCleanMemo struct {
	mu                         sync.Mutex
	entries                    map[fragmentCleanKey]string
	bytes, limit, hits, misses int
}

func (m *fragmentCleanMemo) lookup(key fragmentCleanKey, text string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if prior, ok := m.entries[key]; ok && prior == text {
		m.hits++
		return true
	}
	m.misses++
	return false
}

func (m *fragmentCleanMemo) store(key fragmentCleanKey, text string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(text) > m.limit || m.limit <= 0 {
		return
	}
	if m.entries == nil {
		m.entries = make(map[fragmentCleanKey]string)
	}
	if prior, ok := m.entries[key]; ok {
		m.bytes -= len(prior) + len(key.stream) + len(key.continuity)
		delete(m.entries, key)
	}
	cost := len(text) + len(key.stream) + len(key.continuity)
	if cost > m.limit {
		return
	}
	if m.bytes+cost > m.limit {
		clear(m.entries)
		m.bytes = 0
	}
	m.entries[key] = text
	m.bytes += cost
}

func (fb *FragmentBuffer) scanBatchWithCleanMemo(ctx context.Context, sc *Scanner, fragments []fragment, stream string) []DLPMatch {
	fb.mu.Lock()
	limit := 4 * fb.maxBytes
	fb.mu.Unlock()
	fb.cleanMemo.mu.Lock()
	fb.cleanMemo.limit = limit
	if fb.cleanMemo.bytes > limit {
		clear(fb.cleanMemo.entries)
		fb.cleanMemo.bytes = 0
	}
	fb.cleanMemo.mu.Unlock()
	var matches []DLPMatch
	for _, group := range fragmentContinuityGroups(fragments) {
		matches = append(matches, scanOneFragmentContinuityMemo(ctx, sc, group, &fb.cleanMemo, stream)...)
	}
	return matches
}
