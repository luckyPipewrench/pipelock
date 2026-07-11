// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// GenesisHash is the chain_prev_hash of the first receipt in a session.
const GenesisHash = "genesis"

// ErrUnexpectedRecorderEntryType is returned when a recorder evidence file
// contains an entry whose Type is outside the known recorder taxonomy. Both
// extraction modes fail closed on it rather than silently skipping it, so an
// unknown record type cannot ride inside a file that otherwise verifies.
var ErrUnexpectedRecorderEntryType = errors.New("unexpected recorder entry type")

// TranscriptRoot summarizes a receipt chain for a session.
type TranscriptRoot struct {
	SessionID    string    `json:"session_id"`
	FinalSeq     uint64    `json:"final_seq"`
	RootHash     string    `json:"root_hash"`
	ReceiptCount uint64    `json:"receipt_count"`
	StartTime    time.Time `json:"start_time"`
	EndTime      time.Time `json:"end_time"`
}

// ReceiptHash computes the SHA-256 hex digest of a receipt's canonical JSON.
func ReceiptHash(r Receipt) (string, error) {
	data, err := Marshal(r)
	if err != nil {
		return "", fmt.Errorf("marshal receipt: %w", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// ChainResult describes the outcome of chain verification.
type ChainResult struct {
	Valid bool
	// IntegrityVerified means receipt signatures, trusted signer keys, sequence
	// numbers, and hash links verified without applying session lifecycle
	// rules. It can be true when Valid is false for a lifecycle-only failure.
	IntegrityVerified bool
	ReceiptCount      uint64
	FinalSeq          uint64
	RootHash          string
	StartTime         time.Time
	EndTime           time.Time
	Error             string // empty if valid
	FailureKind       ChainFailureKind
	BrokenAtSeq       uint64 // set when chain breaks
	BrokenAtIndex     int    // zero-based receipt index where chain verification failed

	// SignerKeys is the ordered, de-duplicated set of signer public keys
	// (hex) observed across the chain's segments, in segment order. A
	// single-key chain has one entry. A rotated chain has one entry per
	// segment. Always populated, even on failure, so the operator can see
	// which keys appeared.
	SignerKeys []string
	// Segments describes each contiguous single-key run in the chain.
	Segments []ChainSegment
	// UntrustedSignerKey is set (and Valid=false) when a segment is signed by
	// a key that is not in the supplied trusted set (trust-on-first-use mode:
	// not equal to the genesis key). It names the offending key so the
	// operator can decide whether it is a legitimate rotation to add to the
	// trusted set or an attacker-introduced key to investigate.
	UntrustedSignerKey string
}

// ChainFailureKind classifies why chain verification failed.
type ChainFailureKind string

const (
	ChainFailureIntegrity     ChainFailureKind = "integrity"
	ChainFailureTrust         ChainFailureKind = "trust"
	ChainFailureLifecycle     ChainFailureKind = "lifecycle"
	ChainFailureLifecycleOpen ChainFailureKind = "lifecycle_missing_open"
)

// ChainSegment summarizes one single-key run within a (possibly rotated) chain.
type ChainSegment struct {
	SignerKey string
	FirstSeq  uint64
	FinalSeq  uint64
	Count     uint64
	// Boundary is true when this segment began at a KeyTransition (i.e. it is
	// not the genesis segment). The genesis segment has Boundary=false.
	Boundary bool
}

// VerifyChain verifies hash-chain integrity of a sequence of receipts, with
// support for signing-key rotation boundaries. expectedKeyHex is the single
// trusted signer key; pass "" for trust-on-first-use (the genesis segment's
// key becomes the sole trusted key). It is a thin wrapper over
// VerifyChainTrusted; see that function for the full trust model.
func VerifyChain(receipts []Receipt, expectedKeyHex string) ChainResult {
	if expectedKeyHex == "" {
		return VerifyChainTrusted(receipts, nil)
	}
	return VerifyChainTrusted(receipts, []string{expectedKeyHex})
}

// VerifyChainIntegrity verifies signatures, trusted signer keys, sequence
// numbers, and hash links while ignoring session-control lifecycle rules.
func VerifyChainIntegrity(receipts []Receipt, expectedKeyHex string) ChainResult {
	if expectedKeyHex == "" {
		return VerifyChainIntegrityTrusted(receipts, nil)
	}
	return VerifyChainIntegrityTrusted(receipts, []string{expectedKeyHex})
}

// VerifyChainTrusted verifies hash-chain integrity across signing-key rotation
// boundaries against an explicit set of trusted signer keys (hex).
//
// Receipts must be in chain order. Within a segment: signatures verify under
// that segment's key, chain_seq increments by 1 from the segment's baseline,
// and chain_prev_hash matches the previous receipt's hash.
//
// TRUST MODEL (the crux). A signing-key rotation opens a new chain segment
// whose genesis receipt carries a KeyTransition marker (prior key + seq + tail
// hash) and whose chain_prev_hash equals the prior tail hash. The marker is
// signed by the NEW key, so it proves continuity (the boundary references the
// real prior tail and is internally consistent) but it does NOT prove the
// holder of the OLD key authorized the rotation - an attacker with write access
// to the evidence file can read the real prior tail and fabricate a consistent
// marker, then sign a new segment with their own key. Therefore the marker is
// continuity/audit metadata, NOT trust delegation. Trust comes ONLY from the
// caller-supplied trusted key set:
//
//   - trustedKeys non-empty: EVERY segment must be signed by a key in the set.
//     A segment signed by any other key fails (UntrustedSignerKey is set),
//     regardless of how well-formed its KeyTransition marker is. This is how a
//     forged attacker-key segment is rejected: the attacker key is not in the
//     operator's trusted set.
//   - trustedKeys empty (trust-on-first-use): the genesis segment's key becomes
//     the sole trusted key. Any rotation to a DIFFERENT key fails with
//     UntrustedSignerKey set - the operator must re-run with the new key in the
//     trusted set to confirm it is theirs. A single-key chain still verifies.
//
// Structural rules (independent of trust), all fail-closed:
//
//   - The genesis (first) receipt must have chain_prev_hash == genesis with no
//     KeyTransition marker. A rotated segment cannot be verified as a complete
//     chain in isolation because its embedded marker is not the actual prior tail.
//   - A new segment mid-chain is introduced ONLY by a seq-0 receipt carrying a
//     marker whose PriorChainHash equals both this receipt's chain_prev_hash and
//     the actual prior tail hash, whose PriorSignerKey equals the prior
//     segment's key, and whose PriorChainSeq equals the prior segment's final
//     seq. A tampered prior tail breaks this (hash mismatch).
//   - A KeyTransition marker on a non-seq-0 receipt, or an ordinary seq-0
//     receipt mid-chain (no marker, prev_hash != genesis), is rejected. This
//     preserves the genesis check for ordinary receipts (no weakening).
func VerifyChainTrusted(receipts []Receipt, trustedKeys []string) ChainResult {
	res := verifyChainTrusted(receipts, trustedKeys, false)
	if res.FailureKind != ChainFailureLifecycleOpen {
		return res
	}
	integrity := verifyChainTrusted(receipts, trustedKeys, true)
	if !integrity.Valid {
		return integrity
	}
	res.IntegrityVerified = true
	res.ReceiptCount = integrity.ReceiptCount
	res.FinalSeq = integrity.FinalSeq
	res.RootHash = integrity.RootHash
	res.StartTime = integrity.StartTime
	res.EndTime = integrity.EndTime
	res.SignerKeys = integrity.SignerKeys
	res.Segments = integrity.Segments
	return res
}

// VerifyChainIntegrityTrusted is VerifyChainIntegrity with an explicit trusted
// signer key set.
func VerifyChainIntegrityTrusted(receipts []Receipt, trustedKeys []string) ChainResult {
	return verifyChainTrusted(receipts, trustedKeys, true)
}

func verifyChainTrusted(receipts []Receipt, trustedKeys []string, integrityOnly bool) ChainResult {
	if len(receipts) == 0 {
		return ChainResult{Valid: true, IntegrityVerified: true}
	}

	normalizedKeys, err := normalizeTrustedKeys(trustedKeys)
	if err != nil {
		return ChainResult{
			Valid:         false,
			BrokenAtSeq:   receipts[0].ActionRecord.ChainSeq,
			BrokenAtIndex: 0,
			Error:         fmt.Sprintf("seq %d: trusted key set: %v", receipts[0].ActionRecord.ChainSeq, err),
			FailureKind:   ChainFailureTrust,
		}
	}

	trusted := make(map[string]struct{}, len(normalizedKeys))
	for _, k := range normalizedKeys {
		trusted[k] = struct{}{}
	}
	v := &chainVerifier{
		trusted:       trusted,
		runNonces:     make(map[string]string),
		closedRuns:    make(map[string]bool),
		integrityOnly: integrityOnly,
	}
	return v.run(receipts)
}

func normalizeTrustedKeys(trustedKeys []string) ([]string, error) {
	if len(trustedKeys) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(trustedKeys))
	for _, key := range trustedKeys {
		key = strings.TrimSpace(key)
		if key == "" {
			return nil, fmt.Errorf("trusted signer key cannot be empty")
		}
		out = append(out, key)
	}
	return out, nil
}

// chainVerifier carries the walking state for VerifyChain.
type chainVerifier struct {
	// trusted is the set of trusted signer keys. Empty means trust-on-first-
	// use: the genesis key is adopted as the sole trusted key.
	trusted map[string]struct{}

	curKey     string // expected signer key for the current segment
	segBaseSeq uint64 // chain_seq of the current segment's first receipt
	prevHash   string // expected chain_prev_hash for the next receipt

	signerKeys []string
	segments   []ChainSegment
	curSeg     *ChainSegment
	index      int
	runNonces  map[string]string
	closedRuns map[string]bool
	activeRun  string
	activeOpen string

	integrityOnly bool
}

func (v *chainVerifier) run(receipts []Receipt) ChainResult {
	for i := range receipts {
		v.index = i
		r := receipts[i]
		marker := r.ActionRecord.KeyTransition

		if i == 0 {
			if res, ok := v.startFirstSegment(r); !ok {
				return res
			}
		} else if marker != nil {
			if res, ok := v.startRotatedSegment(r, marker); !ok {
				return res
			}
		} else if res, ok := v.checkContinuation(r); !ok {
			return res
		}

		if res, ok := v.verifyReceiptIntegrity(r, uint64(i)); !ok {
			return res
		}
		if !v.integrityOnly {
			if res, ok := v.validateSessionControl(r); !ok {
				return res
			}
		}
		if res, ok := v.advanceReceiptHash(r); !ok {
			return res
		}
	}

	v.closeSegment()
	first := receipts[0].ActionRecord
	last := receipts[len(receipts)-1].ActionRecord
	return ChainResult{
		Valid:             true,
		IntegrityVerified: true,
		ReceiptCount:      uint64(len(receipts)),
		FinalSeq:          last.ChainSeq,
		RootHash:          v.prevHash,
		StartTime:         first.Timestamp,
		EndTime:           last.Timestamp,
		SignerKeys:        v.signerKeys,
		Segments:          v.segments,
	}
}

// startFirstSegment establishes the anchor and key for the genesis segment.
// Returns ok=false with a failing result on violation.
func (v *chainVerifier) startFirstSegment(r Receipt) (ChainResult, bool) {
	marker := r.ActionRecord.KeyTransition
	// Trust-on-first-use: when no trusted set was supplied, adopt the first
	// receipt's signer_key as the sole trusted key. Otherwise the first
	// segment's key must already be in the trusted set.
	if len(v.trusted) == 0 {
		v.trusted = map[string]struct{}{r.SignerKey: {}}
	}
	if !v.keyTrusted(r.SignerKey) {
		return v.untrusted(r), false
	}
	v.curKey = r.SignerKey

	switch {
	case marker != nil:
		// A KeyTransition marker is continuity metadata for a boundary to a
		// prior tail that must be present in the chain being verified. Accepting
		// a marker on the first receipt would allow deletion/truncation of the
		// prior segment while still returning CHAIN VALID for the suffix.
		return v.brokenAt(r, "chain starts at a key_transition segment without the prior segment"), false
	case strings.HasPrefix(r.ActionRecord.ChainPrevHash, genesisSessionOpenPrefix):
		if res, ok := v.validateBoundGenesisOpen(r); !ok {
			return res, false
		}
		v.prevHash = r.ActionRecord.ChainPrevHash
		v.beginSegment(r, false)
	default:
		// Ordinary genesis: prev_hash must be the genesis sentinel.
		if r.ActionRecord.ChainPrevHash != GenesisHash {
			return v.brokenAt(r, "genesis receipt chain_prev_hash must be genesis or a bound session_open g1 hash"), false
		}
		if !v.integrityOnly && sessionOpen(r.ActionRecord.SessionControl) != nil {
			return v.brokenAt(r, "session_open on legacy genesis must use bound g1 chain_prev_hash"), false
		}
		v.prevHash = GenesisHash
		v.beginSegment(r, false)
	}
	v.segBaseSeq = r.ActionRecord.ChainSeq
	return ChainResult{}, true
}

// startRotatedSegment validates a KeyTransition boundary mid-chain and switches
// the expected key to the new segment.
func (v *chainVerifier) startRotatedSegment(r Receipt, marker *KeyTransition) (ChainResult, bool) {
	// Markers are only valid at a segment genesis (seq 0).
	if r.ActionRecord.ChainSeq != 0 {
		return v.brokenAt(r, "key_transition marker on a non-genesis receipt (seq != 0)"), false
	}
	// The boundary must reference the actual prior tail: prev_hash, the
	// marker's prior hash, and the real prior-tail hash must all agree, and
	// the marker must name the prior segment's key and final seq. v.prevHash
	// holds the prior tail's hash (set by verifyReceipt on the prior receipt).
	if marker.PriorChainHash != v.prevHash {
		return v.brokenAt(r, "key_transition prior_chain_hash does not match actual prior tail hash"), false
	}
	if r.ActionRecord.ChainPrevHash != v.prevHash {
		return v.brokenAt(r, "segment-genesis chain_prev_hash does not match prior tail hash"), false
	}
	if marker.PriorSignerKey != v.curKey {
		return v.brokenAt(r, "key_transition prior_signer_key does not match prior segment key"), false
	}
	if v.curSeg != nil && marker.PriorChainSeq != v.curSeg.FinalSeq {
		return v.brokenAt(r, "key_transition prior_chain_seq does not match prior segment final seq"), false
	}
	if open := sessionOpen(r.ActionRecord.SessionControl); !v.integrityOnly && open != nil {
		if res, ok := v.validateRestartOpen(r, open, marker.PriorChainHash, marker.PriorChainSeq); !ok {
			return res, false
		}
	}
	// The boundary is structurally valid, but trust is NOT delegated by the
	// marker (it is signed by the new key, which an attacker with write access
	// could mint). The new segment's key must be in the operator's trusted set.
	if !v.keyTrusted(r.SignerKey) {
		v.beginSegment(r, true) // record the offending key in SignerKeys/Segments
		return v.untrusted(r), false
	}
	v.closeSegment()
	v.curKey = r.SignerKey
	v.segBaseSeq = 0
	v.beginSegment(r, true)
	return ChainResult{}, true
}

func (v *chainVerifier) keyTrusted(key string) bool {
	_, ok := v.trusted[key]
	return ok
}

// untrusted records the offending key and returns a failing result that names
// it, so the operator can decide whether it is a legitimate rotation (re-run
// with the key added to the trusted set) or an attacker key.
func (v *chainVerifier) untrusted(r Receipt) ChainResult {
	res := v.brokenAtKind(r, fmt.Sprintf("signer key %s is not in the trusted set", r.SignerKey), ChainFailureTrust)
	res.UntrustedSignerKey = r.SignerKey
	res.SignerKeys = v.signerKeys
	return res
}

// checkContinuation enforces seq + prev_hash continuity within a segment for a
// non-boundary receipt.
func (v *chainVerifier) checkContinuation(r Receipt) (ChainResult, bool) {
	// An ordinary seq-0 receipt mid-chain (no marker) is a fork/duplicate, not
	// a valid boundary - reject. This also preserves the genesis check: only
	// the first receipt may legitimately be seq 0 without a marker.
	if r.ActionRecord.ChainSeq == 0 {
		return v.brokenAt(r, "unexpected seq 0 without a key_transition boundary"), false
	}
	if open := sessionOpen(r.ActionRecord.SessionControl); !v.integrityOnly && open != nil {
		if v.curSeg == nil {
			return v.brokenAt(r, "session_open continuation has no prior segment"), false
		}
		if res, ok := v.validateRestartOpen(r, open, v.prevHash, v.curSeg.FinalSeq); !ok {
			return res, false
		}
	}
	return ChainResult{}, true
}

func (v *chainVerifier) validateBoundGenesisOpen(r Receipt) (ChainResult, bool) {
	open := sessionOpen(r.ActionRecord.SessionControl)
	if open == nil {
		return v.brokenAt(r, "g1 chain_prev_hash requires SessionControl.Open"), false
	}
	if r.ActionRecord.ChainSeq != 0 {
		return v.brokenAt(r, "bound session_open genesis must be chain_seq 0"), false
	}
	computed := ComputeSessionOpenGenesis(*open)
	if r.ActionRecord.ChainPrevHash != computed {
		return v.brokenAt(r, "session_open genesis hash mismatch"), false
	}
	if open.GenesisHash != computed {
		return v.brokenAt(r, "session_open genesis_hash mismatch"), false
	}
	if open.ChainOpenSeq != r.ActionRecord.ChainSeq {
		return v.brokenAt(r, "session_open chain_open_seq does not match receipt chain_seq"), false
	}
	if open.PriorChainHead != "" || open.PriorChainSeq != 0 {
		return v.brokenAt(r, "bound genesis session_open must not carry prior chain tail"), false
	}
	return ChainResult{}, true
}

func (v *chainVerifier) validateRestartOpen(r Receipt, open *SessionOpen, priorHead string, priorSeq uint64) (ChainResult, bool) {
	if strings.HasPrefix(r.ActionRecord.ChainPrevHash, genesisSessionOpenPrefix) {
		return v.brokenAt(r, "restart session_open must not use g1 chain_prev_hash"), false
	}
	if open.GenesisHash != "" {
		return v.brokenAt(r, "restart session_open must not carry genesis_hash"), false
	}
	if open.ChainOpenSeq != r.ActionRecord.ChainSeq {
		return v.brokenAt(r, "session_open chain_open_seq does not match receipt chain_seq"), false
	}
	if open.PriorChainHead != priorHead {
		return v.brokenAt(r, "session_open prior_chain_head does not match prior tail hash"), false
	}
	if open.PriorChainSeq != priorSeq {
		return v.brokenAt(r, "session_open prior_chain_seq does not match prior tail seq"), false
	}
	return ChainResult{}, true
}

func (v *chainVerifier) validateSessionControl(r Receipt) (ChainResult, bool) {
	ctrl := r.ActionRecord.SessionControl
	open := sessionOpen(ctrl)
	heartbeat := sessionHeartbeat(ctrl)
	closeRecord := sessionClose(ctrl)
	if ctrl != nil {
		payloads := 0
		if ctrl.Open != nil {
			payloads++
		}
		if ctrl.Heartbeat != nil {
			payloads++
		}
		if ctrl.Close != nil {
			payloads++
		}
		if payloads != 1 {
			return v.brokenAtKind(r, "session_control must carry exactly one payload", ChainFailureLifecycle), false
		}
		switch ctrl.Kind {
		case SessionControlOpen:
			if open == nil {
				return v.brokenAtKind(r, "session_open kind missing open payload", ChainFailureLifecycle), false
			}
		case SessionControlHeartbeat:
			if heartbeat == nil {
				return v.brokenAtKind(r, "heartbeat kind missing heartbeat payload", ChainFailureLifecycle), false
			}
		case SessionControlClose:
			if closeRecord == nil {
				return v.brokenAtKind(r, "session_close kind missing close payload", ChainFailureLifecycle), false
			}
		default:
			return v.brokenAtKind(r, "unknown session_control kind", ChainFailureLifecycle), false
		}
	}
	if r.ActionRecord.RunNonce == "" {
		if ctrl != nil {
			return v.brokenAtKind(r, "session_control receipt missing run_nonce", ChainFailureLifecycle), false
		}
		return ChainResult{}, true
	}
	if open == nil {
		openNonce, ok := v.runNonces[r.ActionRecord.RunNonce]
		if !ok {
			return v.brokenAtKind(r, "run_nonce first receipt is not a matching session_open", ChainFailureLifecycleOpen), false
		}
		if v.closedRuns[r.ActionRecord.RunNonce] {
			return v.brokenAtKind(r, "record observed after session_close", ChainFailureLifecycle), false
		}
		if heartbeat != nil {
			if heartbeat.RunNonce != r.ActionRecord.RunNonce {
				return v.brokenAtKind(r, "heartbeat run_nonce does not match receipt run_nonce", ChainFailureLifecycle), false
			}
			if v.activeRun == "" || v.activeOpen == "" {
				return v.brokenAtKind(r, "heartbeat has no active session_open", ChainFailureLifecycle), false
			}
			if heartbeat.RunNonce != v.activeRun {
				return v.brokenAtKind(r, "heartbeat run_nonce does not match active session_open", ChainFailureLifecycle), false
			}
			if heartbeat.OpenNonce != openNonce {
				return v.brokenAtKind(r, "heartbeat open_nonce does not match session_open", ChainFailureLifecycle), false
			}
			if heartbeat.OpenNonce != v.activeOpen {
				return v.brokenAtKind(r, "heartbeat open_nonce does not match active session_open", ChainFailureLifecycle), false
			}
			if heartbeat.ChainHead != v.prevHash {
				return v.brokenAtKind(r, "heartbeat chain_head mismatch", ChainFailureLifecycle), false
			}
			if heartbeat.ChainSeqHead != r.ActionRecord.ChainSeq-1 {
				return v.brokenAtKind(r, "heartbeat chain_seq_head mismatch", ChainFailureLifecycle), false
			}
		}
		if closeRecord != nil {
			if closeRecord.RunNonce != r.ActionRecord.RunNonce {
				return v.brokenAtKind(r, "session_close run_nonce does not match receipt run_nonce", ChainFailureLifecycle), false
			}
			if v.activeRun == "" || v.activeOpen == "" {
				return v.brokenAtKind(r, "session_close has no active session_open", ChainFailureLifecycle), false
			}
			if closeRecord.RunNonce != v.activeRun {
				return v.brokenAtKind(r, "session_close run_nonce does not match active session_open", ChainFailureLifecycle), false
			}
			if closeRecord.OpenNonce != openNonce {
				return v.brokenAtKind(r, "session_close open_nonce does not match session_open", ChainFailureLifecycle), false
			}
			if closeRecord.OpenNonce != v.activeOpen {
				return v.brokenAtKind(r, "session_close open_nonce does not match active session_open", ChainFailureLifecycle), false
			}
			if closeRecord.RootHash != v.prevHash {
				return v.brokenAtKind(r, "session_close root_hash mismatch", ChainFailureLifecycle), false
			}
			if closeRecord.FinalSeq != r.ActionRecord.ChainSeq {
				return v.brokenAtKind(r, "session_close final_seq mismatch", ChainFailureLifecycle), false
			}
			segmentReceiptCount := uint64(1)
			if v.curSeg != nil {
				segmentReceiptCount = v.curSeg.Count + 1
			}
			if closeRecord.ReceiptCount != segmentReceiptCount {
				return v.brokenAtKind(r, "session_close receipt_count mismatch", ChainFailureLifecycle), false
			}
			v.activeRun = ""
			v.activeOpen = ""
			v.closedRuns[r.ActionRecord.RunNonce] = true
		}
		return ChainResult{}, true
	}
	if open.RunNonce != r.ActionRecord.RunNonce {
		return v.brokenAtKind(r, "session_open run_nonce does not match receipt run_nonce", ChainFailureLifecycle), false
	}
	if open.OpenNonce == "" {
		return v.brokenAtKind(r, "session_open open_nonce is empty", ChainFailureLifecycle), false
	}
	if _, exists := v.runNonces[r.ActionRecord.RunNonce]; exists {
		return v.brokenAtKind(r, "duplicate session_open for run_nonce", ChainFailureLifecycle), false
	}
	v.runNonces[r.ActionRecord.RunNonce] = open.OpenNonce
	v.closedRuns[r.ActionRecord.RunNonce] = false
	v.activeRun = open.RunNonce
	v.activeOpen = open.OpenNonce
	return ChainResult{}, true
}

func sessionOpen(ctrl *SessionControl) *SessionOpen {
	if ctrl == nil || ctrl.Kind != SessionControlOpen {
		return nil
	}
	return ctrl.Open
}

func sessionHeartbeat(ctrl *SessionControl) *SessionHeartbeat {
	if ctrl == nil || ctrl.Kind != SessionControlHeartbeat {
		return nil
	}
	return ctrl.Heartbeat
}

func sessionClose(ctrl *SessionControl) *SessionClose {
	if ctrl == nil || ctrl.Kind != SessionControlClose {
		return nil
	}
	return ctrl.Close
}

func (v *chainVerifier) verifyReceiptIntegrity(r Receipt, index uint64) (ChainResult, bool) {
	if err := VerifyWithKey(r, v.curKey); err != nil {
		return v.brokenAt(r, fmt.Sprintf("signature: %v", err)), false
	}

	expectedSeq := v.segBaseSeq + (index - v.curSegStartIndex())
	if r.ActionRecord.ChainSeq != expectedSeq {
		return v.brokenAt(r, fmt.Sprintf("seq gap: expected %d, got %d", expectedSeq, r.ActionRecord.ChainSeq)), false
	}

	if r.ActionRecord.ChainPrevHash != v.prevHash {
		return v.brokenAt(r, "chain_prev_hash mismatch"), false
	}
	return ChainResult{}, true
}

func (v *chainVerifier) advanceReceiptHash(r Receipt) (ChainResult, bool) {
	hash, err := ReceiptHash(r)
	if err != nil {
		return v.brokenAt(r, fmt.Sprintf("hash computation: %v", err)), false
	}
	v.prevHash = hash
	if v.curSeg != nil {
		v.curSeg.FinalSeq = r.ActionRecord.ChainSeq
		v.curSeg.Count++
	}
	return ChainResult{}, true
}

// curSegStartIndex returns the slice index at which the current segment began,
// derived from segments already closed plus the count of the open segment.
func (v *chainVerifier) curSegStartIndex() uint64 {
	var n uint64
	for _, s := range v.segments {
		n += s.Count
	}
	return n
}

func (v *chainVerifier) beginSegment(r Receipt, boundary bool) {
	v.curSeg = &ChainSegment{
		SignerKey: r.SignerKey,
		FirstSeq:  r.ActionRecord.ChainSeq,
		FinalSeq:  r.ActionRecord.ChainSeq,
		Boundary:  boundary,
	}
	v.appendSignerKey(r.SignerKey)
}

func (v *chainVerifier) closeSegment() {
	if v.curSeg != nil {
		v.segments = append(v.segments, *v.curSeg)
		v.curSeg = nil
	}
}

func (v *chainVerifier) appendSignerKey(key string) {
	for _, k := range v.signerKeys {
		if k == key {
			return
		}
	}
	v.signerKeys = append(v.signerKeys, key)
}

func (v *chainVerifier) brokenAt(r Receipt, msg string) ChainResult {
	return v.brokenAtKind(r, msg, ChainFailureIntegrity)
}

func (v *chainVerifier) brokenAtKind(r Receipt, msg string, kind ChainFailureKind) ChainResult {
	return ChainResult{
		Valid:         false,
		BrokenAtSeq:   r.ActionRecord.ChainSeq,
		BrokenAtIndex: v.index,
		Error:         fmt.Sprintf("seq %d: %s", r.ActionRecord.ChainSeq, msg),
		FailureKind:   kind,
		SignerKeys:    v.signerKeys,
	}
}

// ExtractReceipts reads a flight recorder JSONL file and extracts all
// action_receipt entries as Receipt structs, in file order.
func ExtractReceipts(path string) ([]Receipt, error) {
	clean := filepath.Clean(path)
	entries, err := recorder.ReadEntries(clean)
	if err != nil {
		rawReceipts, rawErr := extractRawReceiptsJSONLFile(clean)
		if rawErr != nil {
			return nil, rawErr
		}
		if len(rawReceipts) > 0 {
			return rawReceipts, nil
		}
		return nil, fmt.Errorf("reading entries: %w", err)
	}
	receipts, err := extractReceiptsFromEntries(entries)
	if err != nil || len(receipts) > 0 {
		return receipts, err
	}
	rawReceipts, rawErr := extractRawReceiptsJSONLFile(clean)
	if rawErr != nil {
		return nil, rawErr
	}
	return rawReceipts, nil
}

// ExtractReceiptsBytes extracts action_receipt entries from JSONL evidence
// bytes using the same accepted formats as ExtractReceipts: recorder entries
// first, then raw receipt JSONL as the compatibility fallback.
func ExtractReceiptsBytes(data []byte) ([]Receipt, error) {
	entries, err := recorder.ReadEntriesFromReader(bytes.NewReader(data))
	if err != nil {
		rawReceipts, rawErr := extractRawReceiptsJSONLBytes(data)
		if rawErr != nil {
			return nil, rawErr
		}
		if len(rawReceipts) > 0 {
			return rawReceipts, nil
		}
		return nil, fmt.Errorf("reading entries: %w", err)
	}
	receipts, err := extractReceiptsFromEntries(entries)
	if err != nil || len(receipts) > 0 {
		return receipts, err
	}
	return extractRawReceiptsJSONLBytes(data)
}

// ExtractAndVerifyWholeRecorderBytes is the WHOLE-RECORDER mode of the two-mode
// extraction contract. Where ExtractReceiptsBytes (receipt-chain mode) returns
// only the receipt subsequence, this mode additionally verifies the recorder
// hash chain over EVERY entry (recorder.VerifyChain) and rejects any entry
// whose Type is outside the recorder taxonomy. A nil error therefore certifies
// whole-file integrity, not merely that the extracted receipts form a valid
// chain. It does not use the raw-receipt-JSONL compatibility fallback: whole
// recorder verification requires real recorder entries.
func ExtractAndVerifyWholeRecorderBytes(data []byte) ([]Receipt, error) {
	entries, err := recorder.ReadEntriesFromReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("reading entries: %w", err)
	}
	for _, e := range entries {
		if !knownRecorderEntryType(e.Type) {
			return nil, fmt.Errorf("%w: %q at seq %d", ErrUnexpectedRecorderEntryType, e.Type, e.Sequence)
		}
	}
	if err := recorder.VerifyChain(entries); err != nil {
		return nil, fmt.Errorf("recorder hash chain: %w", err)
	}
	return extractReceiptsFromEntries(entries)
}

// ExtractReceiptsWithSessionID reads a flight recorder JSONL file and returns
// both the receipts and the session ID from the first entry. The session ID
// comes from the recorder entry metadata, which is lost in plain ExtractReceipts.
// Returns an empty session ID when the file contains no entries.
func ExtractReceiptsWithSessionID(path string) ([]Receipt, string, error) {
	entries, err := recorder.ReadEntries(filepath.Clean(path))
	if err != nil {
		return nil, "", fmt.Errorf("reading entries: %w", err)
	}
	var sessionID string
	if len(entries) > 0 {
		sessionID = entries[0].SessionID
	}
	receipts, err := extractReceiptsFromEntries(entries)
	return receipts, sessionID, err
}

// ExtractReceiptsFromSessionDir reads all evidence files for a session from a
// recorder directory and returns the action receipts in chain order.
func ExtractReceiptsFromSessionDir(dir, sessionID string) ([]Receipt, error) {
	receipts, _, err := ExtractReceiptsFromSessionDirBounded(dir, sessionID, 0)
	return receipts, err
}

// ExtractReceiptsFromSessionDirBounded reads action receipts for a session with
// an optional hard ceiling on parsed recorder entries. The returned boolean is
// true when the ceiling was reached before the full session was loaded.
func ExtractReceiptsFromSessionDirBounded(dir, sessionID string, maxEntriesRead int) ([]Receipt, bool, error) {
	return ExtractReceiptsFromSessionDirWithLimits(dir, sessionID, maxEntriesRead, 0)
}

// ExtractReceiptsFromSessionDirWithLimits reads action receipts for a session
// with hard ceilings on parsed recorder entries and evidence directory entries.
func ExtractReceiptsFromSessionDirWithLimits(dir, sessionID string, maxEntriesRead, maxDirectoryEntries int) ([]Receipt, bool, error) {
	result, err := recorder.QuerySession(filepath.Clean(dir), sessionID, &recorder.QueryFilter{
		MaxEntriesRead:      maxEntriesRead,
		MaxDirectoryEntries: maxDirectoryEntries,
	})
	if err != nil {
		return nil, false, fmt.Errorf("querying session receipts: %w", err)
	}
	receipts, err := extractReceiptsFromEntries(result.Entries)
	return receipts, result.Truncated, err
}

// evidenceReceiptEntryType is the recorder entry type for v2 evidence receipts.
// Go's receipt-chain extraction is action-receipt based, so evidence_receipt is
// a KNOWN operational type it skips rather than extracts (it is not a v1
// receipt); it stays in the taxonomy so a mixed recorder log is not rejected.
const evidenceReceiptEntryType = "evidence_receipt"

// receiptChainSkippableTypes is the allowlist of KNOWN non-extracted recorder
// entry types that receipt-chain extraction legitimately skips. It is the
// complement, within the recorder taxonomy, of the extracted receipt type
// (action_receipt). Any entry whose Type is outside {action_receipt} ∪ this set
// is REJECTED (fail-closed) rather than silently skipped, so a file that mixes
// a valid receipt chain with an unknown record type cannot be reported as a
// "valid receipt subsequence". The set is the confirmed-complete operational
// taxonomy: evidence_receipt, checkpoint, transcript_root, decision, capture,
// capture_drop.
var receiptChainSkippableTypes = map[string]struct{}{
	evidenceReceiptEntryType: {},
	"checkpoint":             {},
	"transcript_root":        {},
	"decision":               {},
	"capture":                {},
	"capture_drop":           {},
}

// knownRecorderEntryType reports whether t is inside the recorder taxonomy
// (the extracted receipt type plus the skippable operational types).
func knownRecorderEntryType(t string) bool {
	if t == recorderEntryType {
		return true
	}
	_, ok := receiptChainSkippableTypes[t]
	return ok
}

// extractReceiptsFromEntries is the RECEIPT-CHAIN mode of the two-mode
// extraction contract: it returns the receipt subsequence (action_receipt
// entries), skips the known operational entry types, and REJECTS any entry
// whose Type is outside the recorder taxonomy. The result certifies the
// receipt subsequence, NOT whole-file integrity — for that, use
// ExtractAndVerifyWholeRecorderBytes, which additionally verifies the recorder
// hash chain over every entry.
func extractReceiptsFromEntries(entries []recorder.Entry) ([]Receipt, error) {
	var receipts []Receipt
	for _, e := range entries {
		if e.Type == recorderEntryType {
			r, err := receiptFromEntry(e)
			if err != nil {
				return nil, fmt.Errorf("receipt at seq %d: %w", e.Sequence, err)
			}
			receipts = append(receipts, *r)
			continue
		}
		if !knownRecorderEntryType(e.Type) {
			return nil, fmt.Errorf("%w: %q at seq %d", ErrUnexpectedRecorderEntryType, e.Type, e.Sequence)
		}
	}
	return receipts, nil
}

func extractRawReceiptsJSONLFile(path string) ([]Receipt, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("reading raw receipts: %w", err)
	}
	return extractRawReceiptsJSONLBytes(data)
}

func extractRawReceiptsJSONLBytes(data []byte) ([]Receipt, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64<<10), 10<<20)
	var receipts []Receipt
	line := 0
	for scanner.Scan() {
		line++
		raw := bytes.TrimSpace(scanner.Bytes())
		if len(raw) == 0 {
			continue
		}
		r, err := Unmarshal(raw)
		if err != nil {
			if len(receipts) == 0 {
				return nil, nil
			}
			return nil, fmt.Errorf("parse raw receipt line %d: %w", line, err)
		}
		if r.Version != ReceiptVersion || r.Signature == "" || r.SignerKey == "" {
			if len(receipts) == 0 {
				return nil, nil
			}
			return nil, fmt.Errorf("parse raw receipt line %d: missing receipt fields", line)
		}
		receipts = append(receipts, r)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan raw receipts: %w", err)
	}
	return receipts, nil
}

// ComputeTranscriptRoot builds a TranscriptRoot from a valid single-key chain.
// It requires a non-empty trust anchor. For rotated chains, use
// ComputeTranscriptRootTrusted with every trusted segment key.
func ComputeTranscriptRoot(sessionID string, receipts []Receipt, expectedKeyHex string) (TranscriptRoot, error) {
	if expectedKeyHex == "" {
		return TranscriptRoot{}, fmt.Errorf("trust anchor required: pass expected signer key hex")
	}
	return ComputeTranscriptRootTrusted(sessionID, receipts, []string{expectedKeyHex})
}

// ComputeTranscriptRootTrusted builds a TranscriptRoot from a chain verified
// against an explicit trusted key set (supports rotation). At least one trusted
// key is required - transcript roots must be verified against a trust anchor,
// never trust-on-first-use.
func ComputeTranscriptRootTrusted(sessionID string, receipts []Receipt, trustedKeys []string) (TranscriptRoot, error) {
	if len(receipts) == 0 {
		return TranscriptRoot{}, fmt.Errorf("empty receipt chain")
	}
	normalizedKeys, err := normalizeTrustedKeys(trustedKeys)
	if err != nil {
		return TranscriptRoot{}, fmt.Errorf("trusted key set: %w", err)
	}
	if len(normalizedKeys) == 0 {
		return TranscriptRoot{}, fmt.Errorf("trust anchor required: pass expected signer key hex")
	}

	result := VerifyChainTrusted(receipts, normalizedKeys)
	if !result.Valid {
		return TranscriptRoot{}, fmt.Errorf("invalid chain: %s", result.Error)
	}

	return TranscriptRoot{
		SessionID:    sessionID,
		FinalSeq:     result.FinalSeq,
		RootHash:     result.RootHash,
		ReceiptCount: result.ReceiptCount,
		StartTime:    result.StartTime,
		EndTime:      result.EndTime,
	}, nil
}
