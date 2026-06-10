// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// GenesisHash is the chain_prev_hash of the first receipt in a session.
const GenesisHash = "genesis"

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
	Valid        bool
	ReceiptCount uint64
	FinalSeq     uint64
	RootHash     string
	StartTime    time.Time
	EndTime      time.Time
	Error        string // empty if valid
	BrokenAtSeq  uint64 // set when chain breaks

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
	if len(receipts) == 0 {
		return ChainResult{Valid: true}
	}

	normalizedKeys, err := normalizeTrustedKeys(trustedKeys)
	if err != nil {
		return ChainResult{
			Valid:       false,
			BrokenAtSeq: receipts[0].ActionRecord.ChainSeq,
			Error:       fmt.Sprintf("seq %d: trusted key set: %v", receipts[0].ActionRecord.ChainSeq, err),
		}
	}

	trusted := make(map[string]struct{}, len(normalizedKeys))
	for _, k := range normalizedKeys {
		trusted[k] = struct{}{}
	}
	v := &chainVerifier{trusted: trusted}
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
}

func (v *chainVerifier) run(receipts []Receipt) ChainResult {
	for i := range receipts {
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

		if res, ok := v.verifyReceipt(r, uint64(i)); !ok {
			return res
		}
	}

	v.closeSegment()
	first := receipts[0].ActionRecord
	last := receipts[len(receipts)-1].ActionRecord
	return ChainResult{
		Valid:        true,
		ReceiptCount: uint64(len(receipts)),
		FinalSeq:     last.ChainSeq,
		RootHash:     v.prevHash,
		StartTime:    first.Timestamp,
		EndTime:      last.Timestamp,
		SignerKeys:   v.signerKeys,
		Segments:     v.segments,
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
	default:
		// Ordinary genesis: prev_hash must be the genesis sentinel.
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
	res := v.brokenAt(r, fmt.Sprintf("signer key %s is not in the trusted set", r.SignerKey))
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
	return ChainResult{}, true
}

func (v *chainVerifier) verifyReceipt(r Receipt, index uint64) (ChainResult, bool) {
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
	return ChainResult{
		Valid:       false,
		BrokenAtSeq: r.ActionRecord.ChainSeq,
		Error:       fmt.Sprintf("seq %d: %s", r.ActionRecord.ChainSeq, msg),
		SignerKeys:  v.signerKeys,
	}
}

// ExtractReceipts reads a flight recorder JSONL file and extracts all
// action_receipt entries as Receipt structs, in file order.
func ExtractReceipts(path string) ([]Receipt, error) {
	entries, err := recorder.ReadEntries(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("reading entries: %w", err)
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
	result, err := recorder.QuerySession(filepath.Clean(dir), sessionID, &recorder.QueryFilter{
		Type: recorderEntryType,
	})
	if err != nil {
		return nil, fmt.Errorf("querying session receipts: %w", err)
	}
	return extractReceiptsFromEntries(result.Entries)
}

func extractReceiptsFromEntries(entries []recorder.Entry) ([]Receipt, error) {
	var receipts []Receipt
	for _, e := range entries {
		if e.Type != recorderEntryType {
			continue
		}
		r, err := receiptFromEntry(e)
		if err != nil {
			return nil, err
		}
		receipts = append(receipts, *r)
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
