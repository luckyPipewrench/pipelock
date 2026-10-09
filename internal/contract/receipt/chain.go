// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/luckyPipewrench/pipelock/internal/evidencename"
	"github.com/luckyPipewrench/pipelock/internal/jsonscan"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// GenesisHash is the chain_prev_hash of the first receipt in a v2 chain.
// It matches the recorder genesis sentinel so external verification can
// recompute the chain root without importing the recorder package.
const GenesisHash = "genesis"

// EvidenceEntryType is the recorder Entry.Type that wraps a v2
// EvidenceReceipt in its Detail field. The shadow emitter and the live-lock
// runtime both record receipts under this type.
const EvidenceEntryType = "evidence_receipt"

var skippableRecorderEntryTypes = map[string]struct{}{
	"action_receipt":  {},
	"checkpoint":      {},
	"transcript_root": {},
	"decision":        {},
	"capture":         {},
	"capture_drop":    {},
}

func knownRecorderEntryType(t string) bool {
	if t == EvidenceEntryType {
		return true
	}
	_, ok := skippableRecorderEntryTypes[t]
	return ok
}

// maxChainLineBytes bounds a single recorder JSONL line during extraction.
// A receipt envelope with an aggregated shadow_delta payload is well under
// this; the cap exists to reject a malicious oversized line rather than
// allocate unboundedly.
const maxChainLineBytes = 8 << 20 // 8 MiB

// ChainVerifyOptions configures v2 evidence-chain verification.
//
// The zero value verifies structure, chain linkage, and signer-id
// consistency only. Signature provenance is checked ONLY when PinnedKey is
// set: a detached Ed25519 signature cannot be verified without the public
// key out of band, so an unpinned verification proves self-consistency, not
// that any particular operator produced the chain.
type ChainVerifyOptions struct {
	// PinnedKey, when non-nil, is the trusted operator public key every
	// receipt's signature must verify against. Required for provenance.
	PinnedKey ed25519.PublicKey
	// ExpectSignerKeyID, when non-empty, requires every receipt to declare
	// this signer_key_id. Defense in depth alongside PinnedKey.
	ExpectSignerKeyID string
	// ExpectContractHash, when non-empty, requires every receipt's
	// contract_hash to match (binds the chain to a known contract).
	ExpectContractHash string
	// ExpectManifestHash, when non-empty, requires every receipt's
	// active_manifest_hash to match.
	ExpectManifestHash string
	// ExpectPayloadKind, when non-empty, requires every receipt's
	// payload_kind to match (e.g. shadow_delta).
	ExpectPayloadKind PayloadKind
	// ExpectHeadHash, when non-empty, requires the chain tip (the
	// ReceiptHash of the final receipt) to equal this value. It is the only
	// option here that can detect OMISSION.
	//
	// Every other check in this type is satisfied by any valid PREFIX of a
	// chain: linkage proves the receipts present form a sequence starting at
	// genesis, so dropping every entry after some point leaves a chain that
	// still verifies. Omission is the failure mode that matters most for
	// evidence, because the dropped entries are exactly the ones a bad actor
	// wants gone, and it is precisely the case a prefix check cannot see.
	//
	// For one accepted v2 receipt chain, pinning the head is sufficient under
	// SHA-256 collision and second-preimage resistance: ReceiptHash covers the
	// full canonical final receipt, whose chain_prev_hash recursively commits to
	// every prior receipt back to genesis. A separate expected count or sequence
	// range therefore cannot distinguish another valid prefix that the pinned
	// head would accept.
	//
	// This commitment is only to the v2 receipt slice being verified. It does
	// not cover recorder entry types skipped during extraction, authenticate a
	// session label, or join independent genesis chains across process restarts.
	// Those require whole-recorder verification and trusted session/segment
	// metadata in addition to this option.
	//
	// The expected head must be authenticated independently of the chain bytes
	// it validates (for example by a pinned-key signed checkpoint, an anchored
	// root, a transparency-log inclusion proof, or an authenticated manifest).
	// It may be stored in the same directory if its authentication is verified
	// and its presence is required; an unsigned sibling value that an attacker
	// can rewrite or delete with the chain proves nothing.
	//
	// Opt-in by construction: unset means structure-only verification, exactly
	// as before, so existing callers and the other-language verifiers are
	// unaffected. A caller that HAS trusted head context and omits this is
	// choosing not to check completeness.
	ExpectHeadHash string
}

// ChainResult describes the outcome of v2 evidence-chain verification.
type ChainResult struct {
	Valid        bool   `json:"valid"`
	ReceiptCount uint64 `json:"receipt_count"`
	FinalSeq     uint64 `json:"final_seq"`
	// RootHash is the ReceiptHash of the final receipt (the chain tip).
	RootHash string `json:"root_hash,omitempty"`
	// SignaturesVerified is true only when PinnedKey was supplied and every
	// signature verified against it. When false, the verdict reflects
	// self-consistency, not provenance.
	SignaturesVerified bool `json:"signatures_verified"`
	// HeadVerified is true only when ExpectHeadHash was supplied and matched.
	// When false, the verdict covers the receipts PRESENT and says nothing
	// about whether later ones were dropped, so a consumer must not report
	// this chain as complete. It exists so "valid" cannot be read as
	// "nothing is missing" by a caller that never pinned a head.
	HeadVerified bool `json:"head_verified"`
	// SignerKeyID is the common signer_key_id shared by every receipt.
	SignerKeyID string `json:"signer_key_id,omitempty"`
	Error       string `json:"error,omitempty"`
	BrokenAtSeq uint64 `json:"broken_at_seq,omitempty"`
}

func brokenChain(seq uint64, format string, args ...any) ChainResult {
	return ChainResult{Valid: false, BrokenAtSeq: seq, Error: fmt.Sprintf(format, args...)}
}

// VerifyChain verifies the hash-chain integrity of an ordered sequence of v2
// evidence receipts. Receipts must be in ascending chain order.
//
// Checks, in order, per receipt: structural validity (Validate), the
// optional Expect* bindings, signer-id consistency, chain_seq == position,
// chain_prev_hash linkage (first == GenesisHash, subsequent == ReceiptHash
// of the prior receipt), and — when ChainVerifyOptions.PinnedKey is set —
// the Ed25519 signature against the pinned key.
func VerifyChain(receipts []EvidenceReceipt, opts ChainVerifyOptions) ChainResult {
	walk := NewChainWalker(opts)
	for _, r := range receipts {
		if !walk.Add(r) {
			break
		}
	}
	return walk.Result()
}

// ChainWalker is VerifyChain applied one receipt at a time. It keeps the
// previous receipt's hash and the chain signer, never the receipts, and
// Result returns exactly what VerifyChain returns for the receipts added so
// far. Once a receipt breaks the chain the walker stays broken.
type ChainWalker struct {
	opts              ChainVerifyOptions
	pinnedSignerKeyID string
	signerID          string
	prevHash          string
	tipHash           string
	count             uint64
	finalSeq          uint64
	fail              *ChainResult
}

// NewChainWalker starts an empty chain under opts.
func NewChainWalker(opts ChainVerifyOptions) *ChainWalker {
	return &ChainWalker{opts: opts, pinnedSignerKeyID: SignerKeyID(opts.PinnedKey), prevHash: GenesisHash}
}

// Add checks the next receipt. It returns false once the chain is broken.
func (w *ChainWalker) Add(r EvidenceReceipt) bool {
	if w.fail != nil {
		return false
	}
	if res, ok := w.add(r); !ok {
		w.fail = &res
		return false
	}
	return true
}

func (w *ChainWalker) add(r EvidenceReceipt) (ChainResult, bool) {
	opts := w.opts
	seq := w.count
	if seq == 0 {
		w.signerID = r.Signature.SignerKeyID
	}

	// Structural validity. VerifyWithKey re-runs Validate internally,
	// so when a key is pinned the explicit call is folded into the
	// signature check below to avoid double validation.
	if opts.PinnedKey == nil {
		if err := r.Validate(); err != nil {
			return brokenChain(seq, "receipt %d invalid: %v", seq, err), false
		}
	}

	if opts.ExpectSignerKeyID != "" && r.Signature.SignerKeyID != opts.ExpectSignerKeyID {
		return brokenChain(seq, "receipt %d signer_key_id %q does not match pinned %q",
			seq, r.Signature.SignerKeyID, opts.ExpectSignerKeyID), false
	}
	if opts.ExpectPayloadKind != "" && r.PayloadKind != opts.ExpectPayloadKind {
		return brokenChain(seq, "receipt %d payload_kind %q does not match expected %q",
			seq, r.PayloadKind, opts.ExpectPayloadKind), false
	}
	if opts.ExpectContractHash != "" && r.ContractHash != opts.ExpectContractHash {
		return brokenChain(seq, "receipt %d contract_hash does not match expected", seq), false
	}
	if opts.ExpectManifestHash != "" && r.ActiveManifestHash != opts.ExpectManifestHash {
		return brokenChain(seq, "receipt %d active_manifest_hash does not match expected", seq), false
	}

	// Signer consistency: a forged chain that splices receipts from a
	// different signer is rejected even without a pinned key.
	if r.Signature.SignerKeyID != w.signerID {
		return brokenChain(seq, "receipt %d signer_key_id %q breaks chain signer %q",
			seq, r.Signature.SignerKeyID, w.signerID), false
	}

	if r.ChainSeq != seq {
		return brokenChain(seq, "receipt %d declares chain_seq %d", seq, r.ChainSeq), false
	}
	if r.ChainPrevHash != w.prevHash {
		return brokenChain(seq, "receipt %d chain_prev_hash mismatch", seq), false
	}

	if opts.PinnedKey != nil {
		if err := VerifyWithKey(r, opts.PinnedKey, w.pinnedSignerKeyID); err != nil {
			return brokenChain(seq, "receipt %d signature: %v", seq, err), false
		}
	}

	h, err := ReceiptHash(r)
	if err != nil {
		return brokenChain(seq, "receipt %d hash: %v", seq, err), false
	}
	w.prevHash = h
	w.tipHash = h
	w.finalSeq = r.ChainSeq
	w.count++
	return ChainResult{}, true
}

// Result returns VerifyChain's result for the receipts added so far.
func (w *ChainWalker) Result() ChainResult {
	if w.fail != nil {
		return *w.fail
	}
	if w.count == 0 {
		return ChainResult{Valid: false, Error: "empty chain"}
	}

	// Completeness, and the only check here that a valid prefix cannot pass.
	// Deliberately last: a chain that is internally broken should report the
	// broken link at its sequence rather than a head mismatch, which is the
	// downstream symptom rather than the cause.
	if w.opts.ExpectHeadHash != "" && w.tipHash != w.opts.ExpectHeadHash {
		return brokenChain(w.finalSeq,
			"chain head %s does not match expected %s: the chain is truncated, forked, or from a different session",
			w.tipHash, w.opts.ExpectHeadHash)
	}

	return ChainResult{
		Valid:              true,
		ReceiptCount:       w.count,
		FinalSeq:           w.finalSeq,
		RootHash:           w.tipHash,
		SignaturesVerified: w.opts.PinnedKey != nil,
		HeadVerified:       w.opts.ExpectHeadHash != "",
		SignerKeyID:        w.signerID,
	}
}

// StreamingVerifier verifies the pinned-key compaction profile without
// retaining all receipts. It intentionally accepts no optional expectation
// bindings: a maintenance caller must not mistake this narrow API for a full
// ChainVerifyOptions implementation.
type StreamingVerifier struct {
	key      ed25519.PublicKey
	count    uint64
	signerID string
	prevHash string
	lastSeq  uint64
	fail     *ChainResult
}

func NewPinnedStreamingVerifier(key ed25519.PublicKey) (*StreamingVerifier, error) {
	if len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("pinned streaming verifier requires Ed25519 public key")
	}
	return &StreamingVerifier{key: key, prevHash: GenesisHash}, nil
}

// AddRaw verifies exact v2 wire bytes before advancing the receipt chain.
func (v *StreamingVerifier) AddRaw(raw []byte) error {
	if v.fail != nil {
		return fmt.Errorf("%s", v.fail.Error)
	}
	if err := jsonscan.RejectDuplicateKeys(raw); err != nil {
		return v.latch(brokenChain(v.count, "receipt %d duplicate keys: %v", v.count, err))
	}
	r, err := ParseEvidenceReceipt(raw)
	if err != nil {
		return v.latch(brokenChain(v.count, "receipt %d decode: %v", v.count, err))
	}
	seq := v.count
	if err := VerifyWithKey(r, v.key, SignerKeyID(v.key)); err != nil {
		return v.latch(brokenChain(seq, "receipt %d signature: %v", seq, err))
	}
	if v.count == 0 {
		v.signerID = r.Signature.SignerKeyID
	} else if r.Signature.SignerKeyID != v.signerID {
		return v.latch(brokenChain(seq, "receipt %d signer_key_id %q breaks chain signer %q", seq, r.Signature.SignerKeyID, v.signerID))
	}
	if r.ChainSeq != seq || r.ChainPrevHash != v.prevHash {
		return v.latch(brokenChain(seq, "receipt %d chain sequence or previous hash mismatch", seq))
	}
	h, err := ReceiptHash(r)
	if err != nil {
		return v.latch(brokenChain(seq, "receipt %d hash: %v", seq, err))
	}
	v.prevHash, v.lastSeq, v.count = h, r.ChainSeq, v.count+1
	return nil
}

func (v *StreamingVerifier) latch(res ChainResult) error {
	v.fail = &res
	return fmt.Errorf("%s", res.Error)
}

func (v *StreamingVerifier) Finish() ChainResult {
	if v.fail != nil {
		return *v.fail
	}
	if v.count == 0 {
		return ChainResult{Valid: false, Error: "empty chain"}
	}
	return ChainResult{Valid: true, ReceiptCount: v.count, FinalSeq: v.lastSeq, RootHash: v.prevHash, SignaturesVerified: true, SignerKeyID: v.signerID}
}

// recorderLine is the minimal recorder Entry shape needed to recover an
// embedded v2 receipt. Non-evidence entries carry other Detail shapes and
// are skipped by type.
type recorderLine struct {
	Type   string          `json:"type"`
	Detail json.RawMessage `json:"detail"`
}

// ExtractEvidenceReceipts reads a recorder JSONL file and returns the v2
// EvidenceReceipts embedded in the Detail field of every entry whose type is
// EvidenceEntryType, in file order. Known operational entry types are skipped,
// while unknown types fail closed so junk cannot ride beside a valid receipt
// subsequence.
func ExtractEvidenceReceipts(path string) ([]EvidenceReceipt, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("read evidence file: %w", err)
	}
	return extractEvidenceReceiptsFromBytes(data, filepath.Clean(path))
}

// ExtractEvidenceReceiptsBytes parses an already-read evidence snapshot.
func ExtractEvidenceReceiptsBytes(data []byte) ([]EvidenceReceipt, error) {
	return extractEvidenceReceiptsFromBytes(data, "evidence bytes")
}

// ExtractEvidenceReceiptsFromSessionDir reads all recorder JSONL files for a
// session and returns v2 EvidenceReceipts in chain order. Files are ordered by
// their numeric sequence suffix, matching recorder.QuerySession's v1 behavior.
func ExtractEvidenceReceiptsFromSessionDir(dir, sessionID string) ([]EvidenceReceipt, error) {
	location, resolveErr := recorder.ResolveEvidenceLocation(dir, "")
	if resolveErr != nil {
		return nil, fmt.Errorf("resolve evidence location: %w", resolveErr)
	}
	return ExtractEvidenceReceiptsFromResolvedSessionDir(location, sessionID)
}

// ExtractEvidenceReceiptsFromResolvedSessionDir reads one already-resolved evidence location.
//
// The shards come from the recorder's authoritative session walk: membership
// is parsed session equality, never an "evidence-<session>-" prefix; order is
// (sequence start, name); two shards starting the same sequence are refused;
// and no directory, file-size or entry-count budget can refuse or truncate the
// chain. Each shard streams one line at a time, so only receipts are retained.
func ExtractEvidenceReceiptsFromResolvedSessionDir(location recorder.EvidenceLocation, sessionID string) ([]EvidenceReceipt, error) {
	clean := filepath.Clean(location.Dir)
	wantSession := filepath.Base(sessionID)
	out := make([]EvidenceReceipt, 0)
	err := recorder.WalkSessionHistoryFiles(location, wantSession, func(shard recorder.SessionHistoryShard, r io.Reader) error {
		return walkEvidenceReceiptLines(r, filepath.Join(clean, shard.Name), func(receipt EvidenceReceipt) {
			out = append(out, receipt)
		})
	})
	if err != nil {
		return nil, fmt.Errorf("evidence session %s in %s: %w", wantSession, clean, err)
	}
	return out, nil
}

// ExtractEvidenceReceiptsFromEntries extracts signed receipts from recorder
// entries that have already passed recorder parsing. It uses RawDetail when
// present so receipt verification consumes the immutable wire bytes rather
// than a re-marshaled approximation. The secret-egress kind requires original
// RawDetail; re-marshaling a parsed map cannot recover its source wire profile.
// Other kinds retain their legacy typed/programmatic Detail fallback.
func ExtractEvidenceReceiptsFromEntries(entries []recorder.Entry) ([]EvidenceReceipt, error) {
	out := make([]EvidenceReceipt, 0)
	for i, entry := range entries {
		receipt, ok, err := EvidenceReceiptFromEntry(i, entry)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, receipt)
		}
	}
	return out, nil
}

// EvidenceReceiptFromEntry is one step of ExtractEvidenceReceiptsFromEntries:
// index is the entry's zero-based position among all recorder entries, which
// errors name. ok is false for a known entry type that is not an evidence
// receipt. A caller that extracts while reading gets the same receipts and
// the same first error without holding the entries.
func EvidenceReceiptFromEntry(index int, entry recorder.Entry) (EvidenceReceipt, bool, error) {
	if entry.Type != EvidenceEntryType {
		if knownRecorderEntryType(entry.Type) {
			return EvidenceReceipt{}, false, nil
		}
		return EvidenceReceipt{}, false, fmt.Errorf("parsed recorder entry %d: unexpected recorder entry type %q", index+1, entry.Type)
	}
	detail := entry.RawDetail
	if len(detail) == 0 {
		var err error
		detail, err = json.Marshal(entry.Detail)
		if err != nil {
			return EvidenceReceipt{}, false, fmt.Errorf("parsed recorder entry %d: marshal evidence detail: %w", index+1, err)
		}
		if isSecretEgressWire(detail) {
			return EvidenceReceipt{}, false, fmt.Errorf("parsed recorder entry %d: secret egress receipt requires original RawDetail", index+1)
		}
	}
	receipt, err := decodeEvidenceReceiptDetail(detail)
	if err != nil {
		return EvidenceReceipt{}, false, fmt.Errorf("parsed recorder entry %d: %w", index+1, err)
	}
	return receipt, true, nil
}

func extractEvidenceReceiptsFromBytes(data []byte, label string) ([]EvidenceReceipt, error) {
	var out []EvidenceReceipt
	if err := walkEvidenceReceiptLines(bytes.NewReader(data), label, func(r EvidenceReceipt) {
		out = append(out, r)
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// walkEvidenceReceiptLines parses recorder JSONL one line at a time and
// delivers each v2 evidence receipt, so a caller retains only receipts.
func walkEvidenceReceiptLines(input io.Reader, label string, deliver func(EvidenceReceipt)) error {
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 0, 64<<10), maxChainLineBytes)
	line := 0
	for scanner.Scan() {
		line++
		raw := bytes.TrimSpace(scanner.Bytes())
		if len(raw) == 0 {
			continue
		}
		if err := jsonscan.RejectDuplicateKeys(raw); err != nil {
			return fmt.Errorf("%s line %d: decode recorder entry: %w", label, line, err)
		}
		var entry recorderLine
		if err := json.Unmarshal(raw, &entry); err != nil {
			return fmt.Errorf("%s line %d: decode recorder entry: %w", label, line, err)
		}
		if entry.Type != EvidenceEntryType {
			if knownRecorderEntryType(entry.Type) {
				continue
			}
			return fmt.Errorf("%s line %d: unexpected recorder entry type %q", label, line, entry.Type)
		}
		r, err := decodeEvidenceReceiptDetail(entry.Detail)
		if err != nil {
			return fmt.Errorf("%s line %d: %w", label, line, err)
		}
		deliver(r)
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan evidence file %s: %w", label, err)
	}
	return nil
}

// decodeEvidenceReceiptDetail decodes the hash-bound detail value used by
// both raw JSONL and recorder-parsed extraction. json.RawMessage("null") is
// non-empty, so explicitly reject it rather than accepting a zero receipt.
func decodeEvidenceReceiptDetail(detail []byte) (EvidenceReceipt, error) {
	if len(detail) == 0 || string(bytes.TrimSpace(detail)) == "null" {
		return EvidenceReceipt{}, errors.New("evidence entry has empty detail")
	}
	r, err := ParseEvidenceReceipt(detail)
	if err != nil {
		return EvidenceReceipt{}, fmt.Errorf("decode evidence receipt: %w", err)
	}
	return r, nil
}

// parseEvidenceName splits an evidence shard filename into its session ID and
// starting sequence, via the shared evidencename package. This verifier and the
// recorder must agree on session membership, and a single definition is what
// guarantees that rather than two copies plus a drift test.
func parseEvidenceName(path string) (sessionID string, seqStart uint64, ok bool) {
	return evidencename.Parse(path)
}
