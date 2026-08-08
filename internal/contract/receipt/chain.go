// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/luckyPipewrench/pipelock/internal/contract"
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
	if len(receipts) == 0 {
		return ChainResult{Valid: false, Error: "empty chain"}
	}

	signerID := receipts[0].Signature.SignerKeyID
	prevHash := GenesisHash
	var tipHash string

	for i, r := range receipts {
		seq := uint64(i)

		// Structural validity. VerifyWithKey re-runs Validate internally,
		// so when a key is pinned the explicit call is folded into the
		// signature check below to avoid double validation.
		if opts.PinnedKey == nil {
			if err := r.Validate(); err != nil {
				return brokenChain(seq, "receipt %d invalid: %v", seq, err)
			}
		}

		if opts.ExpectSignerKeyID != "" && r.Signature.SignerKeyID != opts.ExpectSignerKeyID {
			return brokenChain(seq, "receipt %d signer_key_id %q does not match pinned %q",
				seq, r.Signature.SignerKeyID, opts.ExpectSignerKeyID)
		}
		if opts.ExpectPayloadKind != "" && r.PayloadKind != opts.ExpectPayloadKind {
			return brokenChain(seq, "receipt %d payload_kind %q does not match expected %q",
				seq, r.PayloadKind, opts.ExpectPayloadKind)
		}
		if opts.ExpectContractHash != "" && r.ContractHash != opts.ExpectContractHash {
			return brokenChain(seq, "receipt %d contract_hash does not match expected", seq)
		}
		if opts.ExpectManifestHash != "" && r.ActiveManifestHash != opts.ExpectManifestHash {
			return brokenChain(seq, "receipt %d active_manifest_hash does not match expected", seq)
		}

		// Signer consistency: a forged chain that splices receipts from a
		// different signer is rejected even without a pinned key.
		if r.Signature.SignerKeyID != signerID {
			return brokenChain(seq, "receipt %d signer_key_id %q breaks chain signer %q",
				seq, r.Signature.SignerKeyID, signerID)
		}

		if r.ChainSeq != seq {
			return brokenChain(seq, "receipt %d declares chain_seq %d", seq, r.ChainSeq)
		}
		if r.ChainPrevHash != prevHash {
			return brokenChain(seq, "receipt %d chain_prev_hash mismatch", seq)
		}

		if opts.PinnedKey != nil {
			if err := VerifyWithKey(r, opts.PinnedKey, r.Signature.SignerKeyID); err != nil {
				return brokenChain(seq, "receipt %d signature: %v", seq, err)
			}
		}

		h, err := ReceiptHash(r)
		if err != nil {
			return brokenChain(seq, "receipt %d hash: %v", seq, err)
		}
		prevHash = h
		tipHash = h
	}

	finalSeq := receipts[len(receipts)-1].ChainSeq

	// Completeness, and the only check here that a valid prefix cannot pass.
	// Deliberately last: a chain that is internally broken should report the
	// broken link at its sequence rather than a head mismatch, which is the
	// downstream symptom rather than the cause.
	if opts.ExpectHeadHash != "" && tipHash != opts.ExpectHeadHash {
		return brokenChain(finalSeq,
			"chain head %s does not match expected %s: the chain is truncated, forked, or from a different session",
			tipHash, opts.ExpectHeadHash)
	}

	return ChainResult{
		Valid:              true,
		ReceiptCount:       uint64(len(receipts)),
		FinalSeq:           finalSeq,
		RootHash:           tipHash,
		SignaturesVerified: opts.PinnedKey != nil,
		HeadVerified:       opts.ExpectHeadHash != "",
		SignerKeyID:        signerID,
	}
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
func ExtractEvidenceReceiptsFromResolvedSessionDir(location recorder.EvidenceLocation, sessionID string) ([]EvidenceReceipt, error) {
	clean := filepath.Clean(location.Dir)
	entries, err := recorder.ReadEvidenceLocationEntries(location)
	if err != nil {
		return nil, fmt.Errorf("read evidence directory: %w", err)
	}
	// Session membership is parsed equality, not an "evidence-<session>-"
	// prefix. For session "s", the name "evidence-s-evil-999.jsonl" satisfies
	// the prefix but belongs to session "s-evil", so prefix matching folded
	// another session's receipts into this one's chain order.
	wantSession := filepath.Base(sessionID)
	// Parse once per file rather than on every comparator call. A session's
	// shard count is unbounded over time now that resume no longer caps the
	// directory, and the two sibling scanners in this change already
	// precompute the same way.
	type shard struct {
		name     string
		seqStart uint64
	}
	shards := make([]shard, 0)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		parsedSession, seqStart, ok := parseEvidenceName(name)
		if !ok || parsedSession != wantSession {
			continue
		}
		shards = append(shards, shard{
			name:     name,
			seqStart: seqStart,
		})
	}
	// Total order. sort.Slice is not stable, and a non-numeric trailing segment
	// parses to sequence 0, so several distinct names can tie. Without a
	// tie-break the resulting chain order would depend on directory order.
	sort.Slice(shards, func(i, j int) bool {
		if shards[i].seqStart != shards[j].seqStart {
			return shards[i].seqStart < shards[j].seqStart
		}
		return shards[i].name < shards[j].name
	})
	files := make([]string, 0, len(shards))
	for _, s := range shards {
		files = append(files, s.name)
	}

	// Refuse an ambiguous shard set rather than concatenating receipts in an
	// order that depended on which of two indistinguishable names sorted
	// first. A verifier presenting that as a chain is the same hazard as a
	// truncated read presented as complete.
	if err := evidencename.CheckNoDuplicateSeqStart(files); err != nil {
		return nil, fmt.Errorf("evidence session %s in %s: %w", wantSession, clean, err)
	}

	var out []EvidenceReceipt
	for _, file := range files {
		data, readErr := recorder.ReadEvidenceLocationFileBounded(location, file, recorder.MaxEvidenceReadFileBytes)
		if readErr == nil {
			receipts, parseErr := extractEvidenceReceiptsFromBytes(data, filepath.Join(clean, file))
			if parseErr != nil {
				readErr = parseErr
			} else {
				out = append(out, receipts...)
			}
		}
		if readErr != nil {
			return nil, fmt.Errorf("read %s: %w", filepath.Base(file), readErr)
		}
	}
	return out, nil
}

func extractEvidenceReceiptsFromBytes(data []byte, label string) ([]EvidenceReceipt, error) {
	var out []EvidenceReceipt
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64<<10), maxChainLineBytes)
	line := 0
	for scanner.Scan() {
		line++
		raw := bytes.TrimSpace(scanner.Bytes())
		if len(raw) == 0 {
			continue
		}
		if err := jsonscan.RejectDuplicateKeys(raw); err != nil {
			return nil, fmt.Errorf("%s line %d: decode recorder entry: %w", label, line, err)
		}
		var entry recorderLine
		if err := json.Unmarshal(raw, &entry); err != nil {
			return nil, fmt.Errorf("%s line %d: decode recorder entry: %w", label, line, err)
		}
		if entry.Type != EvidenceEntryType {
			if knownRecorderEntryType(entry.Type) {
				continue
			}
			return nil, fmt.Errorf("%s line %d: unexpected recorder entry type %q", label, line, entry.Type)
		}
		// json.RawMessage("null") is non-nil and 4 bytes long, so a length
		// check alone would let a null detail unmarshal to a zero receipt
		// silently. Reject both empty and literal null.
		if len(entry.Detail) == 0 || string(bytes.TrimSpace(entry.Detail)) == "null" {
			return nil, fmt.Errorf("%s line %d: evidence entry has empty detail", label, line)
		}
		var r EvidenceReceipt
		if err := contract.DecodeStrictJSON(entry.Detail, &r); err != nil {
			return nil, fmt.Errorf("%s line %d: decode evidence receipt: %w", label, line, err)
		}
		out = append(out, r)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan evidence file %s: %w", label, err)
	}
	return out, nil
}

// parseEvidenceName splits an evidence shard filename into its session ID and
// starting sequence, via the shared evidencename package. This verifier and the
// recorder must agree on session membership, and a single definition is what
// guarantees that rather than two copies plus a drift test.
func parseEvidenceName(path string) (sessionID string, seqStart uint64, ok bool) {
	return evidencename.Parse(path)
}
