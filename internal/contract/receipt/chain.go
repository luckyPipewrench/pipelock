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
	"strconv"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/contract"
	"github.com/luckyPipewrench/pipelock/internal/jsonscan"
)

// GenesisHash is the chain_prev_hash of the first receipt in a v2 chain.
// It matches the recorder genesis sentinel so external verification can
// recompute the chain root without importing the recorder package.
const GenesisHash = "genesis"

// EvidenceEntryType is the recorder Entry.Type that wraps a v2
// EvidenceReceipt in its Detail field. The shadow emitter and the live-lock
// runtime both record receipts under this type.
const EvidenceEntryType = "evidence_receipt"

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

	return ChainResult{
		Valid:              true,
		ReceiptCount:       uint64(len(receipts)),
		FinalSeq:           receipts[len(receipts)-1].ChainSeq,
		RootHash:           tipHash,
		SignaturesVerified: opts.PinnedKey != nil,
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
// EvidenceEntryType, in file order. Other entry types are ignored so a mixed
// recorder stream (decision records, checkpoints) verifies cleanly.
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
	clean := filepath.Clean(dir)
	entries, err := os.ReadDir(clean)
	if err != nil {
		return nil, fmt.Errorf("read evidence directory: %w", err)
	}
	prefix := "evidence-" + sessionID + "-"
	files := make([]string, 0)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasPrefix(name, prefix) && strings.HasSuffix(name, ".jsonl") {
			files = append(files, filepath.Join(clean, name))
		}
	}
	sort.Slice(files, func(i, j int) bool {
		return evidenceSeqStart(files[i]) < evidenceSeqStart(files[j])
	})

	var out []EvidenceReceipt
	for _, file := range files {
		receipts, readErr := ExtractEvidenceReceipts(file)
		if readErr != nil {
			return nil, fmt.Errorf("read %s: %w", filepath.Base(file), readErr)
		}
		out = append(out, receipts...)
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
			continue
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

func evidenceSeqStart(path string) int {
	name := filepath.Base(path)
	name = strings.TrimSuffix(name, ".jsonl")
	idx := strings.LastIndex(name, "-")
	if idx < 0 {
		return 0
	}
	seq, err := strconv.Atoi(name[idx+1:])
	if err != nil {
		return 0
	}
	return seq
}
