// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
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
}

// VerifyChain verifies hash-chain integrity of a sequence of receipts.
// Receipts must be in chain order (ascending chain_seq).
// Checks: signature valid, chain_seq increments by 1, chain_prev_hash
// matches previous receipt's hash, first receipt has "genesis" prev_hash.
func VerifyChain(receipts []Receipt, expectedKeyHex string) ChainResult {
	if len(receipts) == 0 {
		return ChainResult{Valid: true}
	}

	// When no key is pinned, enforce signer consistency: all receipts
	// must share the same signer_key. Prevents forged chains where an
	// attacker generates receipts with their own key.
	if expectedKeyHex == "" && len(receipts) > 0 {
		expectedKeyHex = receipts[0].SignerKey
	}

	prevHash := GenesisHash
	for i, r := range receipts {
		// Verify signature against pinned or first-receipt key
		if err := VerifyWithKey(r, expectedKeyHex); err != nil {
			return ChainResult{
				Valid:       false,
				BrokenAtSeq: r.ActionRecord.ChainSeq,
				Error:       fmt.Sprintf("seq %d: signature: %v", r.ActionRecord.ChainSeq, err),
			}
		}

		// Verify seq
		expectedSeq := uint64(i)
		if r.ActionRecord.ChainSeq != expectedSeq {
			return ChainResult{
				Valid:       false,
				BrokenAtSeq: r.ActionRecord.ChainSeq,
				Error:       fmt.Sprintf("seq gap: expected %d, got %d", expectedSeq, r.ActionRecord.ChainSeq),
			}
		}

		// Verify prev_hash
		if r.ActionRecord.ChainPrevHash != prevHash {
			return ChainResult{
				Valid:       false,
				BrokenAtSeq: r.ActionRecord.ChainSeq,
				Error:       fmt.Sprintf("seq %d: chain_prev_hash mismatch", r.ActionRecord.ChainSeq),
			}
		}

		// Compute this receipt's hash for next iteration
		hash, err := ReceiptHash(r)
		if err != nil {
			return ChainResult{
				Valid:       false,
				BrokenAtSeq: r.ActionRecord.ChainSeq,
				Error:       fmt.Sprintf("seq %d: hash computation: %v", r.ActionRecord.ChainSeq, err),
			}
		}
		prevHash = hash
	}

	first := receipts[0].ActionRecord
	last := receipts[len(receipts)-1].ActionRecord
	return ChainResult{
		Valid:        true,
		ReceiptCount: uint64(len(receipts)),
		FinalSeq:     last.ChainSeq,
		RootHash:     prevHash,
		StartTime:    first.Timestamp,
		EndTime:      last.Timestamp,
	}
}

// ExtractReceipts reads a flight recorder JSONL file and extracts all
// action_receipt entries as Receipt structs, in file order.
func ExtractReceipts(path string) ([]Receipt, error) {
	entries, err := recorder.ReadEntries(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("reading entries: %w", err)
	}
	var receipts []Receipt
	for _, e := range entries {
		if e.Type != recorderEntryType {
			continue
		}
		detailJSON, err := json.Marshal(e.Detail)
		if err != nil {
			return nil, fmt.Errorf("seq %d: marshal detail: %w", e.Sequence, err)
		}
		r, err := Unmarshal(detailJSON)
		if err != nil {
			return nil, fmt.Errorf("seq %d: unmarshal receipt: %w", e.Sequence, err)
		}
		receipts = append(receipts, r)
	}
	return receipts, nil
}

// ComputeTranscriptRoot builds a TranscriptRoot from a valid chain.
func ComputeTranscriptRoot(sessionID string, receipts []Receipt, expectedKeyHex string) (TranscriptRoot, error) {
	if len(receipts) == 0 {
		return TranscriptRoot{}, fmt.Errorf("empty receipt chain")
	}

	// Verify chain integrity with the caller's trust anchor. When
	// expectedKeyHex is empty, VerifyChain pins to the first receipt's
	// embedded key — sufficient for self-consistency but not external trust.
	result := VerifyChain(receipts, expectedKeyHex)
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
