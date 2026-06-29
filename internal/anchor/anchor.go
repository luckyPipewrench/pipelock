// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package anchor records and verifies external receipt-chain checkpoints.
package anchor

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/jsonscan"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

const (
	BundleVersion     = 1
	LocalBackend      = "local"
	DefaultLocalLogID = "local-fake-log"
	GenesisHash       = "genesis"

	dirPermissions  = 0o750
	filePermissions = 0o600
)

var DefaultLimits = []string{
	"External anchoring detects after-the-fact rewrite, delete, omit, and equivocation against the anchored checkpoint.",
	"External anchoring does not prove real-time truth by whoever held the receipt signing key.",
	"The local backend is a deterministic test backend, not an operator-independent witness.",
}

type Backend interface {
	Submit(Checkpoint) (Proof, error)
	Verify(Proof, Checkpoint) error
}

type Checkpoint struct {
	SessionID    string    `json:"session_id"`
	FinalSeq     uint64    `json:"final_seq"`
	RootHash     string    `json:"root_hash"`
	ReceiptCount uint64    `json:"receipt_count"`
	StartTime    time.Time `json:"start_time"`
	EndTime      time.Time `json:"end_time"`
	SignerKeys   []string  `json:"signer_keys"`
}

type Proof struct {
	Backend     string `json:"backend"`
	LogID       string `json:"log_id"`
	LogIndex    uint64 `json:"log_index"`
	EntryHash   string `json:"entry_hash"`
	LogRootHash string `json:"log_root_hash"`
}

type Bundle struct {
	Version    int        `json:"version"`
	Backend    string     `json:"backend"`
	CreatedAt  time.Time  `json:"created_at"`
	Checkpoint Checkpoint `json:"checkpoint"`
	Proof      Proof      `json:"proof"`
	Limits     []string   `json:"limits"`
}

type VerifyReport struct {
	Valid        bool       `json:"valid"`
	Backend      string     `json:"backend,omitempty"`
	SessionID    string     `json:"session_id,omitempty"`
	ReceiptCount uint64     `json:"receipt_count,omitempty"`
	FinalSeq     uint64     `json:"final_seq,omitempty"`
	RootHash     string     `json:"root_hash,omitempty"`
	Proof        Proof      `json:"proof,omitempty"`
	Limits       []string   `json:"limits,omitempty"`
	Error        string     `json:"error,omitempty"`
	Checkpoint   Checkpoint `json:"checkpoint,omitempty"`
}

func BuildCheckpoint(sessionID string, receipts []receipt.Receipt, trustedKeys []string) (Checkpoint, error) {
	if len(receipts) == 0 {
		return Checkpoint{}, errors.New("empty receipt chain")
	}
	result := receipt.VerifyChainTrusted(receipts, trustedKeys)
	if !result.Valid {
		return Checkpoint{}, fmt.Errorf("invalid receipt chain: %s", result.Error)
	}
	if len(trustedKeys) == 0 {
		return Checkpoint{}, errors.New("trust anchor required: pass at least one trusted signer key")
	}
	root, err := receipt.ComputeTranscriptRootTrusted(sessionID, receipts, trustedKeys)
	if err != nil {
		return Checkpoint{}, fmt.Errorf("compute transcript root: %w", err)
	}
	return Checkpoint{
		SessionID:    root.SessionID,
		FinalSeq:     root.FinalSeq,
		RootHash:     root.RootHash,
		ReceiptCount: root.ReceiptCount,
		StartTime:    root.StartTime,
		EndTime:      root.EndTime,
		SignerKeys:   append([]string(nil), result.SignerKeys...),
	}, nil
}

func NewBundle(checkpoint Checkpoint, proof Proof) Bundle {
	return Bundle{
		Version:    BundleVersion,
		Backend:    proof.Backend,
		CreatedAt:  time.Now().UTC(),
		Checkpoint: checkpoint,
		Proof:      proof,
		Limits:     append([]string(nil), DefaultLimits...),
	}
}

func VerifyBundle(b Bundle, receipts []receipt.Receipt, trustedKeys []string, backend Backend) VerifyReport {
	report := VerifyReport{
		Valid:      false,
		Proof:      b.Proof,
		Limits:     append([]string(nil), DefaultLimits...),
		Checkpoint: b.Checkpoint,
	}
	if b.Version != BundleVersion {
		report.Error = fmt.Sprintf("unsupported anchor bundle version %d", b.Version)
		return report
	}
	if b.Backend != b.Proof.Backend {
		report.Error = fmt.Sprintf("anchor bundle backend %q does not match proof backend %q", b.Backend, b.Proof.Backend)
		return report
	}
	if backend == nil {
		report.Error = "anchor backend required"
		return report
	}
	computed, err := BuildCheckpoint(b.Checkpoint.SessionID, receipts, trustedKeys)
	if err != nil {
		report.Error = err.Error()
		return report
	}
	if !checkpointsEqual(computed, b.Checkpoint) {
		report.Error = "receipt chain checkpoint does not match anchor bundle"
		return report
	}
	if err := backend.Verify(b.Proof, b.Checkpoint); err != nil {
		report.Error = err.Error()
		return report
	}
	report.Valid = true
	report.Backend = b.Proof.Backend
	report.SessionID = computed.SessionID
	report.ReceiptCount = computed.ReceiptCount
	report.FinalSeq = computed.FinalSeq
	report.RootHash = computed.RootHash
	return report
}

func LoadBundle(path string) (Bundle, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return Bundle{}, fmt.Errorf("read anchor bundle: %w", err)
	}
	var b Bundle
	if err := decodeStrict(data, &b); err != nil {
		return Bundle{}, fmt.Errorf("parse anchor bundle: %w", err)
	}
	return b, nil
}

func WriteBundle(path string, b Bundle) error {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal anchor bundle: %w", err)
	}
	clean := filepath.Clean(path)
	if err := os.MkdirAll(filepath.Dir(clean), dirPermissions); err != nil {
		return fmt.Errorf("create anchor bundle directory: %w", err)
	}
	if err := os.WriteFile(clean, append(data, '\n'), filePermissions); err != nil {
		return fmt.Errorf("write anchor bundle: %w", err)
	}
	return nil
}

func checkpointsEqual(a, b Checkpoint) bool {
	if a.SessionID != b.SessionID ||
		a.FinalSeq != b.FinalSeq ||
		a.RootHash != b.RootHash ||
		a.ReceiptCount != b.ReceiptCount ||
		!a.StartTime.Equal(b.StartTime) ||
		!a.EndTime.Equal(b.EndTime) ||
		len(a.SignerKeys) != len(b.SignerKeys) {
		return false
	}
	for i := range a.SignerKeys {
		if a.SignerKeys[i] != b.SignerKeys[i] {
			return false
		}
	}
	return true
}

func decodeStrict(data []byte, dst any) error {
	if err := jsonscan.RejectDuplicateKeys(data); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("unexpected trailing JSON")
	}
	return nil
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
