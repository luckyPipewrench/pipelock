// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package replaycapture

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
	auditpacket "github.com/luckyPipewrench/pipelock/sdk/audit-packet"
)

// VerifyPacketDir reproduces the shipped `pipelock-verifier audit-packet` checks
// at library level: it validates the packet against the v0 schema, re-extracts
// the signed receipt chain from the packet's evidence file, verifies the chain
// against keyHex, and cross-checks the packet summary against the chain. It is
// the internal gate the rig runs on every packet before publish; the separate
// binary test proves the same packet verifies from a clean machine.
func VerifyPacketDir(dir, keyHex string) error {
	packetPath := filepath.Join(dir, "packet.json")
	data, err := os.ReadFile(filepath.Clean(packetPath))
	if err != nil {
		return fmt.Errorf("reading packet.json: %w", err)
	}
	var pkt auditpacket.Packet
	if err := json.Unmarshal(data, &pkt); err != nil {
		return fmt.Errorf("parsing packet.json: %w", err)
	}
	if err := pkt.Validate(); err != nil {
		return fmt.Errorf("packet schema: %w", err)
	}

	// The evidence path comes from packet.json. Packet.Validate already rejects
	// "../" artifact paths; this is defense-in-depth at the file-read trust
	// boundary so a path-traversal value can never escape the packet directory.
	if !filepath.IsLocal(pkt.Artifacts.Evidence) {
		return fmt.Errorf("evidence path %q is not local to the packet directory", pkt.Artifacts.Evidence)
	}
	evidencePath := filepath.Join(dir, pkt.Artifacts.Evidence)
	evidence, err := os.ReadFile(filepath.Clean(evidencePath))
	if err != nil {
		return fmt.Errorf("extracting evidence: %w", err)
	}
	return verifyPacket(pkt, evidence, keyHex)
}

// VerifyPacketBytes performs the same packet schema, receipt-chain, and summary
// cross-checks as VerifyPacketDir using in-memory packet.json and evidence
// bytes. It is the browser/WASM verifier path: no directory or filesystem is
// required.
func VerifyPacketBytes(packetJSON, evidenceJSONL []byte, keyHex string) error {
	var pkt auditpacket.Packet
	if err := json.Unmarshal(packetJSON, &pkt); err != nil {
		return fmt.Errorf("parsing packet.json: %w", err)
	}
	if err := pkt.Validate(); err != nil {
		return fmt.Errorf("packet schema: %w", err)
	}
	if err := validateInMemoryPacketArtifacts(pkt); err != nil {
		return err
	}
	return verifyPacket(pkt, evidenceJSONL, keyHex)
}

func validateInMemoryPacketArtifacts(pkt auditpacket.Packet) error {
	const (
		expectedPacketArtifact   = "packet.json"
		expectedEvidenceArtifact = "evidence.jsonl"
	)
	if !filepath.IsLocal(pkt.Artifacts.Evidence) {
		return fmt.Errorf("evidence path %q is not local to the packet directory", pkt.Artifacts.Evidence)
	}
	if pkt.Artifacts.Packet != expectedPacketArtifact {
		return fmt.Errorf("packet artifact path %q does not match bundled %s", pkt.Artifacts.Packet, expectedPacketArtifact)
	}
	if pkt.Artifacts.Evidence != expectedEvidenceArtifact {
		return fmt.Errorf("evidence artifact path %q does not match bundled %s", pkt.Artifacts.Evidence, expectedEvidenceArtifact)
	}
	return nil
}

func verifyPacket(pkt auditpacket.Packet, evidenceJSONL []byte, keyHex string) error {
	receipts, err := receipt.ExtractReceiptsBytes(evidenceJSONL)
	if err != nil {
		return fmt.Errorf("extracting evidence: %w", err)
	}
	key := keyHex
	if key == "" {
		key = pkt.Verifier.SignerKey
	}
	chain := receipt.VerifyChain(receipts, key)
	if !chain.Valid {
		return fmt.Errorf("chain verification failed: %s", chain.Error)
	}
	if pkt.Verifier.Verdict != auditpacket.VerdictValid || !pkt.Verifier.Trusted {
		return fmt.Errorf("packet not trusted: verdict=%s trusted=%t", pkt.Verifier.Verdict, pkt.Verifier.Trusted)
	}

	if pkt.Summary.ReceiptCount != len(receipts) {
		return fmt.Errorf("receipt_count mismatch: packet=%d chain=%d", pkt.Summary.ReceiptCount, len(receipts))
	}
	if pkt.Verifier.RootHash != "" && pkt.Verifier.RootHash != chain.RootHash {
		return fmt.Errorf("root_hash mismatch: packet=%s chain=%s", pkt.Verifier.RootHash, chain.RootHash)
	}
	if pkt.Verifier.FinalSeq != 0 && (pkt.Verifier.FinalSeq < 0 || uint64(pkt.Verifier.FinalSeq) != chain.FinalSeq) {
		return fmt.Errorf("final_seq mismatch: packet=%d chain=%d", pkt.Verifier.FinalSeq, chain.FinalSeq)
	}
	if err := crossCheckTotals(pkt.Summary, receipts); err != nil {
		return err
	}
	return nil
}

// crossCheckTotals confirms the packet's verdict buckets reconcile with the
// chain — the same reconciliation the shipped verifier enforces.
func crossCheckTotals(summary auditpacket.Summary, receipts []receipt.Receipt) error {
	var recomputed auditpacket.Totals
	for _, r := range receipts {
		addVerifyVerdict(&recomputed, r.ActionRecord.Verdict)
	}
	if recomputed != summary.Totals {
		return fmt.Errorf("totals mismatch: packet=%+v chain=%+v", summary.Totals, recomputed)
	}
	return nil
}

func addVerifyVerdict(t *auditpacket.Totals, verdict string) {
	switch verdict {
	case "allow":
		t.Allow++
	case "block":
		t.Block++
	case "warn":
		t.Warn++
	case "ask":
		t.Ask++
	case "strip":
		t.Strip++
	case "forward":
		t.Forward++
	case "redirect":
		t.Redirect++
	default:
		t.Other++
	}
}
