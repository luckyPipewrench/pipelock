// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/replaycapture"
)

// AssembleFromEvidenceWithScenario is the same as AssembleFromEvidence but
// accepts a full Scenario so the assembled CapturedScenario carries the real
// Title, Category, ExpectedVerdict, etc. This is needed by the live-run path
// where the caller knows the scenario and BuildManifest needs the full fields.
// When sc is nil the function falls back to deriving a bare Scenario from the
// evidence path (identical to AssembleFromEvidence).
func AssembleFromEvidenceWithScenario(evidenceFile, pubKeyHex string, sc *replaycapture.Scenario, outDir string, generatedAt time.Time) (*replaycapture.AssembleResult, error) {
	return assembleFromEvidenceCore(evidenceFile, pubKeyHex, sc, outDir, generatedAt)
}

// AssembleFromEvidence turns a live evidence JSONL file (written by a real
// Pipelock proxy with receipt emission) into a verified Audit Packet directory.
// This is the shared seam between the live-demo runner and the shipped
// replaycapture assembly pipeline.
//
// It reconstructs a replaycapture.CapturedScenario from the evidence file by
// extracting receipts, verifying the chain, and populating the fields that
// AssemblePacket/BuildManifest/WriteManifest need. The scenario ID is derived
// from the evidence file's parent directory name (matching the convention that
// Engine.Capture writes evidence into <workDir>/<scenarioID>/).
//
// Constraint: the Scenario field of the reconstructed CapturedScenario carries
// only the ID (derived from the evidence path). Fields like Title, Category,
// ExpectedVerdict, etc. are empty because they are not recoverable from the
// evidence alone. AssemblePacket uses only Scenario.ID; callers that also need
// BuildManifest must supply the full Scenario separately.
func AssembleFromEvidence(evidenceFile, pubKeyHex, outDir string, generatedAt time.Time) (*replaycapture.AssembleResult, error) {
	return assembleFromEvidenceCore(evidenceFile, pubKeyHex, nil, outDir, generatedAt)
}

func assembleFromEvidenceCore(evidenceFile, pubKeyHex string, sc *replaycapture.Scenario, outDir string, generatedAt time.Time) (*replaycapture.AssembleResult, error) {
	cleanPath := filepath.Clean(evidenceFile)

	if _, err := os.Stat(cleanPath); err != nil {
		return nil, fmt.Errorf("evidence file: %w", err)
	}

	receipts, err := receipt.ExtractReceipts(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("extract receipts: %w", err)
	}
	if len(receipts) == 0 {
		return nil, fmt.Errorf("no receipts in %s", cleanPath)
	}

	chain := receipt.VerifyChain(receipts, pubKeyHex)
	if !chain.Valid {
		return nil, fmt.Errorf("chain verification failed: %s", chain.Error)
	}

	// Use the caller-supplied scenario when available; otherwise derive a
	// bare Scenario from the evidence file's parent directory name.
	var scenario replaycapture.Scenario
	if sc != nil {
		scenario = *sc
	} else {
		scenarioID := filepath.Base(filepath.Dir(cleanPath))
		if scenarioID == "" || scenarioID == "." || scenarioID == ".." || scenarioID == "/" {
			scenarioID = "live-evidence"
		}
		scenario = replaycapture.Scenario{ID: scenarioID}
	}

	// Extract policy hash from the first receipt (all receipts in a single
	// capture share the same policy hash).
	policyHash := receipts[0].ActionRecord.PolicyHash

	cs := &replaycapture.CapturedScenario{
		Scenario:     scenario,
		Receipts:     receipts,
		EvidenceFile: cleanPath,
		SignerKeyHex: pubKeyHex,
		PolicyHash:   policyHash,
		RootHash:     chain.RootHash,
		FinalSeq:     chain.FinalSeq,
		ReceiptCount: len(receipts),
		ChainResult:  chain,
	}

	result, err := replaycapture.AssemblePacket(cs, outDir, generatedAt)
	if err != nil {
		return nil, fmt.Errorf("assemble packet: %w", err)
	}

	// Read the written packet.json so BuildManifest can compute the binding
	// SHA-256 over the exact bytes on disk.
	packetPath := filepath.Join(result.PacketDir, "packet.json")
	packetBytes, err := os.ReadFile(filepath.Clean(packetPath))
	if err != nil {
		return nil, fmt.Errorf("read packet.json for manifest binding: %w", err)
	}

	manifest := replaycapture.BuildManifest(cs, result, packetBytes, "")
	if err := replaycapture.WriteManifest(result.PacketDir, manifest); err != nil {
		return nil, fmt.Errorf("write manifest: %w", err)
	}

	return result, nil
}
