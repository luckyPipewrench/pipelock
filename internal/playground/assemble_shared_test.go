// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground_test

import (
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/playground"
	"github.com/luckyPipewrench/pipelock/internal/replaycapture"
)

func TestAssembleFromEvidence_ProducesVerifiablePacket(t *testing.T) {
	t.Parallel()

	// Use a real scenario from DefaultScenarios (the AWS-key exfil one) driven
	// through a real proxy to produce genuine signed evidence.
	scenarios := replaycapture.DefaultScenarios()
	var exfilScenario replaycapture.Scenario
	for _, s := range scenarios {
		if s.ID == "secret-exfil-url-blocked" {
			exfilScenario = s
			break
		}
	}
	if exfilScenario.ID == "" {
		t.Fatal("secret-exfil-url-blocked scenario not found in DefaultScenarios()")
	}

	// Capture: drive the scenario through a real proxy, producing signed
	// receipts in an evidence JSONL file.
	engine, err := replaycapture.NewEngine(t.TempDir())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	captured, err := engine.Capture(exfilScenario)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}

	// AssembleFromEvidence: the shared helper under test. It takes the raw
	// evidence file + the signer public key and produces a verified Audit
	// Packet directory.
	outDir := t.TempDir()
	generatedAt := time.Now().UTC()
	result, err := playground.AssembleFromEvidence(
		captured.EvidenceFile,
		engine.PublicKeyHex(),
		outDir,
		generatedAt,
	)
	if err != nil {
		t.Fatalf("AssembleFromEvidence: %v", err)
	}

	if result.PacketDir == "" {
		t.Fatal("AssembleResult.PacketDir is empty")
	}
	if result.Receipts == 0 {
		t.Fatal("AssembleResult.Receipts is zero")
	}

	// Verify: the produced packet directory must pass the same verification
	// that the shipped pipelock-verifier uses.
	if err := replaycapture.VerifyPacketDir(result.PacketDir, engine.PublicKeyHex()); err != nil {
		t.Fatalf("VerifyPacketDir: %v", err)
	}
}
