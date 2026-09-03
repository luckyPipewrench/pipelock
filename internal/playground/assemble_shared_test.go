// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/playground"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
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

// TestAssembleSessionOwnerFromEvidence_RealHostKeepsValidChain covers the
// production evidence-file seam with an intact signed receipt, rather than
// changing an in-memory receipt after capture. The target is evidence only;
// this test never contacts it.
func TestAssembleSessionOwnerFromEvidence_RealHostKeepsValidChain(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pubKeyHex := hex.EncodeToString(pub)
	stamp := time.Date(2026, time.September, 3, 12, 0, 0, 0, time.UTC)

	r, err := receipt.Sign(receipt.ActionRecord{
		Version:         receipt.ActionRecordVersion,
		ActionID:        "visitor-real-host-receipt",
		ActionType:      receipt.ActionWrite,
		Principal:       "pipelock-lab",
		Actor:           "lab-agent",
		Timestamp:       stamp,
		Target:          "https://sts.amazonaws.com/",
		SideEffectClass: receipt.SideEffectExternalWrite,
		Reversibility:   receipt.ReversibilityUnknown,
		PolicyHash:      "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Verdict:         "block",
		Transport:       "forward",
		Method:          "POST",
		Layer:           "core_dlp",
		ChainPrevHash:   receipt.GenesisHash,
		ChainSeq:        0,
	}, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	evidenceDir := filepath.Join(t.TempDir(), "visitor-real-host")
	if err := os.MkdirAll(evidenceDir, 0o750); err != nil {
		t.Fatalf("MkdirAll evidence: %v", err)
	}
	evidenceFile := filepath.Join(evidenceDir, "evidence.jsonl")
	entry := recorder.Entry{
		Version:   recorder.EntryVersion,
		Sequence:  0,
		Timestamp: stamp,
		SessionID: "visitor-session",
		Type:      "action_receipt",
		EventKind: "write",
		Transport: "forward",
		Summary:   "signed visitor receipt",
		Detail:    r,
		PrevHash:  recorder.GenesisHash,
	}
	entry.Hash = recorder.ComputeHash(entry)
	line, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("Marshal evidence entry: %v", err)
	}
	if err := os.WriteFile(evidenceFile, append(line, '\n'), 0o600); err != nil {
		t.Fatalf("WriteFile evidence: %v", err)
	}

	// The same valid signed evidence remains unpublishable to the gallery.
	if _, err := playground.AssembleFromEvidence(evidenceFile, pubKeyHex, t.TempDir(), stamp); err == nil || !strings.Contains(err.Error(), "allowlist") {
		t.Fatalf("gallery assembly error = %v, want public-safe allowlist refusal", err)
	}

	result, err := playground.AssembleSessionOwnerFromEvidence(
		evidenceFile,
		pubKeyHex,
		&replaycapture.Scenario{ID: "visitor-real-host"},
		t.TempDir(),
		stamp,
	)
	if err != nil {
		t.Fatalf("AssembleSessionOwnerFromEvidence: %v", err)
	}
	if err := replaycapture.VerifyPacketDir(result.PacketDir, pubKeyHex); err != nil {
		t.Fatalf("VerifyPacketDir: %v", err)
	}
	if got, want := result.Packet.Summary.DomainsTouched, []string{"sts.amazonaws.com"}; len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("domains_touched = %v, want %v", got, want)
	}
}
