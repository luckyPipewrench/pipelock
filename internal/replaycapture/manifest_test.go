// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package replaycapture

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildManifest_BindsPacketAndReceipts(t *testing.T) {
	t.Parallel()

	eng := newTestEngine(t)
	outDir := t.TempDir()

	// Use a blocked scenario so the manifest carries a decisive layer and one
	// signed receipt view.
	var scenario Scenario
	for _, s := range DefaultScenarios() {
		if s.ID == "operation-aware-policy" {
			scenario = s
		}
	}

	cs, err := eng.Capture(scenario)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	res, err := AssemblePacket(cs, outDir, fixedStamp())
	if err != nil {
		t.Fatalf("AssemblePacket: %v", err)
	}

	packetBytes, err := os.ReadFile(filepath.Join(res.PacketDir, artifactPacketName))
	if err != nil {
		t.Fatalf("read packet.json: %v", err)
	}

	m := BuildManifest(cs, res, packetBytes, "v2.7.0-test")

	// Packet binding sha256 must equal the actual packet.json digest.
	want := sha256.Sum256(packetBytes)
	if m.Packet.SHA256 != hex.EncodeToString(want[:]) {
		t.Errorf("packet sha256 mismatch: %s vs %s", m.Packet.SHA256, hex.EncodeToString(want[:]))
	}
	if m.Packet.RootHash != cs.RootHash {
		t.Errorf("root hash mismatch")
	}
	if len(m.Receipts) != cs.ReceiptCount {
		t.Errorf("receipt views=%d, chain=%d", len(m.Receipts), cs.ReceiptCount)
	}
	if m.SchemaVersion != ManifestSchemaVersion {
		t.Errorf("schema version=%q", m.SchemaVersion)
	}
	if !strings.Contains(m.VerifierCommand, cs.SignerKeyHex) {
		t.Errorf("verifier command missing signer key: %q", m.VerifierCommand)
	}
	if m.CompletenessNote == "" {
		t.Errorf("completeness note must be present")
	}
	// The blocked scenario must carry its block receipt view.
	var sawBlock bool
	for _, v := range m.Receipts {
		switch v.Verdict {
		case verdictBlock:
			sawBlock = true
		}
	}
	if !sawBlock {
		t.Errorf("expected block receipt view")
	}

	// WriteManifest produces valid JSON on disk.
	if err := WriteManifest(res.PacketDir, m); err != nil {
		t.Fatalf("WriteManifest: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(res.PacketDir, artifactManifestName))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var rt Manifest
	if err := json.Unmarshal(raw, &rt); err != nil {
		t.Fatalf("manifest not valid JSON: %v", err)
	}
	if rt.ScenarioID != scenario.ID {
		t.Errorf("round-trip scenario id mismatch")
	}
}
