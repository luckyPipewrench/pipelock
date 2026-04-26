// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGolden_EvidenceReceiptProxyDecision(t *testing.T) {
	t.Parallel()
	// Load the RFC 8032 §7.1 test-1 key pair from the shared contract testdata fixture.
	keysPath := filepath.Join("..", "testdata", "golden", "ed25519_test_keys.json")
	keys, err := os.ReadFile(filepath.Clean(keysPath))
	if err != nil {
		t.Fatalf("read keys: %v", err)
	}
	var k struct {
		PrivateKeyHex string `json:"private_key_hex"`
	}
	if err := json.Unmarshal(keys, &k); err != nil {
		t.Fatalf("unmarshal keys: %v", err)
	}
	seed, err := hex.DecodeString(k.PrivateKeyHex)
	if err != nil {
		t.Fatalf("decode seed: %v", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)

	payload := json.RawMessage(`{"action_type":"connect","target":"example.com","verdict":"allow","transport":"forward","policy_sources":["test"],"winning_source":"test"}`)
	r := EvidenceReceipt{
		RecordType:     RecordTypeEvidenceV2,
		ReceiptVersion: 2,
		PayloadKind:    PayloadProxyDecision,
		EventID:        "01F8MECHZX3TBDSZ7XRADM79XV",
		Timestamp:      time.Date(2026, 4, 25, 22, 0, 0, 0, time.UTC),
		ChainSeq:       1,
		ChainPrevHash:  "sha256:0",
		Payload:        payload,
	}
	preimage, err := r.SignablePreimage()
	if err != nil {
		t.Fatalf("preimage: %v", err)
	}
	r.Signature = SignatureProof{
		SignerKeyID: "receipt-signing-test",
		KeyPurpose:  "receipt-signing",
		Algorithm:   "ed25519",
		Signature:   "ed25519:" + hex.EncodeToString(ed25519.Sign(priv, preimage)),
	}

	body, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		t.Fatalf("marshal receipt: %v", err)
	}
	body = append(body, '\n')

	const goldenPath = "../testdata/golden/valid_evidence_receipt_proxy_decision.json"
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(filepath.Clean(goldenPath), body, 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		return
	}
	got, err := os.ReadFile(filepath.Clean(goldenPath))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(body) {
		t.Errorf("drift in evidence_receipt golden\n--- expected\n%s\n--- got\n%s", got, body)
	}
}
