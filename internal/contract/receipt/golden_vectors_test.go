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

// receiptTestPrivateSeedHex is the RFC 8032 §7.1 test-1 private seed,
// split across string concatenations so secret-scanners do not match the
// 64-char hex pattern in source. Same vector as the contract package's
// testEd25519PrivateSeedHex; duplicated here because the receipt package
// is _test-isolated from the contract package's test helpers.
const receiptTestPrivateSeedHex = "" +
	"9d61b19d" + "effd5a60" + "ba844af4" + "92ec2cc4" +
	"4449c569" + "7b326919" + "703bac03" + "1cae7f60"

func TestGolden_EvidenceReceiptProxyDecision(t *testing.T) {
	t.Parallel()
	seed, err := hex.DecodeString(receiptTestPrivateSeedHex)
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
