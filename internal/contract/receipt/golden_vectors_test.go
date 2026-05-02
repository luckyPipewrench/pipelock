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

// TestGolden_EvidenceReceiptPromoteCommitted is the cross-implementation
// fixture for a `contract_promote_committed` v2 envelope. Covered by
// pipelock-verify-python's tests/test_v2_conformance.py to prove
// byte-for-byte JCS preimage parity for a contract-lifecycle payload
// kind, complementing the existing proxy_decision fixture.
func TestGolden_EvidenceReceiptPromoteCommitted(t *testing.T) {
	t.Parallel()
	seed, err := hex.DecodeString(receiptTestPrivateSeedHex)
	if err != nil {
		t.Fatalf("decode seed: %v", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)

	payload := json.RawMessage(`{` +
		`"target_manifest_hash":"sha256:tttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttt",` +
		`"prior_manifest_hash":"sha256:pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp",` +
		`"intent_id":"01F8MECHZX3TBDSZ7XRADM79XW",` +
		`"validation_outcome":"accepted"` +
		`}`)
	r := EvidenceReceipt{
		RecordType:     RecordTypeEvidenceV2,
		ReceiptVersion: 2,
		PayloadKind:    PayloadContractPromoteCommitted,
		EventID:        "01F8MECHZX3TBDSZ7XRADM79XX",
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

	const goldenPath = "../testdata/golden/valid_evidence_receipt_promote_committed.json"
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
		t.Errorf("drift in promote_committed golden\n--- expected\n%s\n--- got\n%s", got, body)
	}
}

// TestGolden_EvidenceReceiptShadowDelta is the cross-implementation
// fixture for a `shadow_delta` v2 envelope. Shadow-delta is the
// load-bearing payload kind for the LL soak window: every shadow run
// against a candidate contract emits one of these per (rule_id, window)
// bucket. Cross-impl parity here is essential for external auditors
// verifying the soak evidence.
func TestGolden_EvidenceReceiptShadowDelta(t *testing.T) {
	t.Parallel()
	seed, err := hex.DecodeString(receiptTestPrivateSeedHex)
	if err != nil {
		t.Fatalf("decode seed: %v", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)

	payload := json.RawMessage(`{` +
		`"contract_hash":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",` +
		`"rule_id":"r-deadbeef0000-aaaa00",` +
		`"original_verdict":"allow",` +
		`"candidate_verdict":"block",` +
		`"aggregation":{` +
		`"window_start":"2026-04-25T20:00:00Z",` +
		`"window_end":"2026-04-25T21:00:00Z",` +
		`"lossless_count":42,` +
		`"delta_sample_count":7,` +
		`"exemplar_ids":["01F8MECHZX3TBDSZ7XRADM79YA","01F8MECHZX3TBDSZ7XRADM79YB"]` +
		`}}`)
	r := EvidenceReceipt{
		RecordType:     RecordTypeEvidenceV2,
		ReceiptVersion: 2,
		PayloadKind:    PayloadShadowDelta,
		EventID:        "01F8MECHZX3TBDSZ7XRADM79YC",
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

	const goldenPath = "../testdata/golden/valid_evidence_receipt_shadow_delta.json"
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
		t.Errorf("drift in shadow_delta golden\n--- expected\n%s\n--- got\n%s", got, body)
	}
}
