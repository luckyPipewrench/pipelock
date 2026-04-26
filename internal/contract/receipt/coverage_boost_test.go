// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/contract/receipt"
)

// Hits the empty/null guard in decodeStrict.

func TestDecodeStrict_RejectsEmptyPayload(t *testing.T) {
	t.Parallel()
	err := callValidator(t, receipt.PayloadProxyDecision, json.RawMessage(""))
	if err == nil {
		t.Error("expected error for empty payload, got nil")
	}
}

func TestDecodeStrict_RejectsNullPayload(t *testing.T) {
	t.Parallel()
	err := callValidator(t, receipt.PayloadProxyDecision, json.RawMessage("null"))
	if err == nil {
		t.Error("expected error for null payload, got nil")
	}
}

// validateSignatureProof branches: bad hex, short signature.

func TestEvidenceReceipt_Validate_RejectsBadSignatureHex(t *testing.T) {
	t.Parallel()
	r := receipt.EvidenceReceipt{
		RecordType:     receipt.RecordTypeEvidenceV2,
		ReceiptVersion: 2,
		PayloadKind:    receipt.PayloadProxyDecision,
		EventID:        "01900000-0000-7000-8000-000000000001",
		Payload: json.RawMessage(`{"action_type":"connect","target":"x.com","verdict":"allow",
			"transport":"forward","policy_sources":["a"],"winning_source":"a"}`),
		Signature: receipt.SignatureProof{
			SignerKeyID: "test-key",
			KeyPurpose:  "receipt-signing",
			Algorithm:   "ed25519",
			Signature:   "ed25519:notvalidhex!!",
		},
	}
	if err := r.Validate(); err == nil {
		t.Error("expected error for bad signature hex, got nil")
	}
}

func TestEvidenceReceipt_Validate_RejectsShortSignature(t *testing.T) {
	t.Parallel()
	r := receipt.EvidenceReceipt{
		RecordType:     receipt.RecordTypeEvidenceV2,
		ReceiptVersion: 2,
		PayloadKind:    receipt.PayloadProxyDecision,
		EventID:        "01900000-0000-7000-8000-000000000001",
		Payload: json.RawMessage(`{"action_type":"connect","target":"x.com","verdict":"allow",
			"transport":"forward","policy_sources":["a"],"winning_source":"a"}`),
		Signature: receipt.SignatureProof{
			SignerKeyID: "test-key",
			KeyPurpose:  "receipt-signing",
			Algorithm:   "ed25519",
			Signature:   "ed25519:0011", // 2 bytes, not 64
		},
	}
	if err := r.Validate(); !errors.Is(err, receipt.ErrPayloadInvalidEnum) {
		t.Errorf("got %v, want ErrPayloadInvalidEnum for short signature", err)
	}
}

func TestEvidenceReceipt_Validate_RejectsMissingSignerKeyID(t *testing.T) {
	t.Parallel()
	r := receipt.EvidenceReceipt{
		RecordType:     receipt.RecordTypeEvidenceV2,
		ReceiptVersion: 2,
		PayloadKind:    receipt.PayloadProxyDecision,
		EventID:        "01900000-0000-7000-8000-000000000001",
		Payload: json.RawMessage(`{"action_type":"connect","target":"x.com","verdict":"allow",
			"transport":"forward","policy_sources":["a"],"winning_source":"a"}`),
		Signature: receipt.SignatureProof{
			SignerKeyID: "",
			KeyPurpose:  "receipt-signing",
			Algorithm:   "ed25519",
			Signature:   "ed25519:" + "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		},
	}
	if err := r.Validate(); !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Errorf("got %v, want ErrPayloadMissingField for missing signer_key_id", err)
	}
}
