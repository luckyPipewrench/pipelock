// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt_test

import (
	"errors"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/contract/receipt"
)

// allPayloadKinds enumerates every declared PayloadKind constant.
var allPayloadKinds = []receipt.PayloadKind{
	receipt.PayloadProxyDecision,
	receipt.PayloadProxyDecisionWithSpans,
	receipt.PayloadContractRatified,
	receipt.PayloadContractPromoteIntent,
	receipt.PayloadContractPromoteCommitted,
	receipt.PayloadContractRollbackAuthorized,
	receipt.PayloadContractRollbackCommitted,
	receipt.PayloadContractDemoted,
	receipt.PayloadContractExpired,
	receipt.PayloadContractDrift,
	receipt.PayloadShadowDelta,
	receipt.PayloadOpportunityMissing,
	receipt.PayloadKeyRotation,
	receipt.PayloadContractRedactionRequest,
}

func TestRegistry_HasAll14PayloadKinds(t *testing.T) {
	expectedKinds := []receipt.PayloadKind{
		receipt.PayloadProxyDecision,
		receipt.PayloadProxyDecisionWithSpans,
		receipt.PayloadContractRatified,
		receipt.PayloadContractPromoteIntent,
		receipt.PayloadContractPromoteCommitted,
		receipt.PayloadContractRollbackAuthorized,
		receipt.PayloadContractRollbackCommitted,
		receipt.PayloadContractDemoted,
		receipt.PayloadContractExpired,
		receipt.PayloadContractDrift,
		receipt.PayloadShadowDelta,
		receipt.PayloadOpportunityMissing,
		receipt.PayloadKeyRotation,
		receipt.PayloadContractRedactionRequest,
	}
	if len(allPayloadKinds) != len(expectedKinds) {
		t.Fatalf("expected %d payload kinds in test table, got %d", len(expectedKinds), len(allPayloadKinds))
	}
	seen := make(map[receipt.PayloadKind]struct{}, len(allPayloadKinds))
	for _, kind := range allPayloadKinds {
		if _, ok := seen[kind]; ok {
			t.Fatalf("duplicate payload kind in test table: %q", kind)
		}
		seen[kind] = struct{}{}
	}
	for _, kind := range expectedKinds {
		if _, ok := seen[kind]; !ok {
			t.Fatalf("missing payload kind in test table: %q", kind)
		}
	}
	for _, kind := range allPayloadKinds {
		kind := kind
		t.Run(string(kind), func(t *testing.T) {
			// A valid envelope but empty payload: we expect a payload validation
			// error (missing field), NOT ErrUnknownPayloadKind.
			r := validRegistryEnvelope(kind, []byte(`{}`))
			err := r.Validate()
			if errors.Is(err, receipt.ErrUnknownPayloadKind) {
				t.Fatalf("kind %q has no registered validator", kind)
			}
		})
	}
}

func TestRegistry_DispatchesToCorrectValidator_ProxyDecision(t *testing.T) {
	// Empty payload → missing required field from proxy_decision validator.
	r := validRegistryEnvelope(receipt.PayloadProxyDecision, []byte(`{}`))
	err := r.Validate()
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField from proxy_decision dispatch, got: %v", err)
	}
}

func TestRegistry_DispatchesToCorrectValidator_ContractRatified(t *testing.T) {
	r := validRegistryEnvelope(receipt.PayloadContractRatified, []byte(`{}`))
	err := r.Validate()
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField from contract_ratified dispatch, got: %v", err)
	}
}

func TestRegistry_DispatchesToCorrectValidator_KeyRotation(t *testing.T) {
	r := validRegistryEnvelope(receipt.PayloadKeyRotation, []byte(`{}`))
	err := r.Validate()
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField from key_rotation dispatch, got: %v", err)
	}
}

func TestRegistry_UnknownKindReturnsError(t *testing.T) {
	r := validRegistryEnvelope("totally_unknown", []byte(`{}`))
	err := r.Validate()
	if !errors.Is(err, receipt.ErrUnknownPayloadKind) {
		t.Fatalf("expected ErrUnknownPayloadKind, got: %v", err)
	}
}

func validRegistryEnvelope(kind receipt.PayloadKind, payload []byte) receipt.EvidenceReceipt {
	return receipt.EvidenceReceipt{
		RecordType:       receipt.RecordTypeEvidenceV2,
		ReceiptVersion:   2,
		PayloadKind:      kind,
		Canonicalization: receipt.DefaultCanonicalizationProfile(),
		Crit:             receipt.CritForPayloadKind(kind),
		EventID:          "01900000-0000-7000-8000-000000000002",
		Timestamp:        time.Now(),
		Payload:          payload,
		Signature: receipt.SignatureProof{
			SignerKeyID: "receipt-key",
			KeyPurpose:  testKeyPurposeForPayload(kind),
			Algorithm:   "ed25519",
			Signature:   validReceiptSignature,
		},
	}
}
