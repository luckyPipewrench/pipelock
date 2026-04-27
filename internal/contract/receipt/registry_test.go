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

func TestRegistry_HasAll13PayloadKinds(t *testing.T) {
	if len(allPayloadKinds) != 13 {
		t.Fatalf("expected 13 payload kinds in test table, got %d", len(allPayloadKinds))
	}
	for _, kind := range allPayloadKinds {
		kind := kind
		t.Run(string(kind), func(t *testing.T) {
			// A valid envelope but empty payload: we expect a payload validation
			// error (missing field), NOT ErrUnknownPayloadKind.
			r := receipt.EvidenceReceipt{
				RecordType:     receipt.RecordTypeEvidenceV2,
				ReceiptVersion: 2,
				PayloadKind:    kind,
				EventID:        "01900000-0000-7000-8000-000000000002",
				Payload:        []byte(`{}`),
			}
			err := r.Validate()
			if errors.Is(err, receipt.ErrUnknownPayloadKind) {
				t.Fatalf("kind %q has no registered validator", kind)
			}
		})
	}
}

func TestRegistry_DispatchesToCorrectValidator_ProxyDecision(t *testing.T) {
	// Empty payload → missing required field from proxy_decision validator.
	r := receipt.EvidenceReceipt{
		RecordType:     receipt.RecordTypeEvidenceV2,
		ReceiptVersion: 2,
		PayloadKind:    receipt.PayloadProxyDecision,
		EventID:        "01900000-0000-7000-8000-000000000003",
		Payload:        []byte(`{}`),
	}
	err := r.Validate()
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField from proxy_decision dispatch, got: %v", err)
	}
}

func TestRegistry_DispatchesToCorrectValidator_ContractRatified(t *testing.T) {
	r := receipt.EvidenceReceipt{
		RecordType:     receipt.RecordTypeEvidenceV2,
		ReceiptVersion: 2,
		PayloadKind:    receipt.PayloadContractRatified,
		EventID:        "01900000-0000-7000-8000-000000000004",
		Payload:        []byte(`{}`),
	}
	err := r.Validate()
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField from contract_ratified dispatch, got: %v", err)
	}
}

func TestRegistry_DispatchesToCorrectValidator_KeyRotation(t *testing.T) {
	r := receipt.EvidenceReceipt{
		RecordType:     receipt.RecordTypeEvidenceV2,
		ReceiptVersion: 2,
		PayloadKind:    receipt.PayloadKeyRotation,
		EventID:        "01900000-0000-7000-8000-000000000005",
		Payload:        []byte(`{}`),
	}
	err := r.Validate()
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField from key_rotation dispatch, got: %v", err)
	}
}

func TestRegistry_UnknownKindReturnsError(t *testing.T) {
	r := receipt.EvidenceReceipt{
		RecordType:     receipt.RecordTypeEvidenceV2,
		ReceiptVersion: 2,
		PayloadKind:    "totally_unknown",
		EventID:        "01900000-0000-7000-8000-000000000006",
		Timestamp:      time.Now(),
		Payload:        []byte(`{}`),
	}
	err := r.Validate()
	if !errors.Is(err, receipt.ErrUnknownPayloadKind) {
		t.Fatalf("expected ErrUnknownPayloadKind, got: %v", err)
	}
}
