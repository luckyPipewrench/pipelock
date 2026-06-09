// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt_test

import (
	"errors"
	"strings"
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
	receipt.PayloadDeferOpened,
	receipt.PayloadDeferResolved,
}

func TestRegistry_HasAll16PayloadKinds(t *testing.T) {
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
		receipt.PayloadDeferOpened,
		receipt.PayloadDeferResolved,
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

func TestRegistry_ReservedDeferKindsAreKnownButNotImplemented(t *testing.T) {
	for _, kind := range []receipt.PayloadKind{receipt.PayloadDeferOpened, receipt.PayloadDeferResolved} {
		kind := kind
		t.Run(string(kind), func(t *testing.T) {
			r := validRegistryEnvelope(kind, []byte(`{}`))
			err := r.Validate()
			if !errors.Is(err, receipt.ErrPayloadKindNotImplemented) {
				t.Fatalf("expected ErrPayloadKindNotImplemented, got: %v", err)
			}
			if errors.Is(err, receipt.ErrUnknownPayloadKind) {
				t.Fatalf("reserved kind %q must not be classified as unknown", kind)
			}
		})
	}
}

func TestValidatePolicyHashGrammar(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		value   string
		wantErr error
	}{
		{name: "valid", value: validPolicyHash},
		{name: "missing", value: "", wantErr: receipt.ErrPayloadMissingField},
		{name: "missing prefix", value: strings.TrimPrefix(validPolicyHash, "sha256:"), wantErr: receipt.ErrPayloadInvalidEnum},
		{name: "short digest", value: "sha256:abc123", wantErr: receipt.ErrPayloadInvalidEnum},
		{name: "uppercase digest", value: "sha256:ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef0123456789", wantErr: receipt.ErrPayloadInvalidEnum},
		{name: "non hex", value: "sha256:" + strings.Repeat("g", 64), wantErr: receipt.ErrPayloadInvalidEnum},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := receipt.ValidatePolicyHash(tc.value)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("ValidatePolicyHash(%q) error = %v", tc.value, err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("ValidatePolicyHash(%q) error = %v, want %v", tc.value, err, tc.wantErr)
			}
		})
	}
}

func TestNormalizePolicyHash(t *testing.T) {
	t.Parallel()
	raw := strings.TrimPrefix(validPolicyHash, "sha256:")
	cases := []struct {
		name  string
		value string
		want  string
	}{
		{name: "wire form unchanged", value: validPolicyHash, want: validPolicyHash},
		{name: "raw lowercase promoted", value: raw, want: validPolicyHash},
		{name: "raw uppercase unchanged", value: strings.ToUpper(raw), want: strings.ToUpper(raw)},
		{name: "wrong length unchanged", value: "abc123", want: "abc123"},
		{name: "raw non hex unchanged", value: strings.Repeat("g", 64), want: strings.Repeat("g", 64)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := receipt.NormalizePolicyHash(tc.value); got != tc.want {
				t.Fatalf("NormalizePolicyHash(%q) = %q, want %q", tc.value, got, tc.want)
			}
		})
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
		PolicyHash:       validPolicyHash,
		Payload:          payload,
		Signature: receipt.SignatureProof{
			SignerKeyID: "receipt-key",
			KeyPurpose:  testKeyPurposeForPayload(kind),
			Algorithm:   "ed25519",
			Signature:   validReceiptSignature,
		},
	}
}
