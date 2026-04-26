// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"errors"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/contract"
)

func TestKeyPurpose_String(t *testing.T) {
	tests := []struct {
		name     string
		purpose  KeyPurpose
		expected string
	}{
		{"receipt-signing", PurposeReceiptSigning, "receipt-signing"},
		{"contract-compile-signing", PurposeContractCompileSigning, "contract-compile-signing"},
		{"contract-activation-signing", PurposeContractActivationSigning, "contract-activation-signing"},
		{"rules-official-signing", PurposeRulesOfficialSigning, "rules-official-signing"},
		{"roster-root", PurposeRosterRoot, "roster-root"},
		{"recovery-root", PurposeRecoveryRoot, "recovery-root"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.purpose.String(); got != tt.expected {
				t.Errorf("String() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestKeyPurpose_Validate(t *testing.T) {
	t.Run("valid_purposes", func(t *testing.T) {
		for _, p := range KnownPurposes() {
			t.Run(string(p), func(t *testing.T) {
				if err := p.Validate(); err != nil {
					t.Errorf("Validate() returned error for valid purpose %q: %v", p, err)
				}
			})
		}
	})

	t.Run("invalid_purposes", func(t *testing.T) {
		invalid := []struct {
			name  string
			value KeyPurpose
		}{
			{"empty", KeyPurpose("")},
			{"partial", KeyPurpose("signing")},
			{"wrong_case", KeyPurpose("RECEIPT-SIGNING")},
			{"typo", KeyPurpose("receipt_signing")},
			{"unknown", KeyPurpose("audit-signing")},
		}
		for _, tt := range invalid {
			t.Run(tt.name, func(t *testing.T) {
				err := tt.value.Validate()
				if err == nil {
					t.Fatalf("Validate() returned nil for invalid purpose %q", tt.value)
				}
				if !errors.Is(err, ErrUnknownKeyPurpose) {
					t.Errorf("error does not wrap ErrUnknownKeyPurpose: %v", err)
				}
			})
		}
	})
}

func TestKeyPurpose_IsRoot(t *testing.T) {
	tests := []struct {
		purpose  KeyPurpose
		expected bool
	}{
		{PurposeReceiptSigning, false},
		{PurposeContractCompileSigning, false},
		{PurposeContractActivationSigning, false},
		{PurposeRulesOfficialSigning, false},
		{PurposeRosterRoot, true},
		{PurposeRecoveryRoot, true},
		{KeyPurpose("unknown"), false},
	}
	for _, tt := range tests {
		t.Run(string(tt.purpose), func(t *testing.T) {
			if got := tt.purpose.IsRoot(); got != tt.expected {
				t.Errorf("IsRoot() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestKeyPurpose_IsActivationAuthority(t *testing.T) {
	tests := []struct {
		purpose  KeyPurpose
		expected bool
	}{
		{PurposeReceiptSigning, false},
		{PurposeContractCompileSigning, false},
		{PurposeContractActivationSigning, true},
		{PurposeRulesOfficialSigning, false},
		{PurposeRosterRoot, false},
		{PurposeRecoveryRoot, false},
		{KeyPurpose("unknown"), false},
	}
	for _, tt := range tests {
		t.Run(string(tt.purpose), func(t *testing.T) {
			if got := tt.purpose.IsActivationAuthority(); got != tt.expected {
				t.Errorf("IsActivationAuthority() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestKeyPurpose_IsRuntimeReceipt(t *testing.T) {
	tests := []struct {
		purpose  KeyPurpose
		expected bool
	}{
		{PurposeReceiptSigning, true},
		{PurposeContractCompileSigning, false},
		{PurposeContractActivationSigning, false},
		{PurposeRulesOfficialSigning, false},
		{PurposeRosterRoot, false},
		{PurposeRecoveryRoot, false},
		{KeyPurpose("unknown"), false},
	}
	for _, tt := range tests {
		t.Run(string(tt.purpose), func(t *testing.T) {
			if got := tt.purpose.IsRuntimeReceipt(); got != tt.expected {
				t.Errorf("IsRuntimeReceipt() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestKeyPurpose_IsCompileTime(t *testing.T) {
	tests := []struct {
		purpose  KeyPurpose
		expected bool
	}{
		{PurposeReceiptSigning, false},
		{PurposeContractCompileSigning, true},
		{PurposeContractActivationSigning, false},
		{PurposeRulesOfficialSigning, false},
		{PurposeRosterRoot, false},
		{PurposeRecoveryRoot, false},
		{KeyPurpose("unknown"), false},
	}
	for _, tt := range tests {
		t.Run(string(tt.purpose), func(t *testing.T) {
			if got := tt.purpose.IsCompileTime(); got != tt.expected {
				t.Errorf("IsCompileTime() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestKnownPurposes(t *testing.T) {
	purposes := KnownPurposes()

	t.Run("length", func(t *testing.T) {
		if len(purposes) != 6 {
			t.Fatalf("KnownPurposes() returned %d elements, want 6", len(purposes))
		}
	})

	t.Run("order", func(t *testing.T) {
		expected := []KeyPurpose{
			PurposeReceiptSigning,
			PurposeContractCompileSigning,
			PurposeContractActivationSigning,
			PurposeRulesOfficialSigning,
			PurposeRosterRoot,
			PurposeRecoveryRoot,
		}
		for i, p := range purposes {
			if p != expected[i] {
				t.Errorf("index %d: got %q, want %q", i, p, expected[i])
			}
		}
	})

	t.Run("fresh_slice", func(t *testing.T) {
		a := KnownPurposes()
		b := KnownPurposes()
		// Mutating one must not affect the other.
		a[0] = KeyPurpose("mutated")
		if b[0] == KeyPurpose("mutated") {
			t.Fatal("KnownPurposes() returns shared backing array; expected independent slices")
		}
	})
}

func TestAuthorizePayload(t *testing.T) {
	// Happy paths: each payload kind from the authority matrix paired with its
	// required purpose. These are exhaustively listed from
	// internal/contract/verify.go payloadAuthority map.
	t.Run("happy_paths", func(t *testing.T) {
		tests := []struct {
			payloadKind string
			signedWith  KeyPurpose
		}{
			{"proxy_decision", PurposeReceiptSigning},
			{"contract_ratified", PurposeReceiptSigning},
			{"contract_promote_intent", PurposeContractActivationSigning},
			{"contract_promote_committed", PurposeReceiptSigning},
			{"contract_rollback_authorized", PurposeContractActivationSigning},
			{"contract_rollback_committed", PurposeReceiptSigning},
			{"contract_demoted", PurposeReceiptSigning},
			{"contract_expired", PurposeReceiptSigning},
			{"contract_drift", PurposeReceiptSigning},
			{"shadow_delta", PurposeReceiptSigning},
			{"opportunity_missing", PurposeReceiptSigning},
			{"key_rotation", PurposeContractActivationSigning},
			{"contract_redaction_request", PurposeContractActivationSigning},
		}
		for _, tt := range tests {
			t.Run(tt.payloadKind, func(t *testing.T) {
				if err := AuthorizePayload(tt.payloadKind, tt.signedWith); err != nil {
					t.Errorf("AuthorizePayload(%q, %q) = %v, want nil", tt.payloadKind, tt.signedWith, err)
				}
			})
		}
	})

	t.Run("wrong_purpose", func(t *testing.T) {
		// proxy_decision requires receipt-signing; use activation instead.
		err := AuthorizePayload("proxy_decision", PurposeContractActivationSigning)
		if err == nil {
			t.Fatal("expected error for wrong purpose, got nil")
		}
		if !errors.Is(err, contract.ErrWrongKeyPurpose) {
			t.Errorf("error does not wrap contract.ErrWrongKeyPurpose: %v", err)
		}
	})

	t.Run("unknown_payload_kind", func(t *testing.T) {
		err := AuthorizePayload("made_up_kind", PurposeReceiptSigning)
		if err == nil {
			t.Fatal("expected error for unknown payload kind, got nil")
		}
		if !errors.Is(err, contract.ErrUnknownPayloadKind) {
			t.Errorf("error does not wrap contract.ErrUnknownPayloadKind: %v", err)
		}
	})
}
