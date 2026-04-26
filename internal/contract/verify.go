// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"crypto/ed25519"
	"errors"
	"fmt"
)

// ErrWrongKeyPurpose rejects valid signatures from the wrong key purpose.
var ErrWrongKeyPurpose = errors.New("signature key_purpose does not match authority matrix")

// ErrUnknownPayloadKind rejects payload_kinds not in the authority matrix.
var ErrUnknownPayloadKind = errors.New("unknown payload_kind")

// payloadAuthority maps EvidenceReceipt v2 payload_kind to required signing purpose.
// Source: design doc Round 5, "EvidenceReceipt signing authority matrix".
var payloadAuthority = map[string]string{
	"proxy_decision":               "receipt-signing",
	"contract_ratified":            "receipt-signing",
	"contract_promote_intent":      "contract-activation-signing",
	"contract_promote_committed":   "receipt-signing",
	"contract_rollback_authorized": "contract-activation-signing",
	"contract_rollback_committed":  "receipt-signing",
	"contract_demoted":             "receipt-signing",
	"contract_expired":             "receipt-signing",
	"contract_drift":               "receipt-signing",
	"shadow_delta":                 "receipt-signing",
	"opportunity_missing":          "receipt-signing",
	"key_rotation":                 "contract-activation-signing",
	"contract_redaction_request":   "contract-activation-signing",
}

// VerifyEd25519PureEdDSA wraps stdlib ed25519.Verify, which implements
// RFC 8032 §5.1.6 PureEdDSA. Implementations MUST NOT call Ed25519ph or
// Ed25519ctx variants. Returns false on length mismatch or verify failure.
func VerifyEd25519PureEdDSA(publicKey, message, signature []byte) bool {
	if len(publicKey) != ed25519.PublicKeySize {
		return false
	}
	if len(signature) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(publicKey), message, signature)
}

// AuthorizeKeyPurpose returns nil if signedWith is the required key_purpose
// for payloadKind. Returns ErrUnknownPayloadKind for unknown payload_kind.
// Returns ErrWrongKeyPurpose if signedWith does not match the matrix.
func AuthorizeKeyPurpose(payloadKind, signedWith string) error {
	required, ok := payloadAuthority[payloadKind]
	if !ok {
		return fmt.Errorf("%w: %q", ErrUnknownPayloadKind, payloadKind)
	}
	if signedWith != required {
		return fmt.Errorf("%w: payload_kind=%q required=%q got=%q", ErrWrongKeyPurpose, payloadKind, required, signedWith)
	}
	return nil
}
