// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"

	"github.com/luckyPipewrench/pipelock/internal/contract"
	"github.com/luckyPipewrench/pipelock/internal/jsonscan"
)

// VerifyV2BytesWithKey verifies a v2 evidence receipt from the exact JSON bytes
// supplied by the caller. It is additive: existing object-taking verification
// continues to use VerifyWithKey.
func VerifyV2BytesWithKey(raw []byte, pubKey ed25519.PublicKey, expectedSignerKeyID string) error {
	if err := jsonscan.RejectDuplicateKeys(raw); err != nil {
		return fmt.Errorf("verify v2 receipt bytes: %w", err)
	}

	var r EvidenceReceipt
	if err := contract.DecodeStrictJSON(raw, &r); err != nil {
		return fmt.Errorf("decode v2 receipt: %w", err)
	}
	if err := r.Validate(); err != nil {
		return err
	}
	payload, err := emittedPayloadBytes(r.PayloadKind, r.Payload)
	if err != nil {
		return err
	}
	if !bytes.Equal(r.Payload, payload) {
		return fmt.Errorf("receipt payload bytes do not match v2 emitted JSON")
	}

	emitted, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("marshal v2 receipt for exact-byte check: %w", err)
	}
	if !bytes.Equal(raw, emitted) {
		return fmt.Errorf("receipt bytes do not match v2 emitted JSON")
	}

	return VerifyWithKey(r, pubKey, expectedSignerKeyID)
}

func emittedPayloadBytes(kind PayloadKind, raw json.RawMessage) ([]byte, error) {
	switch kind {
	case PayloadProxyDecision:
		return marshalStrictPayload[PayloadProxyDecisionStruct](raw)
	case PayloadProxyDecisionWithSpans:
		return marshalStrictPayload[PayloadProxyDecisionWithSpansStruct](raw)
	case PayloadContractRatified:
		return marshalStrictPayload[PayloadContractRatifiedStruct](raw)
	case PayloadContractPromoteIntent:
		return marshalStrictPayload[PayloadContractPromoteIntentStruct](raw)
	case PayloadContractPromoteCommitted:
		return marshalStrictPayload[PayloadContractPromoteCommittedStruct](raw)
	case PayloadContractRollbackAuthorized:
		return marshalStrictPayload[PayloadContractRollbackAuthorizedStruct](raw)
	case PayloadContractRollbackCommitted:
		return marshalStrictPayload[PayloadContractRollbackCommittedStruct](raw)
	case PayloadContractDemoted:
		return marshalStrictPayload[PayloadContractDemotedStruct](raw)
	case PayloadContractExpired:
		return marshalStrictPayload[PayloadContractExpiredStruct](raw)
	case PayloadContractDrift:
		return marshalStrictPayload[PayloadContractDriftStruct](raw)
	case PayloadShadowDelta:
		return marshalStrictPayload[PayloadShadowDeltaStruct](raw)
	case PayloadOpportunityMissing:
		return marshalStrictPayload[PayloadOpportunityMissingStruct](raw)
	case PayloadKeyRotation:
		return marshalStrictPayload[PayloadKeyRotationStruct](raw)
	case PayloadContractRedactionRequest:
		return marshalStrictPayload[PayloadContractRedactionRequestStruct](raw)
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnknownPayloadKind, kind)
	}
}

func marshalStrictPayload[T any](raw json.RawMessage) ([]byte, error) {
	var payload T
	if err := decodeStrict(raw, &payload); err != nil {
		return nil, fmt.Errorf("decode v2 receipt payload bytes: %w", err)
	}
	out, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal v2 receipt payload for exact-byte check: %w", err)
	}
	return out, nil
}
