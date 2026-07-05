// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/luckyPipewrench/pipelock/internal/contract"
	"github.com/luckyPipewrench/pipelock/internal/jsonscan"
)

type receiptBytesEnvelopeV1 struct {
	Version      int             `json:"version"`
	ActionRecord json.RawMessage `json:"action_record"`
	Signature    string          `json:"signature"`
	SignerKey    string          `json:"signer_key"`
}

// VerifyV1BytesWithKey verifies a v1 receipt from the exact JSON bytes supplied
// by the caller. It is additive: existing object-taking verification continues
// to use VerifyWithKey.
func VerifyV1BytesWithKey(raw []byte, expectedKeyHex string) error {
	if err := jsonscan.RejectDuplicateKeys(raw); err != nil {
		return fmt.Errorf("verify v1 receipt bytes: %w", err)
	}

	var typed Receipt
	if err := contract.DecodeStrictJSON(raw, &typed); err != nil {
		return fmt.Errorf("decode v1 receipt: %w", err)
	}

	var env receiptBytesEnvelopeV1
	if err := contract.DecodeStrictJSON(raw, &env); err != nil {
		return fmt.Errorf("decode v1 receipt bytes envelope: %w", err)
	}
	if err := contract.DecodeStrictJSON(env.ActionRecord, &typed.ActionRecord); err != nil {
		return fmt.Errorf("decode v1 action_record bytes: %w", err)
	}
	emitted, err := json.Marshal(typed)
	if err != nil {
		return fmt.Errorf("marshal v1 receipt for exact-byte check: %w", err)
	}
	if !bytes.Equal(raw, emitted) {
		return fmt.Errorf("receipt bytes do not match v1 emitted JSON")
	}

	if expectedKeyHex == "" {
		return fmt.Errorf("receipt verification requires a trusted public key")
	}
	if env.Version != ReceiptVersion {
		return fmt.Errorf("unsupported receipt version %d (expected %d)", env.Version, ReceiptVersion)
	}
	if err := typed.ActionRecord.Validate(); err != nil {
		return fmt.Errorf("invalid action record: %w", err)
	}
	if env.Signature == "" {
		return fmt.Errorf("receipt has no signature")
	}
	if env.SignerKey == "" {
		return fmt.Errorf("receipt has no signer_key")
	}
	if env.SignerKey != expectedKeyHex {
		return fmt.Errorf("signer_key %s does not match expected key %s", env.SignerKey, expectedKeyHex)
	}

	canonical, err := canonicalActionRecord(env.Version, typed.ActionRecord)
	if err != nil {
		return fmt.Errorf("canonical encoding: %w", err)
	}
	if !bytes.Equal(env.ActionRecord, canonical) {
		return fmt.Errorf("action_record bytes do not match v1 signing projection")
	}

	pubKeyBytes, err := hex.DecodeString(env.SignerKey)
	if err != nil {
		return fmt.Errorf("decoding signer_key: %w", err)
	}
	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid signer_key length: got %d, want %d", len(pubKeyBytes), ed25519.PublicKeySize)
	}

	sigHex := env.Signature
	if len(sigHex) > len(signaturePrefix) && sigHex[:len(signaturePrefix)] == signaturePrefix {
		sigHex = sigHex[len(signaturePrefix):]
	} else {
		return fmt.Errorf("invalid signature format: missing %s prefix", signaturePrefix)
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return fmt.Errorf("decoding signature: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature length: got %d, want %d", len(sig), ed25519.SignatureSize)
	}

	sum := sha256.Sum256(env.ActionRecord)
	if !ed25519.Verify(ed25519.PublicKey(pubKeyBytes), sum[:], sig) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}
