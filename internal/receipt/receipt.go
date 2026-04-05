// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// ReceiptVersion is the current receipt envelope schema version.
const ReceiptVersion = 1

const signaturePrefix = "ed25519:"

// Receipt is a self-signed proof of an action record. It bundles the
// action record, an Ed25519 signature over the canonical record hash,
// and the signer's public key for independent verification.
type Receipt struct {
	Version      int          `json:"version"`
	ActionRecord ActionRecord `json:"action_record"`
	Signature    string       `json:"signature"`
	SignerKey    string       `json:"signer_key"`
}

// Sign creates a receipt by signing the canonical action record with Ed25519.
// The signature covers SHA-256(canonical JSON of the action record).
func Sign(ar ActionRecord, privKey ed25519.PrivateKey) (Receipt, error) {
	if len(privKey) != ed25519.PrivateKeySize {
		return Receipt{}, fmt.Errorf("invalid private key size: got %d, want %d", len(privKey), ed25519.PrivateKeySize)
	}
	if err := ar.Validate(); err != nil {
		return Receipt{}, fmt.Errorf("invalid action record: %w", err)
	}

	data, err := ar.Canonical()
	if err != nil {
		return Receipt{}, fmt.Errorf("canonical encoding: %w", err)
	}

	sum := sha256.Sum256(data)
	sig := ed25519.Sign(privKey, sum[:])
	pubKey := privKey.Public().(ed25519.PublicKey)

	return Receipt{
		Version:      ReceiptVersion,
		ActionRecord: ar,
		Signature:    signaturePrefix + hex.EncodeToString(sig),
		SignerKey:    hex.EncodeToString(pubKey),
	}, nil
}

// Verify checks the receipt's signature against the embedded signer key.
// Returns nil if the signature is valid and the action record is well-formed.
func Verify(r Receipt) error {
	return VerifyWithKey(r, "")
}

// VerifyWithKey checks the receipt's signature against the given public key hex.
// If expectedKeyHex is empty, the embedded signer_key is used.
func VerifyWithKey(r Receipt, expectedKeyHex string) error {
	if r.Version != ReceiptVersion {
		return fmt.Errorf("unsupported receipt version %d (expected %d)", r.Version, ReceiptVersion)
	}
	if err := r.ActionRecord.Validate(); err != nil {
		return fmt.Errorf("invalid action record: %w", err)
	}
	if r.Signature == "" {
		return fmt.Errorf("receipt has no signature")
	}
	if r.SignerKey == "" {
		return fmt.Errorf("receipt has no signer_key")
	}

	// Determine which key to verify against
	keyHex := r.SignerKey
	if expectedKeyHex != "" {
		if keyHex != expectedKeyHex {
			return fmt.Errorf("signer_key %s does not match expected key %s", keyHex, expectedKeyHex)
		}
	}

	pubKeyBytes, err := hex.DecodeString(keyHex)
	if err != nil {
		return fmt.Errorf("decoding signer_key: %w", err)
	}
	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid signer_key length: got %d, want %d", len(pubKeyBytes), ed25519.PublicKeySize)
	}
	pubKey := ed25519.PublicKey(pubKeyBytes)

	// Decode signature
	sigHex := r.Signature
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

	// Compute canonical hash and verify
	data, err := r.ActionRecord.Canonical()
	if err != nil {
		return fmt.Errorf("canonical encoding: %w", err)
	}
	sum := sha256.Sum256(data)
	if !ed25519.Verify(pubKey, sum[:], sig) {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}

// Marshal returns the JSON encoding of a receipt.
func Marshal(r Receipt) ([]byte, error) {
	return json.Marshal(r)
}

// Unmarshal parses a JSON-encoded receipt.
func Unmarshal(data []byte) (Receipt, error) {
	var r Receipt
	if err := json.Unmarshal(data, &r); err != nil {
		return Receipt{}, fmt.Errorf("unmarshal receipt: %w", err)
	}
	return r, nil
}
