// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/jsonscan"
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

	// Ext is the single, UNSIGNED, advisory forward-compat metadata bag. It is
	// the ONLY tolerated unknown top-level surface on a v1 receipt: every other
	// unrecognized field, at any nesting depth, is rejected (fail-closed) by
	// Unmarshal. Ext is captured verbatim, NEVER covered by the receipt
	// signature (the signature covers only the canonical action record), and
	// NEVER consulted by verification — so no verified claim can rest on it.
	// A producer that needs to attach non-authoritative metadata puts it here;
	// a consumer must treat it as untrusted. Absent on stock receipts.
	Ext json.RawMessage `json:"ext,omitempty"`
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

	data, err := canonicalActionRecord(ReceiptVersion, ar)
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

// Verify is intentionally unusable without an external trust anchor. Receipt
// signatures prove only that the action record was signed by a key; callers that
// care about trust MUST call VerifyWithKey with the expected public key from
// enrollment/configuration. Use VerifyInternalConsistencyOnly only for local
// chain-recovery code that deliberately needs to distinguish corruption from a
// legitimate signing-key rotation.
func Verify(r Receipt) error {
	_ = r
	return fmt.Errorf("receipt verification requires a trusted public key; use VerifyWithKey")
}

// VerifyWithKey checks the receipt's signature against the given public key hex.
func VerifyWithKey(r Receipt, expectedKeyHex string) error {
	if expectedKeyHex == "" {
		return fmt.Errorf("receipt verification requires a trusted public key")
	}
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

	keyHex := r.SignerKey
	if keyHex != expectedKeyHex {
		return fmt.Errorf("signer_key %s does not match expected key %s", keyHex, expectedKeyHex)
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
	data, err := canonicalActionRecord(r.Version, r.ActionRecord)
	if err != nil {
		return fmt.Errorf("canonical encoding: %w", err)
	}
	sum := sha256.Sum256(data)
	if !ed25519.Verify(pubKey, sum[:], sig) {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}

// VerifyInternalConsistencyOnly checks that the receipt is structurally valid
// and self-signed by its embedded signer_key. It does NOT prove the signer is
// trusted. Production trust decisions must use VerifyWithKey.
func VerifyInternalConsistencyOnly(r Receipt) error {
	if r.SignerKey == "" {
		return fmt.Errorf("receipt has no signer_key")
	}
	return VerifyWithKey(r, r.SignerKey)
}

// Marshal returns the JSON encoding of a receipt.
func Marshal(r Receipt) ([]byte, error) {
	return json.Marshal(r)
}

// ErrUnknownField is returned when a v1 receipt (or any of its signed nested
// objects: action_record, session_control and its payloads, key_transition,
// redaction, shield, recent_taint_sources) carries a field the schema does not
// define. The only tolerated unknown surface is the top-level advisory ext bag.
var ErrUnknownField = errors.New("unknown field on signed v1 receipt object")

// ErrTrailingTokens is returned when valid receipt JSON is followed by
// additional non-whitespace tokens. Trailing tokens are a parser-differential
// smuggling surface, so the verify path rejects them.
var ErrTrailingTokens = errors.New("trailing tokens after receipt")

// Unmarshal parses a JSON-encoded receipt under the strict v1 verify contract.
//
// It fails closed on three parser-differential surfaces:
//
//   - Duplicate object keys at any nesting depth. encoding/json silently keeps
//     the last value for a duplicate key, so {"verdict":"allow","verdict":"block"}
//     would decode as "block" with no error, letting a display, log, or summary
//     layer that reads the first occurrence see a different value than the one
//     the signature was checked against.
//   - Unknown fields on any signed v1 object. A verifier that accept-and-ignores
//     an unrecognized sidecar field lets a downstream consumer trust content the
//     signature never covered. The single, deliberate exception is the top-level
//     ext bag (see Receipt.Ext), which is unsigned and never affects a verdict.
//   - Trailing tokens after the receipt value.
//
// Stock producers emit no unknown v1 fields, so no legitimate receipt breaks.
// The verify path runs through Unmarshal, so this closes the gaps on the verify
// side without touching the signing input (Sign uses Marshal, not Unmarshal).
func Unmarshal(data []byte) (Receipt, error) {
	if err := jsonscan.RejectDuplicateKeys(data); err != nil {
		return Receipt{}, fmt.Errorf("unmarshal receipt: %w", err)
	}
	var r Receipt
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		// encoding/json reports a disallowed field as "json: unknown field
		// ...". Wrap it with the ErrUnknownField sentinel so callers can match
		// the strict-schema rejection with errors.Is.
		if strings.Contains(err.Error(), "unknown field") {
			return Receipt{}, fmt.Errorf("unmarshal receipt: %w: %w", ErrUnknownField, err)
		}
		return Receipt{}, fmt.Errorf("unmarshal receipt: %w", err)
	}
	if err := dec.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		if err != nil {
			return Receipt{}, fmt.Errorf("unmarshal receipt: %w: %w", ErrTrailingTokens, err)
		}
		return Receipt{}, fmt.Errorf("unmarshal receipt: %w", ErrTrailingTokens)
	}
	return r, nil
}

// ErrDuplicateKey is returned when a receipt contains a duplicate object key.
// It aliases the shared scanner's sentinel so errors.Is(err, ErrDuplicateKey)
// works on errors surfaced through Unmarshal.
var ErrDuplicateKey = jsonscan.ErrDuplicateKey
