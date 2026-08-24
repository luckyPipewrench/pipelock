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

// UnanchoredSuffixResult describes a contiguous v1 receipt segment whose
// earlier chain history is unavailable. OriginPrevHash is recorded rather than
// trusted: the verifier can prove the suffix from OriginSeq onward, not the
// missing predecessor it references.
type UnanchoredSuffixResult struct {
	Count          uint64
	OriginSeq      uint64
	OriginPrevHash string
	FinalSeq       uint64
	Head           string
}

// UnanchoredSuffixVerifier verifies a bounded stream that starts after an
// irrecoverable historical gap. Its first receipt must be signed by the
// caller-pinned key. Every later receipt must use that same key, be valid in
// its exact emitted-byte representation, and continue the suffix directly.
// Key transitions are deliberately unsupported: accepting one without its
// missing predecessor would make the new key's authority unverifiable.
type UnanchoredSuffixVerifier struct {
	expectedKeyHex string
	seen           bool
	failed         error
	result         UnanchoredSuffixResult
}

// NewUnanchoredSuffixVerifier creates a verifier pinned to one trusted v1
// signer key. A suffix cannot use trust-on-first-use because its missing
// predecessor is precisely the trust boundary that cannot be reconstructed.
func NewUnanchoredSuffixVerifier(expectedKeyHex string) (*UnanchoredSuffixVerifier, error) {
	if expectedKeyHex == "" {
		return nil, fmt.Errorf("unanchored suffix verification requires a trusted public key")
	}
	key, err := hex.DecodeString(expectedKeyHex)
	if err != nil {
		return nil, fmt.Errorf("decode trusted public key: %w", err)
	}
	if len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid trusted public key length: got %d, want %d", len(key), ed25519.PublicKeySize)
	}
	return &UnanchoredSuffixVerifier{expectedKeyHex: expectedKeyHex}, nil
}

// Add verifies one exact v1 receipt and advances the suffix. Once it fails,
// the verifier stays failed so a caller cannot accidentally continue from a
// corrupted or substituted record.
func (v *UnanchoredSuffixVerifier) Add(raw []byte) error {
	if v.failed != nil {
		return v.failed
	}
	if err := verifyV1SuffixBytesWithKey(raw, v.expectedKeyHex); err != nil {
		return v.latch(err)
	}
	r, _ := Unmarshal(raw)
	if r.ActionRecord.KeyTransition != nil {
		return v.latch(fmt.Errorf("key_transition is unsupported in an unanchored receipt suffix"))
	}
	if v.seen {
		if v.result.FinalSeq == ^uint64(0) {
			return v.latch(fmt.Errorf("unanchored suffix sequence overflows after %d", v.result.FinalSeq))
		}
		if r.ActionRecord.ChainSeq != v.result.FinalSeq+1 {
			return v.latch(fmt.Errorf("unanchored suffix sequence break: expected %d, got %d", v.result.FinalSeq+1, r.ActionRecord.ChainSeq))
		}
		if r.ActionRecord.ChainPrevHash != v.result.Head {
			return v.latch(fmt.Errorf("unanchored suffix chain_prev_hash mismatch"))
		}
	}
	head, _ := ReceiptHash(r)
	if !v.seen {
		v.result.OriginSeq = r.ActionRecord.ChainSeq
		v.result.OriginPrevHash = r.ActionRecord.ChainPrevHash
		v.seen = true
	}
	v.result.Count++
	v.result.FinalSeq = r.ActionRecord.ChainSeq
	v.result.Head = head
	return nil
}

// verifyV1SuffixBytesWithKey preserves the one deliberate v1 parser
// compatibility rule for historical action_record.detected_patterns metadata.
// All ordinary receipts retain the stricter exact-emitted-byte check.
func verifyV1SuffixBytesWithKey(raw []byte, expectedKeyHex string) error {
	strictErr := VerifyV1BytesWithKey(raw, expectedKeyHex)
	if strictErr == nil {
		return nil
	}
	if err := jsonscan.RejectDuplicateKeys(raw); err != nil {
		return fmt.Errorf("decode legacy v1 suffix envelope: %w", err)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return fmt.Errorf("decode legacy v1 suffix envelope: %w", err)
	}
	var action map[string]json.RawMessage
	if err := json.Unmarshal(top["action_record"], &action); err != nil {
		return fmt.Errorf("decode legacy v1 suffix action_record: %w", err)
	}
	if _, ok := action["detected_patterns"]; !ok {
		return strictErr
	}
	canonicalAction, _ := json.Marshal(action) // RawMessage values were validated by json.Unmarshal above.
	top["action_record"] = canonicalAction
	canonicalRaw, _ := json.Marshal(top) // RawMessage values were validated by json.Unmarshal above.
	if !bytes.Equal(raw, canonicalRaw) {
		return fmt.Errorf("legacy v1 suffix bytes do not match the historical emitted JSON shape")
	}
	receipt, err := Unmarshal(raw)
	if err != nil {
		return err
	}
	if err := VerifyWithKey(receipt, expectedKeyHex); err != nil {
		return err
	}
	return nil
}

func (v *UnanchoredSuffixVerifier) latch(err error) error {
	v.failed = err
	return err
}

// Finish returns the verified suffix boundary. Empty or failed suffixes do not
// yield a proof because there is no signed trusted origin to report.
func (v *UnanchoredSuffixVerifier) Finish() (UnanchoredSuffixResult, error) {
	if v.failed != nil {
		return UnanchoredSuffixResult{}, v.failed
	}
	if !v.seen {
		return UnanchoredSuffixResult{}, fmt.Errorf("empty unanchored receipt suffix")
	}
	return v.result, nil
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
