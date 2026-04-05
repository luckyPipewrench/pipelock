// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

const (
	testSigPrefix = "ed25519:"
)

func generateTestKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pub, priv
}

func signValidReceipt(t *testing.T, priv ed25519.PrivateKey) Receipt {
	t.Helper()
	ar := validActionRecord()
	r, err := Sign(ar, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return r
}

func TestSign_HappyPath(t *testing.T) {
	t.Parallel()

	pub, priv := generateTestKey(t)
	ar := validActionRecord()

	r, err := Sign(ar, priv)
	if err != nil {
		t.Fatalf("Sign() error: %v", err)
	}

	if r.Version != ReceiptVersion {
		t.Errorf("receipt version = %d, want %d", r.Version, ReceiptVersion)
	}
	if !strings.HasPrefix(r.Signature, testSigPrefix) {
		t.Errorf("signature missing %q prefix: %s", testSigPrefix, r.Signature)
	}
	if r.SignerKey != hex.EncodeToString(pub) {
		t.Errorf("signer_key = %s, want %s", r.SignerKey, hex.EncodeToString(pub))
	}
}

func TestSign_InvalidPrivateKeySize(t *testing.T) {
	t.Parallel()

	ar := validActionRecord()
	shortKey := make([]byte, 16)
	_, err := Sign(ar, shortKey)
	if err == nil {
		t.Fatal("Sign() expected error for short private key, got nil")
	}
	if !strings.Contains(err.Error(), "invalid private key size") {
		t.Errorf("Sign() error = %q, want substring \"invalid private key size\"", err)
	}
}

func TestSign_InvalidActionRecord(t *testing.T) {
	t.Parallel()

	_, priv := generateTestKey(t)
	ar := validActionRecord()
	ar.ActionID = "" // missing required field

	_, err := Sign(ar, priv)
	if err == nil {
		t.Fatal("Sign() expected error for invalid action record, got nil")
	}
	if !strings.Contains(err.Error(), "invalid action record") {
		t.Errorf("Sign() error = %q, want substring \"invalid action record\"", err)
	}
}

func TestVerify_HappyPath(t *testing.T) {
	t.Parallel()

	_, priv := generateTestKey(t)
	r := signValidReceipt(t, priv)

	if err := Verify(r); err != nil {
		t.Fatalf("Verify() error: %v", err)
	}
}

func TestVerify_TamperedRecord(t *testing.T) {
	t.Parallel()

	_, priv := generateTestKey(t)
	r := signValidReceipt(t, priv)

	// Tamper with the action record after signing.
	r.ActionRecord.Target = "https://evil.example.com"

	err := Verify(r)
	if err == nil {
		t.Fatal("Verify() expected error for tampered record, got nil")
	}
	if !strings.Contains(err.Error(), "signature verification failed") {
		t.Errorf("Verify() error = %q, want substring \"signature verification failed\"", err)
	}
}

func TestVerify_TamperedSignature(t *testing.T) {
	t.Parallel()

	_, priv := generateTestKey(t)
	r := signValidReceipt(t, priv)

	// Flip a byte in the signature hex.
	sigHex := r.Signature[len(testSigPrefix):]
	flipped := flipHexByte(sigHex)
	r.Signature = testSigPrefix + flipped

	err := Verify(r)
	if err == nil {
		t.Fatal("Verify() expected error for tampered signature, got nil")
	}
	if !strings.Contains(err.Error(), "signature verification failed") {
		t.Errorf("Verify() error = %q, want substring \"signature verification failed\"", err)
	}
}

func TestVerifyWithKey_MatchingKey(t *testing.T) {
	t.Parallel()

	pub, priv := generateTestKey(t)
	r := signValidReceipt(t, priv)

	err := VerifyWithKey(r, hex.EncodeToString(pub))
	if err != nil {
		t.Fatalf("VerifyWithKey() error: %v", err)
	}
}

func TestVerifyWithKey_WrongKey(t *testing.T) {
	t.Parallel()

	_, priv := generateTestKey(t)
	r := signValidReceipt(t, priv)

	// Generate a different key pair.
	otherPub, _ := generateTestKey(t)

	err := VerifyWithKey(r, hex.EncodeToString(otherPub))
	if err == nil {
		t.Fatal("VerifyWithKey() expected error for wrong key, got nil")
	}
	if !strings.Contains(err.Error(), "does not match expected key") {
		t.Errorf("VerifyWithKey() error = %q, want substring \"does not match expected key\"", err)
	}
}

func TestVerify_MissingSignature(t *testing.T) {
	t.Parallel()

	_, priv := generateTestKey(t)
	r := signValidReceipt(t, priv)
	r.Signature = ""

	err := Verify(r)
	if err == nil {
		t.Fatal("Verify() expected error for missing signature, got nil")
	}
	if !strings.Contains(err.Error(), "no signature") {
		t.Errorf("Verify() error = %q, want substring \"no signature\"", err)
	}
}

func TestVerify_MissingSignerKey(t *testing.T) {
	t.Parallel()

	_, priv := generateTestKey(t)
	r := signValidReceipt(t, priv)
	r.SignerKey = ""

	err := Verify(r)
	if err == nil {
		t.Fatal("Verify() expected error for missing signer_key, got nil")
	}
	if !strings.Contains(err.Error(), "no signer_key") {
		t.Errorf("Verify() error = %q, want substring \"no signer_key\"", err)
	}
}

func TestVerify_WrongVersion(t *testing.T) {
	t.Parallel()

	_, priv := generateTestKey(t)
	r := signValidReceipt(t, priv)
	r.Version = 99

	err := Verify(r)
	if err == nil {
		t.Fatal("Verify() expected error for wrong version, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported receipt version") {
		t.Errorf("Verify() error = %q, want substring \"unsupported receipt version\"", err)
	}
}

func TestVerify_BadHexSignerKey(t *testing.T) {
	t.Parallel()

	_, priv := generateTestKey(t)
	r := signValidReceipt(t, priv)
	r.SignerKey = "not-valid-hex!"

	err := Verify(r)
	if err == nil {
		t.Fatal("Verify() expected error for bad hex signer_key, got nil")
	}
	if !strings.Contains(err.Error(), "decoding signer_key") {
		t.Errorf("Verify() error = %q, want substring \"decoding signer_key\"", err)
	}
}

func TestVerify_BadHexSignature(t *testing.T) {
	t.Parallel()

	_, priv := generateTestKey(t)
	r := signValidReceipt(t, priv)
	r.Signature = testSigPrefix + "not-valid-hex!"

	err := Verify(r)
	if err == nil {
		t.Fatal("Verify() expected error for bad hex signature, got nil")
	}
	if !strings.Contains(err.Error(), "decoding signature") {
		t.Errorf("Verify() error = %q, want substring \"decoding signature\"", err)
	}
}

func TestVerify_WrongSignatureLength(t *testing.T) {
	t.Parallel()

	_, priv := generateTestKey(t)
	r := signValidReceipt(t, priv)
	// Set signature to valid hex but wrong length (16 bytes instead of 64).
	r.Signature = testSigPrefix + hex.EncodeToString(make([]byte, 16))

	err := Verify(r)
	if err == nil {
		t.Fatal("Verify() expected error for wrong signature length, got nil")
	}
	if !strings.Contains(err.Error(), "invalid signature length") {
		t.Errorf("Verify() error = %q, want substring \"invalid signature length\"", err)
	}
}

func TestVerify_WrongKeyLength(t *testing.T) {
	t.Parallel()

	_, priv := generateTestKey(t)
	r := signValidReceipt(t, priv)
	// Set signer_key to valid hex but wrong length (16 bytes instead of 32).
	r.SignerKey = hex.EncodeToString(make([]byte, 16))

	err := Verify(r)
	if err == nil {
		t.Fatal("Verify() expected error for wrong key length, got nil")
	}
	if !strings.Contains(err.Error(), "invalid signer_key length") {
		t.Errorf("Verify() error = %q, want substring \"invalid signer_key length\"", err)
	}
}

func TestVerify_MissingSignaturePrefix(t *testing.T) {
	t.Parallel()

	_, priv := generateTestKey(t)
	r := signValidReceipt(t, priv)
	// Remove the ed25519: prefix.
	r.Signature = strings.TrimPrefix(r.Signature, testSigPrefix)

	err := Verify(r)
	if err == nil {
		t.Fatal("Verify() expected error for missing signature prefix, got nil")
	}
	if !strings.Contains(err.Error(), "missing") {
		t.Errorf("Verify() error = %q, want substring \"missing\"", err)
	}
}

func TestMarshal_Unmarshal_RoundTrip(t *testing.T) {
	t.Parallel()

	_, priv := generateTestKey(t)
	r := signValidReceipt(t, priv)

	data, err := Marshal(r)
	if err != nil {
		t.Fatalf("Marshal() error: %v", err)
	}

	r2, err := Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}

	// Verify the unmarshaled receipt still verifies.
	if err := Verify(r2); err != nil {
		t.Fatalf("Verify(unmarshaled) error: %v", err)
	}

	// Check key fields survived the round trip.
	if r2.Version != r.Version {
		t.Errorf("version: got %d, want %d", r2.Version, r.Version)
	}
	if r2.Signature != r.Signature {
		t.Errorf("signature mismatch after round trip")
	}
	if r2.SignerKey != r.SignerKey {
		t.Errorf("signer_key mismatch after round trip")
	}
	if r2.ActionRecord.ActionID != r.ActionRecord.ActionID {
		t.Errorf("action_id mismatch after round trip")
	}
	if r2.ActionRecord.Target != r.ActionRecord.Target {
		t.Errorf("target mismatch after round trip")
	}
}

func TestUnmarshal_InvalidJSON(t *testing.T) {
	t.Parallel()

	_, err := Unmarshal([]byte("not json"))
	if err == nil {
		t.Fatal("Unmarshal() expected error for invalid JSON, got nil")
	}
	if !strings.Contains(err.Error(), "unmarshal receipt") {
		t.Errorf("Unmarshal() error = %q, want substring \"unmarshal receipt\"", err)
	}
}

func TestUnmarshal_EmptyJSON(t *testing.T) {
	t.Parallel()

	r, err := Unmarshal([]byte("{}"))
	if err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}
	// Empty JSON produces zero-value receipt. Verify should fail on it.
	if err := Verify(r); err == nil {
		t.Error("Verify() on empty receipt expected error, got nil")
	}
}

func TestSign_PreservesTimestamp(t *testing.T) {
	t.Parallel()

	_, priv := generateTestKey(t)
	ar := validActionRecord()
	fixedTime := time.Date(2026, 4, 4, 15, 30, 0, 0, time.UTC)
	ar.Timestamp = fixedTime

	r, err := Sign(ar, priv)
	if err != nil {
		t.Fatalf("Sign() error: %v", err)
	}
	if !r.ActionRecord.Timestamp.Equal(fixedTime) {
		t.Errorf("timestamp = %v, want %v", r.ActionRecord.Timestamp, fixedTime)
	}
}

// flipHexByte flips the first hex character in a hex string to produce
// a different but still valid hex string.
func flipHexByte(h string) string {
	if len(h) == 0 {
		return h
	}
	b := []byte(h)
	if b[0] == 'f' {
		b[0] = '0'
	} else {
		b[0] = 'f'
	}
	return string(b)
}
