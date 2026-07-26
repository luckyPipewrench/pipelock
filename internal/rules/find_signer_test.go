// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestFindSigner_InvalidTrustedKeyHex(t *testing.T) {
	// Non-parallel: mutates keyring globals.

	// No official keys.
	setEmbeddedKeyringHexForTest(t, "", "")

	data := []byte("test-data")
	// Sign with some key.
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	sig := ed25519.Sign(priv, data)

	// Invalid hex string in trusted key fails closed with an operator-visible
	// configuration error instead of being collapsed into "no matching signer".
	trustedKeys := []config.TrustedKey{
		{Name: "bad-hex", PublicKey: "not-valid-hex!!"},
	}

	_, err = findSigner(data, sig, DefaultTrustPolicy(trustedKeys))
	if err == nil {
		t.Fatal("expected error for malformed trusted key, got nil")
	}
	if !strings.Contains(err.Error(), "bad-hex") || !strings.Contains(err.Error(), "exactly 64 hex chars") {
		t.Fatalf("findSigner error = %v, want malformed key detail", err)
	}
}

func TestFindSigner_CorrectLengthButNotHex(t *testing.T) {
	// Non-parallel: mutates keyring globals.

	// No official keys.
	setEmbeddedKeyringHexForTest(t, "", "")

	data := []byte("test-data")
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	sig := ed25519.Sign(priv, data)

	// Exactly 64 characters, so the length check passes, but not hex. This is the
	// realistic operator typo the sibling test cannot reach: pasting a base64 key
	// where hex was expected clears the length gate and only fails at decode. It must
	// still fail closed naming the entry, not collapse into "no matching signer".
	trustedKeys := []config.TrustedKey{
		{Name: "base64-not-hex", PublicKey: strings.Repeat("z", 64)},
	}

	_, err = findSigner(data, sig, DefaultTrustPolicy(trustedKeys))
	if err == nil {
		t.Fatal("expected error for non-hex trusted key, got nil")
	}
	if !strings.Contains(err.Error(), "base64-not-hex") || !strings.Contains(err.Error(), "invalid hex") {
		t.Fatalf("findSigner error = %v, want the entry name and an invalid-hex detail", err)
	}
}

func TestFindSigner_WrongKeySize(t *testing.T) {
	// Non-parallel: mutates keyring globals.

	// No official keys.
	setEmbeddedKeyringHexForTest(t, "", "")

	data := []byte("test-data")
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	sig := ed25519.Sign(priv, data)

	// Trusted key with valid hex but wrong length (16 bytes instead of 32).
	shortKey := make([]byte, 16)
	trustedKeys := []config.TrustedKey{
		{Name: "short-key", PublicKey: hex.EncodeToString(shortKey)},
	}

	_, err = findSigner(data, sig, DefaultTrustPolicy(trustedKeys))
	if err == nil {
		t.Fatal("expected error for malformed trusted key, got nil")
	}
	if !strings.Contains(err.Error(), "short-key") || !strings.Contains(err.Error(), "exactly 64 hex chars") {
		t.Fatalf("findSigner error = %v, want malformed key detail", err)
	}
}

func TestFindSigner_MalformedTrustedKeyBeforeValidSignerFailsClosed(t *testing.T) {
	// Non-parallel: mutates keyring globals.

	setEmbeddedKeyringHexForTest(t, "", "")

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	data := []byte("test-data")
	sig := ed25519.Sign(priv, data)

	trustedKeys := []config.TrustedKey{
		{Name: "bad-root", PublicKey: "not-valid-hex!!"},
		{Name: "good-root", PublicKey: hex.EncodeToString(pub)},
	}

	_, err = findSigner(data, sig, DefaultTrustPolicy(trustedKeys))
	if err == nil {
		t.Fatal("expected malformed trusted key to fail closed before signature acceptance")
	}
	if !strings.Contains(err.Error(), "bad-root") {
		t.Fatalf("findSigner error = %v, want bad-root detail", err)
	}
}

func TestFindSigner_NoKeysAtAll(t *testing.T) {
	// Non-parallel: mutates keyring globals.

	setEmbeddedKeyringHexForTest(t, "", "")

	data := []byte("test-data")
	sig := make([]byte, ed25519.SignatureSize)

	_, err := findSigner(data, sig, DefaultTrustPolicy(nil))
	if err == nil {
		t.Fatal("expected error for no keys at all, got nil")
	}
}
