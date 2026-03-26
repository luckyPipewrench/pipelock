// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestFindSigner_InvalidTrustedKeyHex(t *testing.T) {
	// Non-parallel: mutates KeyringHex.

	// No official keys.
	orig := KeyringHex
	KeyringHex = ""
	t.Cleanup(func() { KeyringHex = orig })

	data := []byte("test-data")
	// Sign with some key.
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	sig := ed25519.Sign(priv, data)

	// Invalid hex string in trusted key should be skipped (not panic).
	trustedKeys := []config.TrustedKey{
		{Name: "bad-hex", PublicKey: "not-valid-hex!!"},
	}

	_, err = findSigner(data, sig, trustedKeys)
	if err == nil {
		t.Fatal("expected error for no matching signer, got nil")
	}
}

func TestFindSigner_WrongKeySize(t *testing.T) {
	// Non-parallel: mutates KeyringHex.

	// No official keys.
	orig := KeyringHex
	KeyringHex = ""
	t.Cleanup(func() { KeyringHex = orig })

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

	_, err = findSigner(data, sig, trustedKeys)
	if err == nil {
		t.Fatal("expected error for no matching signer, got nil")
	}
}

func TestFindSigner_NoKeysAtAll(t *testing.T) {
	// Non-parallel: mutates KeyringHex.

	orig := KeyringHex
	KeyringHex = ""
	t.Cleanup(func() { KeyringHex = orig })

	data := []byte("test-data")
	sig := []byte("not-a-real-signature")

	_, err := findSigner(data, sig, nil)
	if err == nil {
		t.Fatal("expected error for no keys at all, got nil")
	}
}
