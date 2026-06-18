// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

// allZeroPrivateKey is a length-valid but degenerate Ed25519 private key: its
// 32-byte stored public half is all zeros, which does NOT match the public key
// that the (all-zero) seed actually derives. Without a seed->stored-pub
// consistency check it loads as "valid" and would sign receipts.
func allZeroPrivateKey() ed25519.PrivateKey {
	return ed25519.PrivateKey(make([]byte, ed25519.PrivateKeySize))
}

func realPrivateKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return priv
}

func TestValidatePrivateKeyConsistency(t *testing.T) {
	realKey := realPrivateKey(t)

	// A real key with its stored public half corrupted: the seed no longer
	// derives the stored pub. Tamper a copy so the seed is untouched.
	tampered := make(ed25519.PrivateKey, ed25519.PrivateKeySize)
	copy(tampered, realKey)
	tampered[ed25519.SeedSize] ^= 0xFF

	tests := []struct {
		name    string
		key     ed25519.PrivateKey
		wantErr bool
	}{
		{"real key from GenerateKey", realKey, false},
		{"real key from NewKeyFromSeed", ed25519.NewKeyFromSeed(realKey.Seed()), false},
		{"all-zero degenerate key", allZeroPrivateKey(), true},
		{"seed/public mismatch (tampered pub half)", tampered, true},
		{"wrong length (seed only)", ed25519.PrivateKey(make([]byte, ed25519.SeedSize)), true},
		{"wrong length (empty)", ed25519.PrivateKey(nil), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePrivateKeyConsistency(tc.key)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got nil (degenerate/invalid key accepted)")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected nil, got %v (real key wrongly rejected)", err)
			}
		})
	}
}

func TestDecodePrivateKey_RejectsDegenerate_TwoLine(t *testing.T) {
	// 2-line versioned format with an all-zero 64-byte key.
	encoded := EncodePrivateKey(allZeroPrivateKey())
	if _, err := DecodePrivateKey(encoded); err == nil {
		t.Fatal("DecodePrivateKey accepted an all-zero 2-line key (fail-open)")
	}

	// A real key round-trips fine.
	realKey := realPrivateKey(t)
	got, err := DecodePrivateKey(EncodePrivateKey(realKey))
	if err != nil {
		t.Fatalf("DecodePrivateKey rejected a real key: %v", err)
	}
	if !got.Equal(realKey) {
		t.Fatal("round-tripped key does not equal original")
	}
}

func TestDecodePrivateKey_RejectsDegenerate_JSON(t *testing.T) {
	// JSON keyfile where BOTH the private and public fields are all zeros: the
	// existing stored-pub-vs-declared-pub check passes (both zero), so only a
	// seed->stored-pub derivation check catches it.
	zeroPriv := strings.Repeat("00", ed25519.PrivateKeySize)
	zeroPub := strings.Repeat("00", ed25519.PublicKeySize)
	jsonKey := fmt.Sprintf(`{"schema_version":1,"private":"%s","public":"%s"}`, zeroPriv, zeroPub)
	if _, err := DecodePrivateKey(jsonKey); err == nil {
		t.Fatal("DecodePrivateKey accepted an all-zero JSON key with matching zero public field (fail-open)")
	}

	// JSON with no public field but degenerate private must also be rejected.
	jsonNoPub := fmt.Sprintf(`{"schema_version":1,"private":"%s"}`, zeroPriv)
	if _, err := DecodePrivateKey(jsonNoPub); err == nil {
		t.Fatal("DecodePrivateKey accepted an all-zero JSON key with no public field (fail-open)")
	}

	// A real key serialized as JSON is accepted.
	realKey := realPrivateKey(t)
	realPrivHex := hex.EncodeToString(realKey)
	realPubHex := hex.EncodeToString(realKey[ed25519.SeedSize:])
	realJSON := fmt.Sprintf(`{"schema_version":1,"private":"%s","public":"%s"}`, realPrivHex, realPubHex)
	if _, err := DecodePrivateKey(realJSON); err != nil {
		t.Fatalf("DecodePrivateKey rejected a real JSON key: %v", err)
	}
}
