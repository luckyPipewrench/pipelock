// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// Tests in this file that mutate the package-level keyring variables
// are intentionally not parallel to avoid data races.

func setEmbeddedKeyringHexForTest(t *testing.T, defaultHex, keyringHex string) {
	t.Helper()

	origDefault := DefaultKeyringHex
	origKeyring := KeyringHex
	DefaultKeyringHex = defaultHex
	KeyringHex = keyringHex
	t.Cleanup(func() {
		DefaultKeyringHex = origDefault
		KeyringHex = origKeyring
	})
}

func TestEmbeddedKeyring_DefaultBuildIncludesOfficialKey(t *testing.T) {
	origKeyring := KeyringHex
	KeyringHex = ""
	t.Cleanup(func() { KeyringHex = origKeyring })

	want, err := hex.DecodeString(DefaultKeyringHex)
	if err != nil {
		t.Fatalf("decoding DefaultKeyringHex: %v", err)
	}

	got := EmbeddedKeyring()
	if len(got) != 1 {
		t.Fatalf("EmbeddedKeyring() returned %d keys, want 1", len(got))
	}
	if !got[0].Equal(ed25519.PublicKey(want)) {
		t.Fatalf("EmbeddedKeyring()[0] = %x, want %x", got[0], want)
	}
	if !IsOfficialKey(ed25519.PublicKey(want)) {
		t.Fatal("IsOfficialKey(DefaultKeyringHex) = false, want true")
	}

	randomPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating random key: %v", err)
	}
	if IsOfficialKey(randomPub) {
		t.Fatal("IsOfficialKey(random key) = true, want false")
	}
}

func TestEmbeddedKeyring(t *testing.T) {
	// Generate two test keys for multi-key tests.
	pub1, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating key 1: %v", err)
	}
	pub2, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating key 2: %v", err)
	}

	hex1 := hex.EncodeToString(pub1)
	hex2 := hex.EncodeToString(pub2)

	tests := []struct {
		name       string
		defaultHex string
		keyringHex string
		wantLen    int
	}{
		{
			name:    "empty vars return empty keyring",
			wantLen: 0,
		},
		{
			name:       "single valid default key",
			defaultHex: hex1,
			wantLen:    1,
		},
		{
			name:       "single valid ldflag key",
			keyringHex: hex1,
			wantLen:    1,
		},
		{
			name:       "multiple comma-separated keys in both vars",
			defaultHex: hex1,
			keyringHex: hex2,
			wantLen:    2,
		},
		{
			name:       "invalid hex entry skipped in default",
			defaultHex: "not-valid-hex," + hex1,
			wantLen:    1,
		},
		{
			name:       "invalid hex entry skipped in ldflag keyring",
			keyringHex: "not-valid-hex," + hex1,
			wantLen:    1,
		},
		{
			name:       "wrong length hex entry skipped in default",
			defaultHex: "aabbccdd," + hex1,
			wantLen:    1,
		},
		{
			name:       "wrong length hex entry skipped in ldflag keyring",
			keyringHex: "aabbccdd," + hex1,
			wantLen:    1,
		},
		{
			name:       "long wrong length hex entry skipped",
			keyringHex: strings.Repeat("ab", ed25519.PublicKeySize+512) + "," + hex1,
			wantLen:    1,
		},
		{
			name:       "all invalid entries returns empty",
			defaultHex: "bad",
			keyringHex: "also-bad",
			wantLen:    0,
		},
		{
			name:       "whitespace entries skipped",
			defaultHex: " , " + hex1 + " , ",
			wantLen:    1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setEmbeddedKeyringHexForTest(t, tt.defaultHex, tt.keyringHex)

			got := EmbeddedKeyring()
			if len(got) != tt.wantLen {
				t.Errorf("EmbeddedKeyring() returned %d keys, want %d", len(got), tt.wantLen)
			}
		})
	}
}

func TestEmbeddedKeyring_UnionDedupe(t *testing.T) {
	pub1, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating key 1: %v", err)
	}
	pub2, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating key 2: %v", err)
	}

	hex1 := hex.EncodeToString(pub1)
	hex2 := hex.EncodeToString(pub2)
	setEmbeddedKeyringHexForTest(t, hex1, hex1+","+hex2)

	got := EmbeddedKeyring()
	if len(got) != 2 {
		t.Fatalf("EmbeddedKeyring() returned %d keys, want 2", len(got))
	}
	if !got[0].Equal(pub1) {
		t.Errorf("EmbeddedKeyring()[0] = %x, want %x", got[0], pub1)
	}
	if !got[1].Equal(pub2) {
		t.Errorf("EmbeddedKeyring()[1] = %x, want %x", got[1], pub2)
	}
}

func TestEmbeddedKeyring_UnionDedupeMixedCase(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	lowerHex := hex.EncodeToString(pub)
	setEmbeddedKeyringHexForTest(t, strings.ToUpper(lowerHex), lowerHex)

	got := EmbeddedKeyring()
	if len(got) != 1 {
		t.Fatalf("EmbeddedKeyring() returned %d keys, want 1", len(got))
	}
	if !got[0].Equal(pub) {
		t.Errorf("EmbeddedKeyring()[0] = %x, want %x", got[0], pub)
	}
}

func TestIsOfficialKey(t *testing.T) {
	pub1, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	pub2, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	hex1 := hex.EncodeToString(pub1)

	setEmbeddedKeyringHexForTest(t, "", hex1)

	tests := []struct {
		name string
		key  ed25519.PublicKey
		want bool
	}{
		{
			name: "key in keyring returns true",
			key:  pub1,
			want: true,
		},
		{
			name: "key not in keyring returns false",
			key:  pub2,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsOfficialKey(tt.key); got != tt.want {
				t.Errorf("IsOfficialKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEmbeddedKeyringParticipatesInBundleVerification(t *testing.T) {
	keyringPub, keyringPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating keyring key: %v", err)
	}
	defaultPub, defaultPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating default key: %v", err)
	}

	tests := []struct {
		name       string
		defaultHex string
		keyringHex string
		pub        ed25519.PublicKey
		priv       ed25519.PrivateKey
	}{
		{
			name:       "ldflag keyring key verifies",
			keyringHex: hex.EncodeToString(keyringPub),
			pub:        keyringPub,
			priv:       keyringPriv,
		},
		{
			name:       "default keyring key verifies",
			defaultHex: hex.EncodeToString(defaultPub),
			pub:        defaultPub,
			priv:       defaultPriv,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setEmbeddedKeyringHexForTest(t, tt.defaultHex, tt.keyringHex)

			dir := writeSignedTestBundle(t, tt.priv)
			result, err := VerifyBundleSignature(dir, nil)
			if err != nil {
				t.Fatalf("VerifyBundleSignature() error: %v", err)
			}
			if result.Tier != TrustTierOfficial {
				t.Errorf("Tier = %q, want %q", result.Tier, TrustTierOfficial)
			}
			if result.SignerFingerprint != KeyFingerprint(tt.pub) {
				t.Errorf("SignerFingerprint = %q, want %q", result.SignerFingerprint, KeyFingerprint(tt.pub))
			}
		})
	}
}

func writeSignedTestBundle(t *testing.T, priv ed25519.PrivateKey) string {
	t.Helper()

	dir := t.TempDir()
	bundlePath := filepath.Join(dir, testBundleFilename)
	if err := os.WriteFile(bundlePath, []byte("name: test-bundle\n"), 0o600); err != nil {
		t.Fatalf("writing bundle: %v", err)
	}

	sig, err := signing.SignFile(bundlePath, priv)
	if err != nil {
		t.Fatalf("signing bundle: %v", err)
	}
	if err := signing.SaveSignature(sig, bundlePath+signing.SigExtension); err != nil {
		t.Fatalf("saving signature: %v", err)
	}

	return dir
}

func TestKeyFingerprint(t *testing.T) {
	t.Parallel()

	// Use a known key to verify hex encoding.
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	got := KeyFingerprint(pub)
	want := hex.EncodeToString(pub)

	if got != want {
		t.Errorf("KeyFingerprint() = %q, want %q", got, want)
	}

	// Verify it's lowercase.
	for _, c := range got {
		if c >= 'A' && c <= 'F' {
			t.Errorf("KeyFingerprint() contains uppercase hex: %q", got)
			break
		}
	}
}
