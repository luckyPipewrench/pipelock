// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"
)

// Tests in this file that mutate the package-level KeyringHex variable
// are intentionally not parallel to avoid data races.

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
		name     string
		hexValue string
		wantLen  int
	}{
		{
			name:     "empty KeyringHex returns empty keyring",
			hexValue: "",
			wantLen:  0,
		},
		{
			name:     "single valid key",
			hexValue: hex1,
			wantLen:  1,
		},
		{
			name:     "multiple comma-separated keys",
			hexValue: hex1 + "," + hex2,
			wantLen:  2,
		},
		{
			name:     "invalid hex entry skipped",
			hexValue: "not-valid-hex," + hex1,
			wantLen:  1,
		},
		{
			name:     "wrong length hex entry skipped",
			hexValue: "aabbccdd," + hex1,
			wantLen:  1,
		},
		{
			name:     "all invalid entries returns empty",
			hexValue: "bad,also-bad",
			wantLen:  0,
		},
		{
			name:     "whitespace entries skipped",
			hexValue: " , " + hex1 + " , ",
			wantLen:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orig := KeyringHex
			KeyringHex = tt.hexValue
			t.Cleanup(func() { KeyringHex = orig })

			got := EmbeddedKeyring()
			if len(got) != tt.wantLen {
				t.Errorf("EmbeddedKeyring() returned %d keys, want %d", len(got), tt.wantLen)
			}
		})
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

	orig := KeyringHex
	KeyringHex = hex1
	t.Cleanup(func() { KeyringHex = orig })

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
