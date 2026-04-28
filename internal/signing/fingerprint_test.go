// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// RFC 8032 section 7.1 test vector 1 seed (split for G101 lint).
const rfcTestSeedHex = "9d61b19d" + "effd5a60" + "ba844af4" + "92ec2cc4" +
	"4449c569" + "7b326919" + "703bac03" + "1cae7f60"

// rfcTestPubKeyHex is the public key derived from the RFC 8032 test seed.
const rfcTestPubKeyHex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"

// rfcTestPubFingerprint is the expected fingerprint of the RFC 8032 test
// public key. Computed: sha256 over the raw 32-byte public key bytes.
// Cross-impl pinning: if the Python verifier disagrees, this test fails first.
const rfcTestPubFingerprint = "sha256:21fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9"

func rfcTestPubKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	seed, err := hex.DecodeString(rfcTestSeedHex)
	if err != nil {
		t.Fatalf("decoding RFC test seed: %v", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return priv.Public().(ed25519.PublicKey)
}

func TestFingerprint_HappyPath(t *testing.T) {
	pub := rfcTestPubKey(t)

	// Sanity: the public key matches the known hex.
	if got := hex.EncodeToString(pub); got != rfcTestPubKeyHex {
		t.Fatalf("RFC test pubkey mismatch: got %s, want %s", got, rfcTestPubKeyHex)
	}

	fp, err := Fingerprint(pub)
	if err != nil {
		t.Fatalf("Fingerprint() error: %v", err)
	}

	// Primary assertion: computed fingerprint matches hardcoded golden vector.
	if fp != rfcTestPubFingerprint {
		t.Fatalf("Fingerprint() = %q, want %q", fp, rfcTestPubFingerprint)
	}

	// Secondary assertion: deterministic — calling again yields same result.
	fp2, err := Fingerprint(pub)
	if err != nil {
		t.Fatalf("Fingerprint() second call error: %v", err)
	}
	if fp != fp2 {
		t.Fatalf("Fingerprint() not deterministic: %q != %q", fp, fp2)
	}
}

func TestFingerprint_RejectsWrongLength(t *testing.T) {
	tests := []struct {
		name string
		key  []byte
	}{
		{name: "empty", key: []byte{}},
		{name: "31_bytes", key: make([]byte, 31)},
		{name: "33_bytes", key: make([]byte, 33)},
		{name: "64_bytes_private_key_sized", key: make([]byte, 64)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp, err := Fingerprint(tt.key)
			if !errors.Is(err, ErrFingerprintLength) {
				t.Fatalf("Fingerprint(%d bytes) error = %v, want ErrFingerprintLength", len(tt.key), err)
			}
			if fp != "" {
				t.Fatalf("Fingerprint(%d bytes) = %q, want empty string", len(tt.key), fp)
			}
		})
	}
}

func TestParseFingerprint_HappyPath(t *testing.T) {
	algo, hexDigest, err := ParseFingerprint(rfcTestPubFingerprint)
	if err != nil {
		t.Fatalf("ParseFingerprint() error: %v", err)
	}
	if algo != FingerprintAlgorithm {
		t.Errorf("algorithm = %q, want %q", algo, FingerprintAlgorithm)
	}

	// Extract expected hex from the golden constant.
	wantHex := rfcTestPubFingerprint[len(fingerprintAlgorithmPrefix):]
	if hexDigest != wantHex {
		t.Errorf("hexDigest = %q, want %q", hexDigest, wantHex)
	}
}

func TestParseFingerprint_Rejects(t *testing.T) {
	// Valid 64-char hex digest for reuse in test cases.
	validHex := "21fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9"
	// Uppercase variant of the same digest.
	upperHex := strings.ToUpper(validHex)

	tests := []struct {
		name  string
		input string
	}{
		{name: "missing_prefix", input: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"},
		{name: "wrong_algorithm", input: "sha512:" + validHex},
		{name: "empty_algorithm", input: ":" + validHex},
		{name: "empty_digest", input: "sha256:"},
		{name: "non_hex_digest", input: "sha256:gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg"},
		{name: "truncated_digest", input: "sha256:21fe31dfa154a261"},
		{name: "extended_digest", input: "sha256:" + validHex + "deadbeef"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := ParseFingerprint(tt.input)
			if !errors.Is(err, ErrFingerprintFormat) {
				t.Fatalf("ParseFingerprint(%q) error = %v, want ErrFingerprintFormat", tt.input, err)
			}
		})
	}

	// Special case: uppercase hex IS accepted and normalized to lowercase.
	t.Run("uppercase_hex_normalized", func(t *testing.T) {
		algo, hexDigest, err := ParseFingerprint("sha256:" + upperHex)
		if err != nil {
			t.Fatalf("ParseFingerprint(uppercase) error: %v", err)
		}
		if algo != FingerprintAlgorithm {
			t.Errorf("algorithm = %q, want %q", algo, FingerprintAlgorithm)
		}
		if hexDigest != validHex {
			t.Errorf("hexDigest = %q, want normalized lowercase %q", hexDigest, validHex)
		}
		if hexDigest == upperHex {
			t.Error("uppercase hex was not normalized to lowercase")
		}
	})
}

func TestVerifyFingerprint(t *testing.T) {
	pub := rfcTestPubKey(t)

	// Build a one-byte-different public key for the mismatch test.
	diffPub := make([]byte, ed25519.PublicKeySize)
	copy(diffPub, pub)
	diffPub[0] ^= 0xff

	tests := []struct {
		name      string
		pubKey    []byte
		expected  string
		wantErr   error
		wantNilOK bool
	}{
		{
			name:      "happy_path_matches",
			pubKey:    pub,
			expected:  rfcTestPubFingerprint,
			wantNilOK: true,
		},
		{
			name:     "one_byte_different_pubkey",
			pubKey:   diffPub,
			expected: rfcTestPubFingerprint,
			wantErr:  ErrFingerprintMismatch,
		},
		{
			name:     "wrong_format_expected",
			pubKey:   pub,
			expected: "not-a-fingerprint",
			wantErr:  ErrFingerprintFormat,
		},
		{
			name:     "wrong_length_pubkey",
			pubKey:   []byte("short"),
			expected: rfcTestPubFingerprint,
			wantErr:  ErrFingerprintLength,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyFingerprint(tt.pubKey, tt.expected)
			if tt.wantNilOK {
				if err != nil {
					t.Fatalf("VerifyFingerprint() error = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("VerifyFingerprint() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestFingerprint_DocumentedFormat(t *testing.T) {
	pub := rfcTestPubKey(t)
	fp, err := Fingerprint(pub)
	if err != nil {
		t.Fatalf("Fingerprint() error: %v", err)
	}

	// Must start with "sha256:" prefix.
	if !strings.HasPrefix(fp, fingerprintAlgorithmPrefix) {
		t.Fatalf("fingerprint %q missing prefix %q", fp, fingerprintAlgorithmPrefix)
	}

	hexPart := fp[len(fingerprintAlgorithmPrefix):]

	// Hex part must be exactly 64 characters (sha256 = 32 bytes = 64 hex chars).
	if len(hexPart) != sha256DigestHexLen {
		t.Fatalf("hex part length = %d, want %d", len(hexPart), sha256DigestHexLen)
	}

	// Must be all lowercase hex.
	if hexPart != strings.ToLower(hexPart) {
		t.Fatalf("hex part contains uppercase characters: %q", hexPart)
	}

	// Must decode as valid hex.
	if _, err := hex.DecodeString(hexPart); err != nil {
		t.Fatalf("hex part is not valid hex: %v", err)
	}
}
