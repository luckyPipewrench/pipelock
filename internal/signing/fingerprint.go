// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// FingerprintAlgorithm is the prefix used for all key fingerprints in
// pipelock signed artifacts.
const FingerprintAlgorithm = "sha256"

// fingerprintAlgorithmPrefix is the canonical wire prefix for fingerprint
// strings: "sha256:".
const fingerprintAlgorithmPrefix = FingerprintAlgorithm + ":"

// sha256DigestHexLen is the expected length of a SHA-256 digest in lowercase
// hex encoding: 32 bytes = 64 hex characters.
const sha256DigestHexLen = 64

// Sentinel errors for fingerprint operations.
var (
	// ErrFingerprintMismatch indicates that a fingerprint comparison failed.
	ErrFingerprintMismatch = errors.New("fingerprint mismatch")

	// ErrFingerprintFormat indicates that a fingerprint string is malformed:
	// missing prefix, wrong algorithm, bad hex, or wrong digest length.
	ErrFingerprintFormat = errors.New("malformed fingerprint")

	// ErrFingerprintLength indicates that the public key input has the wrong
	// byte length (expected exactly ed25519.PublicKeySize = 32 bytes).
	ErrFingerprintLength = errors.New("invalid public key length for fingerprint")
)

// Fingerprint returns the canonical pipelock key fingerprint for an Ed25519
// public key.
//
// Format (locked):
//
//	"sha256:" + lowercase hex of sha256 over the raw 32-byte public key
//
// The preimage is the raw 32-byte Ed25519 public key. NEVER hash hex text.
// NEVER hash an encoded form.
//
// Cross-implementation: the Python verifier computes the same value byte for
// byte. Changing this format requires a roster schema_version bump.
//
// Returns ErrFingerprintLength if pubKey is not exactly ed25519.PublicKeySize
// (32) bytes long. The function does not panic on malformed input.
func Fingerprint(pubKey []byte) (string, error) {
	if len(pubKey) != ed25519.PublicKeySize {
		return "", fmt.Errorf("%w: got %d bytes, want %d",
			ErrFingerprintLength, len(pubKey), ed25519.PublicKeySize)
	}
	digest := sha256.Sum256(pubKey)
	return fingerprintAlgorithmPrefix + hex.EncodeToString(digest[:]), nil
}

// ParseFingerprint splits a fingerprint string into algorithm and lowercase
// hex digest.
//
// Returns ErrFingerprintFormat for:
//   - missing ":" separator
//   - empty algorithm or empty digest
//   - unknown algorithm (only "sha256" is accepted)
//   - non-hex characters in the digest
//   - wrong digest length (sha256 = 32 bytes = 64 hex chars)
//
// Uppercase hex is accepted on input but the returned hex is always lowercase.
func ParseFingerprint(s string) (algorithm, hexDigest string, err error) {
	idx := strings.IndexByte(s, ':')
	if idx < 0 {
		return "", "", fmt.Errorf("%w: missing algorithm prefix", ErrFingerprintFormat)
	}

	algorithm = s[:idx]
	hexDigest = s[idx+1:]

	if algorithm == "" {
		return "", "", fmt.Errorf("%w: empty algorithm", ErrFingerprintFormat)
	}
	if hexDigest == "" {
		return "", "", fmt.Errorf("%w: empty digest", ErrFingerprintFormat)
	}
	if algorithm != FingerprintAlgorithm {
		return "", "", fmt.Errorf("%w: unsupported algorithm %q", ErrFingerprintFormat, algorithm)
	}

	// Validate hex encoding by attempting decode.
	digestBytes, decErr := hex.DecodeString(hexDigest)
	if decErr != nil {
		return "", "", fmt.Errorf("%w: invalid hex in digest: %w", ErrFingerprintFormat, decErr)
	}

	if len(digestBytes) != sha256.Size {
		return "", "", fmt.Errorf("%w: digest length %d hex chars, want %d",
			ErrFingerprintFormat, len(hexDigest), sha256DigestHexLen)
	}

	// Normalize to lowercase (hex.EncodeToString always returns lowercase).
	hexDigest = hex.EncodeToString(digestBytes)

	return algorithm, hexDigest, nil
}

// VerifyFingerprint computes Fingerprint(pubKey) and compares it to expected
// in constant time on the digest bytes. Returns nil on match.
//
// On mismatch returns ErrFingerprintMismatch. On invalid input (bad expected
// format or wrong pubKey length) returns the underlying ErrFingerprintFormat /
// ErrFingerprintLength.
//
// Constant-time comparison (crypto/subtle.ConstantTimeCompare) defends against
// fingerprint-oracle timing attacks when expected is operator-controlled. An
// attacker with repeated verify attempts could otherwise learn the fingerprint
// byte-by-byte from early-exit comparison timing.
func VerifyFingerprint(pubKey []byte, expected string) error {
	_, expectedHex, err := ParseFingerprint(expected)
	if err != nil {
		return err
	}

	computed, err := Fingerprint(pubKey)
	if err != nil {
		return err
	}

	// Extract the hex portion of the computed fingerprint for comparison.
	// We know the format is valid because Fingerprint succeeded.
	computedHex := computed[len(fingerprintAlgorithmPrefix):]

	// Decode both hex strings to raw bytes for constant-time comparison.
	// Both are validated hex at this point, so errors are impossible.
	expectedBytes, _ := hex.DecodeString(expectedHex)
	computedBytes, _ := hex.DecodeString(computedHex)

	if subtle.ConstantTimeCompare(expectedBytes, computedBytes) != 1 {
		return fmt.Errorf("%w: got %s, want %s", ErrFingerprintMismatch, computed, expected)
	}
	return nil
}
