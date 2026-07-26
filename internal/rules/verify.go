// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// Trust tier constants identify how a bundle's signature was verified.
const (
	TrustTierOfficial   = "official"
	TrustTierThirdParty = "third-party"
	TrustTierUnsigned   = "unsigned"
)

// bundleFilename is the expected name of the bundle manifest file.
const bundleFilename = "bundle.yaml"

// VerifyResult holds the outcome of signature verification.
type VerifyResult struct {
	// Tier indicates trust level: official, third-party, or unsigned.
	Tier string
	// SignerFingerprint is the lowercase hex fingerprint of the key that
	// produced the valid signature.
	SignerFingerprint string
}

// TrustPolicy is the pair of inputs that decides WHICH signing keys a rule bundle
// may be verified against: the operator's configured third-party keys, and whether
// the compiled-in official keyring is trusted at all.
//
// They travel together as one value because using either without the other is always
// a bug. Passing trusted keys while dropping the embedded-keyring decision silently
// re-trusts the vendor key an operator asked to remove; passing the flag without the
// keys silently empties the trust set. Separate parameters let a caller do both by
// omission, which is exactly the failure this type prevents.
type TrustPolicy struct {
	TrustedKeys       []config.TrustedKey
	TrustEmbeddedKeys bool
}

// DefaultTrustPolicy is the backward-compatible policy: the operator's keys plus the
// embedded official keyring, which is what every caller got before the keyring became
// optional.
func DefaultTrustPolicy(trustedKeys []config.TrustedKey) TrustPolicy {
	return TrustPolicy{TrustedKeys: trustedKeys, TrustEmbeddedKeys: true}
}

// VerifyBundleSignature verifies the signature on bundleDir/bundle.yaml
// against the embedded keyring and any additional trusted keys.
//
// It loads bundle.yaml and bundle.yaml.sig, then tries each key in the
// embedded keyring first (official tier), then each trusted key (third-party
// tier). Returns an error if the signature file is missing, malformed, or
// no key matches.
func VerifyBundleSignature(bundleDir string, trustedKeys []config.TrustedKey) (*VerifyResult, error) {
	return VerifyBundleSignatureWithPolicy(bundleDir, DefaultTrustPolicy(trustedKeys))
}

// VerifyBundleSignatureWithPolicy verifies a bundle signature with an explicit
// embedded-keyring trust policy.
func VerifyBundleSignatureWithPolicy(bundleDir string, policy TrustPolicy) (*VerifyResult, error) {
	bundlePath := filepath.Join(bundleDir, bundleFilename)
	sigPath := bundlePath + signing.SigExtension

	data, err := os.ReadFile(filepath.Clean(bundlePath))
	if err != nil {
		return nil, fmt.Errorf("reading bundle: %w", err)
	}

	sig, err := signing.LoadSignature(sigPath)
	if err != nil {
		return nil, fmt.Errorf("loading bundle signature: %w", err)
	}

	return VerifyBundleSignatureBytes(data, sig, policy)
}

// VerifyBundleSignatureBytes verifies pre-read bundle bytes against a detached
// Ed25519 signature and explicit trust policy.
func VerifyBundleSignatureBytes(data, sig []byte, policy TrustPolicy) (*VerifyResult, error) {
	return findSigner(data, sig, policy)
}

// CheckSignerPinning verifies that the current signer fingerprint matches
// the pinned fingerprint from a lock file. If allowRotation is true,
// mismatches are permitted (the caller should update the lock file).
func CheckSignerPinning(pinnedFP, currentFP string, allowRotation bool) error {
	if pinnedFP == currentFP {
		return nil
	}

	if allowRotation {
		return nil
	}

	return fmt.Errorf("signer fingerprint mismatch: pinned %q, got %q (use --allow-key-rotation to permit key changes)", pinnedFP, currentFP)
}

// VerifyIntegrity checks the integrity of a bundle directory.
//
// For signed bundles (unsigned == false): performs full Ed25519 verification
// of bundle.yaml against bundle.yaml.sig, resolving the signer from the
// embedded keyring and trusted keys, then verifying it matches signerFP.
//
// For unsigned bundles: computes SHA-256 of bundle.yaml and compares it
// to expectedSHA256.
//
// Returns an error on verification failure. The caller decides whether to
// skip the bundle or abort.
func VerifyIntegrity(bundleDir string, unsigned bool, signerFP, expectedSHA256 string, trustedKeys []config.TrustedKey) error {
	return VerifyIntegrityWithPolicy(bundleDir, unsigned, signerFP, expectedSHA256, DefaultTrustPolicy(trustedKeys))
}

// VerifyIntegrityWithPolicy checks bundle integrity with an explicit
// embedded-keyring trust policy.
func VerifyIntegrityWithPolicy(bundleDir string, unsigned bool, signerFP, expectedSHA256 string, policy TrustPolicy) error {
	bundlePath := filepath.Join(bundleDir, bundleFilename)

	if unsigned {
		return verifyUnsignedIntegrity(bundlePath, expectedSHA256, policy.TrustEmbeddedKeys)
	}

	return verifySignedIntegrity(bundleDir, signerFP, expectedSHA256, policy)
}

// VerifyIntegrityBytes checks integrity using pre-read bundle data, avoiding
// TOCTOU issues where the file could change between read and verify. Used by
// the loader which reads bundle.yaml once and needs to verify those exact bytes.
func VerifyIntegrityBytes(data []byte, bundleDir string, unsigned bool, signerFP, expectedSHA256 string, trustedKeys []config.TrustedKey) error {
	return VerifyIntegrityBytesWithPolicy(data, bundleDir, unsigned, signerFP, expectedSHA256, DefaultTrustPolicy(trustedKeys))
}

// VerifyIntegrityBytesWithPolicy checks integrity using pre-read bundle data
// and an explicit embedded-keyring trust policy.
func VerifyIntegrityBytesWithPolicy(data []byte, bundleDir string, unsigned bool, signerFP, expectedSHA256 string, policy TrustPolicy) error {
	if unsigned {
		return verifyUnsignedIntegrityBytes(data, expectedSHA256, policy.TrustEmbeddedKeys)
	}

	// SHA-256 check applies to signed bundles when the lock pins a digest.
	if expectedSHA256 != "" {
		hash := sha256.Sum256(data)
		actual := hex.EncodeToString(hash[:])
		if actual != expectedSHA256 {
			return fmt.Errorf("integrity check: SHA-256 mismatch: expected %q, got %q", expectedSHA256, actual)
		}
	}

	// Signature verification: load sig file and verify against pre-read data.
	sigPath := filepath.Join(bundleDir, bundleFilename) + signing.SigExtension
	sig, err := signing.LoadSignature(sigPath)
	if err != nil {
		return fmt.Errorf("integrity check: loading signature: %w", err)
	}

	result, err := findSigner(data, sig, policy)
	if err != nil {
		return fmt.Errorf("integrity check: %w", err)
	}

	if result.SignerFingerprint != signerFP {
		return fmt.Errorf("integrity check: signer fingerprint %q does not match expected %q", result.SignerFingerprint, signerFP)
	}

	return nil
}

// findSigner is the single key-scanning helper. It tries the embedded keyring
// (official tier) then trusted keys (third-party tier) and returns the first
// match. Both VerifyBundleSignature (disk I/O) and VerifyIntegrityBytes
// (pre-read data) delegate here so the trust path cannot drift.
func findSigner(data, sig []byte, policy TrustPolicy) (*VerifyResult, error) {
	if policy.TrustEmbeddedKeys {
		for _, key := range EmbeddedKeyring() {
			if ed25519.Verify(key, data, sig) {
				return &VerifyResult{
					Tier:              TrustTierOfficial,
					SignerFingerprint: KeyFingerprint(key),
				}, nil
			}
		}
	}
	for i, tk := range policy.TrustedKeys {
		if strings.TrimSpace(tk.Name) == "" {
			return nil, fmt.Errorf("bundle signature: trusted key %d name is empty", i)
		}
		if len(tk.PublicKey) != ed25519.PublicKeySize*2 {
			return nil, fmt.Errorf("bundle signature: trusted key %d %q public_key must be exactly 64 hex chars", i, tk.Name)
		}
		if tk.PublicKey != strings.ToLower(tk.PublicKey) {
			return nil, fmt.Errorf("bundle signature: trusted key %d %q public_key must be lowercase hex", i, tk.Name)
		}
		raw, err := hex.DecodeString(tk.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("bundle signature: trusted key %d %q public_key invalid hex: %w", i, tk.Name, err)
		}
		if len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("bundle signature: trusted key %d %q public_key must decode to 32 bytes", i, tk.Name)
		}
		key := ed25519.PublicKey(raw)
		if ed25519.Verify(key, data, sig) {
			return &VerifyResult{
				Tier:              TrustTierThirdParty,
				SignerFingerprint: KeyFingerprint(key),
			}, nil
		}
	}
	return nil, fmt.Errorf("bundle signature: no matching signer found")
}

// verifySignedIntegrity reads the bundle once, verifies the signature and
// SHA-256 digest against that single snapshot, and checks the signer fingerprint.
// This eliminates the TOCTOU window that would exist if the file were read twice.
func verifySignedIntegrity(bundleDir, signerFP, expectedSHA256 string, policy TrustPolicy) error {
	bundlePath := filepath.Join(bundleDir, bundleFilename)
	data, err := os.ReadFile(filepath.Clean(bundlePath))
	if err != nil {
		return fmt.Errorf("integrity check: reading bundle: %w", err)
	}

	sigPath := bundlePath + signing.SigExtension
	sig, err := signing.LoadSignature(sigPath)
	if err != nil {
		return fmt.Errorf("integrity check: loading signature: %w", err)
	}

	result, err := findSigner(data, sig, policy)
	if err != nil {
		return fmt.Errorf("integrity check: %w", err)
	}

	if result.SignerFingerprint != signerFP {
		return fmt.Errorf("integrity check: signer fingerprint %q does not match expected %q", result.SignerFingerprint, signerFP)
	}

	if expectedSHA256 != "" {
		hash := sha256.Sum256(data)
		actual := hex.EncodeToString(hash[:])
		if actual != expectedSHA256 {
			return fmt.Errorf("integrity check: SHA-256 mismatch: expected %q, got %q", expectedSHA256, actual)
		}
	}

	return nil
}

// verifyUnsignedIntegrity computes SHA-256 of the bundle file and compares
// it to the expected hash.
func verifyUnsignedIntegrity(bundlePath, expectedSHA256 string, allowUnsigned bool) error {
	data, err := os.ReadFile(filepath.Clean(bundlePath))
	if err != nil {
		return fmt.Errorf("integrity check: reading bundle: %w", err)
	}

	return verifyUnsignedIntegrityBytes(data, expectedSHA256, allowUnsigned)
}

func verifyUnsignedIntegrityBytes(data []byte, expectedSHA256 string, allowUnsigned bool) error {
	if !allowUnsigned {
		return fmt.Errorf("integrity check: unsigned bundles are disabled when rules.trust_embedded_keys is false")
	}
	if expectedSHA256 == "" {
		return fmt.Errorf("integrity check: missing SHA-256 for unsigned bundle")
	}

	hash := sha256.Sum256(data)
	actual := hex.EncodeToString(hash[:])

	if actual != expectedSHA256 {
		return fmt.Errorf("integrity check: SHA-256 mismatch: expected %q, got %q", expectedSHA256, actual)
	}

	return nil
}
