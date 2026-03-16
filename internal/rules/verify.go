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

// VerifyBundleSignature verifies the signature on bundleDir/bundle.yaml
// against the embedded keyring and any additional trusted keys.
//
// It loads bundle.yaml and bundle.yaml.sig, then tries each key in the
// embedded keyring first (official tier), then each trusted key (third-party
// tier). Returns an error if the signature file is missing, malformed, or
// no key matches.
func VerifyBundleSignature(bundleDir string, trustedKeys []config.TrustedKey) (*VerifyResult, error) {
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

	// Try embedded keyring first (official tier).
	for _, key := range EmbeddedKeyring() {
		if ed25519.Verify(key, data, sig) {
			return &VerifyResult{
				Tier:              TrustTierOfficial,
				SignerFingerprint: KeyFingerprint(key),
			}, nil
		}
	}

	// Try trusted keys (third-party tier).
	for _, tk := range trustedKeys {
		raw, err := hex.DecodeString(tk.PublicKey)
		if err != nil {
			continue
		}

		if len(raw) != ed25519.PublicKeySize {
			continue
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

	return fmt.Errorf("signer fingerprint mismatch: pinned %q, got %q (set allow_rotation to permit key changes)", pinnedFP, currentFP)
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
	bundlePath := filepath.Join(bundleDir, bundleFilename)

	if unsigned {
		return verifyUnsignedIntegrity(bundlePath, expectedSHA256)
	}

	return verifySignedIntegrity(bundleDir, signerFP, trustedKeys)
}

// verifySignedIntegrity performs Ed25519 signature verification and signer
// fingerprint matching.
func verifySignedIntegrity(bundleDir, signerFP string, trustedKeys []config.TrustedKey) error {
	result, err := VerifyBundleSignature(bundleDir, trustedKeys)
	if err != nil {
		return fmt.Errorf("integrity check: %w", err)
	}

	if result.SignerFingerprint != signerFP {
		return fmt.Errorf("integrity check: signer fingerprint %q does not match expected %q", result.SignerFingerprint, signerFP)
	}

	return nil
}

// verifyUnsignedIntegrity computes SHA-256 of the bundle file and compares
// it to the expected hash.
func verifyUnsignedIntegrity(bundlePath, expectedSHA256 string) error {
	data, err := os.ReadFile(filepath.Clean(bundlePath))
	if err != nil {
		return fmt.Errorf("integrity check: reading bundle: %w", err)
	}

	hash := sha256.Sum256(data)
	actual := hex.EncodeToString(hash[:])

	if actual != expectedSHA256 {
		return fmt.Errorf("integrity check: SHA-256 mismatch: expected %q, got %q", expectedSHA256, actual)
	}

	return nil
}
