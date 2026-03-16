// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// Tests in this file that mutate the package-level KeyringHex variable
// are intentionally not parallel to avoid data races.

const testBundleFilename = "bundle.yaml"

func TestVerifyBundleSignature_Official(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	orig := KeyringHex
	KeyringHex = hex.EncodeToString(pub)
	t.Cleanup(func() { KeyringHex = orig })

	dir := t.TempDir()
	bundlePath := filepath.Join(dir, testBundleFilename)
	bundleContent := []byte("name: test-bundle\n")
	if err := os.WriteFile(bundlePath, bundleContent, 0o600); err != nil {
		t.Fatalf("writing bundle: %v", err)
	}

	sig, err := signing.SignFile(bundlePath, priv)
	if err != nil {
		t.Fatalf("signing bundle: %v", err)
	}
	if err := signing.SaveSignature(sig, bundlePath+signing.SigExtension); err != nil {
		t.Fatalf("saving signature: %v", err)
	}

	result, err := VerifyBundleSignature(dir, nil)
	if err != nil {
		t.Fatalf("VerifyBundleSignature() error: %v", err)
	}

	if result.Tier != TrustTierOfficial {
		t.Errorf("Tier = %q, want %q", result.Tier, TrustTierOfficial)
	}
	if result.SignerFingerprint != hex.EncodeToString(pub) {
		t.Errorf("SignerFingerprint = %q, want %q", result.SignerFingerprint, hex.EncodeToString(pub))
	}
}

func TestVerifyBundleSignature_ThirdParty(t *testing.T) {
	// Official key (in keyring) is different from signer.
	officialPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating official key: %v", err)
	}

	orig := KeyringHex
	KeyringHex = hex.EncodeToString(officialPub)
	t.Cleanup(func() { KeyringHex = orig })

	// Third-party key signs the bundle.
	thirdPub, thirdPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating third-party key: %v", err)
	}

	dir := t.TempDir()
	bundlePath := filepath.Join(dir, testBundleFilename)
	bundleContent := []byte("name: third-party-bundle\n")
	if err := os.WriteFile(bundlePath, bundleContent, 0o600); err != nil {
		t.Fatalf("writing bundle: %v", err)
	}

	sig, err := signing.SignFile(bundlePath, thirdPriv)
	if err != nil {
		t.Fatalf("signing bundle: %v", err)
	}
	if err := signing.SaveSignature(sig, bundlePath+signing.SigExtension); err != nil {
		t.Fatalf("saving signature: %v", err)
	}

	trustedKeys := []config.TrustedKey{
		{Name: "test-third-party", PublicKey: hex.EncodeToString(thirdPub)},
	}

	result, err := VerifyBundleSignature(dir, trustedKeys)
	if err != nil {
		t.Fatalf("VerifyBundleSignature() error: %v", err)
	}

	if result.Tier != TrustTierThirdParty {
		t.Errorf("Tier = %q, want %q", result.Tier, TrustTierThirdParty)
	}
	if result.SignerFingerprint != hex.EncodeToString(thirdPub) {
		t.Errorf("SignerFingerprint = %q, want %q", result.SignerFingerprint, hex.EncodeToString(thirdPub))
	}
}

func TestVerifyBundleSignature_NoSigFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bundlePath := filepath.Join(dir, testBundleFilename)
	if err := os.WriteFile(bundlePath, []byte("content\n"), 0o600); err != nil {
		t.Fatalf("writing bundle: %v", err)
	}

	_, err := VerifyBundleSignature(dir, nil)
	if err == nil {
		t.Fatal("expected error for missing sig file, got nil")
	}
}

func TestVerifyBundleSignature_WrongSigner(t *testing.T) {
	// Sign with a key that's not in the keyring and not in trustedKeys.
	_, signerPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating signer key: %v", err)
	}

	// Put a different key in the keyring.
	otherPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating other key: %v", err)
	}
	orig := KeyringHex
	KeyringHex = hex.EncodeToString(otherPub)
	t.Cleanup(func() { KeyringHex = orig })

	dir := t.TempDir()
	bundlePath := filepath.Join(dir, testBundleFilename)
	if err := os.WriteFile(bundlePath, []byte("content\n"), 0o600); err != nil {
		t.Fatalf("writing bundle: %v", err)
	}

	sig, err := signing.SignFile(bundlePath, signerPriv)
	if err != nil {
		t.Fatalf("signing bundle: %v", err)
	}
	if err := signing.SaveSignature(sig, bundlePath+signing.SigExtension); err != nil {
		t.Fatalf("saving signature: %v", err)
	}

	_, err = VerifyBundleSignature(dir, nil)
	if err == nil {
		t.Fatal("expected error for unrecognized signer, got nil")
	}
}

func TestCheckSignerPinning(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		pinnedFP      string
		currentFP     string
		allowRotation bool
		wantErr       bool
	}{
		{
			name:          "matching fingerprints",
			pinnedFP:      "aabbccdd",
			currentFP:     "aabbccdd",
			allowRotation: false,
			wantErr:       false,
		},
		{
			name:          "mismatch without rotation allowed",
			pinnedFP:      "aabbccdd",
			currentFP:     "11223344",
			allowRotation: false,
			wantErr:       true,
		},
		{
			name:          "mismatch with rotation allowed",
			pinnedFP:      "aabbccdd",
			currentFP:     "11223344",
			allowRotation: true,
			wantErr:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := CheckSignerPinning(tt.pinnedFP, tt.currentFP, tt.allowRotation)
			if (err != nil) != tt.wantErr {
				t.Errorf("CheckSignerPinning() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestVerifyIntegrity_SignedValid(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	orig := KeyringHex
	KeyringHex = hex.EncodeToString(pub)
	t.Cleanup(func() { KeyringHex = orig })

	dir := t.TempDir()
	bundlePath := filepath.Join(dir, testBundleFilename)
	bundleContent := []byte("name: signed-bundle\n")
	if err := os.WriteFile(bundlePath, bundleContent, 0o600); err != nil {
		t.Fatalf("writing bundle: %v", err)
	}

	sig, err := signing.SignFile(bundlePath, priv)
	if err != nil {
		t.Fatalf("signing bundle: %v", err)
	}
	if err := signing.SaveSignature(sig, bundlePath+signing.SigExtension); err != nil {
		t.Fatalf("saving signature: %v", err)
	}

	signerFP := hex.EncodeToString(pub)
	hash := sha256.Sum256(bundleContent)
	expectedSHA := hex.EncodeToString(hash[:])

	err = VerifyIntegrity(dir, false, signerFP, expectedSHA, nil)
	if err != nil {
		t.Fatalf("VerifyIntegrity() signed valid: %v", err)
	}
}

func TestVerifyIntegrity_SignedTampered(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	orig := KeyringHex
	KeyringHex = hex.EncodeToString(pub)
	t.Cleanup(func() { KeyringHex = orig })

	dir := t.TempDir()
	bundlePath := filepath.Join(dir, testBundleFilename)
	originalContent := []byte("name: signed-bundle\n")
	if err := os.WriteFile(bundlePath, originalContent, 0o600); err != nil {
		t.Fatalf("writing bundle: %v", err)
	}

	sig, err := signing.SignFile(bundlePath, priv)
	if err != nil {
		t.Fatalf("signing bundle: %v", err)
	}
	if err := signing.SaveSignature(sig, bundlePath+signing.SigExtension); err != nil {
		t.Fatalf("saving signature: %v", err)
	}

	// Tamper with the bundle after signing.
	tamperedContent := []byte("name: TAMPERED\n")
	if err := os.WriteFile(bundlePath, tamperedContent, 0o600); err != nil {
		t.Fatalf("writing tampered bundle: %v", err)
	}

	signerFP := hex.EncodeToString(pub)
	hash := sha256.Sum256(originalContent)
	expectedSHA := hex.EncodeToString(hash[:])

	err = VerifyIntegrity(dir, false, signerFP, expectedSHA, nil)
	if err == nil {
		t.Fatal("expected error for tampered signed bundle, got nil")
	}
}

func TestVerifyIntegrity_UnsignedValid(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bundlePath := filepath.Join(dir, testBundleFilename)
	bundleContent := []byte("name: unsigned-bundle\n")
	if err := os.WriteFile(bundlePath, bundleContent, 0o600); err != nil {
		t.Fatalf("writing bundle: %v", err)
	}

	hash := sha256.Sum256(bundleContent)
	expectedSHA := hex.EncodeToString(hash[:])

	err := VerifyIntegrity(dir, true, "", expectedSHA, nil)
	if err != nil {
		t.Fatalf("VerifyIntegrity() unsigned valid: %v", err)
	}
}

func TestVerifyIntegrity_UnsignedTampered(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bundlePath := filepath.Join(dir, testBundleFilename)
	if err := os.WriteFile(bundlePath, []byte("name: unsigned-bundle\n"), 0o600); err != nil {
		t.Fatalf("writing bundle: %v", err)
	}

	// Provide a SHA that doesn't match the file.
	wrongSHA := "0000000000000000000000000000000000000000000000000000000000000000"
	err := VerifyIntegrity(dir, true, "", wrongSHA, nil)
	if err == nil {
		t.Fatal("expected error for tampered unsigned bundle, got nil")
	}
}
