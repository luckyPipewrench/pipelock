// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
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

// ---------- VerifyIntegrityBytes coverage tests ----------

func TestVerifyIntegrityBytes_UnsignedSHAMismatch(t *testing.T) {
	t.Parallel()

	data := []byte("name: unsigned-bundle\n")
	wrongSHA := "0000000000000000000000000000000000000000000000000000000000000000"

	err := VerifyIntegrityBytes(data, t.TempDir(), true, "", wrongSHA, nil)
	if err == nil {
		t.Fatal("expected error for SHA mismatch on unsigned bundle")
	}
	if !strings.Contains(err.Error(), "SHA-256 mismatch") {
		t.Errorf("error should mention SHA-256 mismatch, got: %v", err)
	}
}

func TestVerifyIntegrityBytes_SignedSHAMismatch(t *testing.T) {
	// Non-parallel: mutates KeyringHex.
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	orig := KeyringHex
	KeyringHex = hex.EncodeToString(pub)
	t.Cleanup(func() { KeyringHex = orig })

	data := []byte("name: signed-bundle\n")
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, testBundleFilename)
	if err := os.WriteFile(bundlePath, data, 0o600); err != nil {
		t.Fatalf("writing bundle: %v", err)
	}

	sig, err := signing.SignFile(bundlePath, priv)
	if err != nil {
		t.Fatalf("signing bundle: %v", err)
	}
	if err := signing.SaveSignature(sig, bundlePath+signing.SigExtension); err != nil {
		t.Fatalf("saving signature: %v", err)
	}

	// Provide a wrong SHA-256 digest. The SHA check runs before signature
	// verification, so it should fail with SHA mismatch.
	wrongSHA := "0000000000000000000000000000000000000000000000000000000000000000"
	signerFP := hex.EncodeToString(pub)

	err = VerifyIntegrityBytes(data, dir, false, signerFP, wrongSHA, nil)
	if err == nil {
		t.Fatal("expected error for SHA mismatch on signed bundle")
	}
	if !strings.Contains(err.Error(), "SHA-256 mismatch") {
		t.Errorf("error should mention SHA-256 mismatch, got: %v", err)
	}
}

func TestVerifyIntegrityBytes_SignedHappyPath(t *testing.T) {
	// Non-parallel: mutates KeyringHex.
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	orig := KeyringHex
	KeyringHex = hex.EncodeToString(pub)
	t.Cleanup(func() { KeyringHex = orig })

	data := []byte("name: signed-bundle\n")
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, testBundleFilename)
	if err := os.WriteFile(bundlePath, data, 0o600); err != nil {
		t.Fatalf("writing bundle: %v", err)
	}

	sig, err := signing.SignFile(bundlePath, priv)
	if err != nil {
		t.Fatalf("signing bundle: %v", err)
	}
	if err := signing.SaveSignature(sig, bundlePath+signing.SigExtension); err != nil {
		t.Fatalf("saving signature: %v", err)
	}

	hash := sha256.Sum256(data)
	expectedSHA := hex.EncodeToString(hash[:])
	signerFP := hex.EncodeToString(pub)

	err = VerifyIntegrityBytes(data, dir, false, signerFP, expectedSHA, nil)
	if err != nil {
		t.Fatalf("VerifyIntegrityBytes() signed happy path: %v", err)
	}
}

// ---------- verifySignedIntegrity SHA-256 mismatch ----------

func TestVerifyIntegrity_SignedSHA256Mismatch(t *testing.T) {
	// Non-parallel: mutates KeyringHex.
	// Signature is valid but the lock file has a different SHA-256 digest.
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	orig := KeyringHex
	KeyringHex = hex.EncodeToString(pub)
	t.Cleanup(func() { KeyringHex = orig })

	dir := t.TempDir()
	bundlePath := filepath.Join(dir, testBundleFilename)
	bundleContent := []byte("name: signed-sha-mismatch\n")
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
	// Provide a wrong SHA-256 that does not match the actual content.
	wrongSHA := "0000000000000000000000000000000000000000000000000000000000000000"

	err = VerifyIntegrity(dir, false, signerFP, wrongSHA, nil)
	if err == nil {
		t.Fatal("expected error for SHA-256 mismatch on signed bundle with valid signature")
	}
	if !strings.Contains(err.Error(), "SHA-256 mismatch") {
		t.Errorf("error should mention SHA-256 mismatch, got: %v", err)
	}
}

// ---------- VerifyIntegrityBytes signer fingerprint mismatch ----------

func TestVerifyIntegrityBytes_SignerFingerprintMismatch(t *testing.T) {
	// Non-parallel: mutates KeyringHex.
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	orig := KeyringHex
	KeyringHex = hex.EncodeToString(pub)
	t.Cleanup(func() { KeyringHex = orig })

	data := []byte("name: signer-fp-mismatch\n")
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, testBundleFilename)
	if err := os.WriteFile(bundlePath, data, 0o600); err != nil {
		t.Fatalf("writing bundle: %v", err)
	}

	sig, err := signing.SignFile(bundlePath, priv)
	if err != nil {
		t.Fatalf("signing bundle: %v", err)
	}
	if err := signing.SaveSignature(sig, bundlePath+signing.SigExtension); err != nil {
		t.Fatalf("saving signature: %v", err)
	}

	hash := sha256.Sum256(data)
	expectedSHA := hex.EncodeToString(hash[:])
	wrongSignerFP := "wrong-fingerprint-that-does-not-match"

	err = VerifyIntegrityBytes(data, dir, false, wrongSignerFP, expectedSHA, nil)
	if err == nil {
		t.Fatal("expected error for signer fingerprint mismatch")
	}
	if !strings.Contains(err.Error(), "signer fingerprint") {
		t.Errorf("error should mention signer fingerprint mismatch, got: %v", err)
	}
}

// ---------- verifySignedIntegrity signer fingerprint mismatch ----------

func TestVerifyIntegrity_SignerFingerprintMismatch(t *testing.T) {
	// Non-parallel: mutates KeyringHex.
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	orig := KeyringHex
	KeyringHex = hex.EncodeToString(pub)
	t.Cleanup(func() { KeyringHex = orig })

	dir := t.TempDir()
	bundlePath := filepath.Join(dir, testBundleFilename)
	bundleContent := []byte("name: fp-mismatch-test\n")
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

	hash := sha256.Sum256(bundleContent)
	expectedSHA := hex.EncodeToString(hash[:])
	wrongFP := "aaaa0000bbbb1111cccc2222dddd3333"

	err = VerifyIntegrity(dir, false, wrongFP, expectedSHA, nil)
	if err == nil {
		t.Fatal("expected error for signer fingerprint mismatch")
	}
	if !strings.Contains(err.Error(), "signer fingerprint") {
		t.Errorf("error should mention signer fingerprint, got: %v", err)
	}
}

// ---------- findSigner coverage tests ----------

func TestFindSigner_TrustedKeyPath(t *testing.T) {
	// Non-parallel: mutates KeyringHex.

	// Official key in keyring (NOT the signer).
	officialPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating official key: %v", err)
	}

	orig := KeyringHex
	KeyringHex = hex.EncodeToString(officialPub)
	t.Cleanup(func() { KeyringHex = orig })

	// Third-party key signs the data.
	thirdPub, thirdPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating third-party key: %v", err)
	}

	data := []byte("test-data-for-trusted-key-path")
	sig := ed25519.Sign(thirdPriv, data)

	trustedKeys := []config.TrustedKey{
		{Name: "test-third-party", PublicKey: hex.EncodeToString(thirdPub)},
	}

	result, err := findSigner(data, sig, trustedKeys)
	if err != nil {
		t.Fatalf("findSigner() error: %v", err)
	}

	if result.Tier != TrustTierThirdParty {
		t.Errorf("Tier = %q, want %q", result.Tier, TrustTierThirdParty)
	}
	if result.SignerFingerprint != hex.EncodeToString(thirdPub) {
		t.Errorf("SignerFingerprint = %q, want %q", result.SignerFingerprint, hex.EncodeToString(thirdPub))
	}
}
