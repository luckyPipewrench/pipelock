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

// Tests in this file that mutate the package-level keyring variables
// are intentionally not parallel to avoid data races.

const testBundleFilename = "bundle.yaml"

func TestVerifyBundleSignature_Official(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	setEmbeddedKeyringHexForTest(t, "", hex.EncodeToString(pub))

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

	setEmbeddedKeyringHexForTest(t, "", hex.EncodeToString(officialPub))

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
	setEmbeddedKeyringHexForTest(t, "", hex.EncodeToString(otherPub))

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

	setEmbeddedKeyringHexForTest(t, "", hex.EncodeToString(pub))

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

	setEmbeddedKeyringHexForTest(t, "", hex.EncodeToString(pub))

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

func TestVerifyIntegrity_SignedMissingSignatureFailsClosed(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bundlePath := filepath.Join(dir, testBundleFilename)
	bundleContent := []byte("name: signed-missing-signature\n")
	if err := os.WriteFile(bundlePath, bundleContent, 0o600); err != nil {
		t.Fatalf("writing bundle: %v", err)
	}
	hash := sha256.Sum256(bundleContent)

	err := VerifyIntegrity(dir, false, "missing-signer", hex.EncodeToString(hash[:]), nil)
	if err == nil {
		t.Fatal("expected missing signature to fail closed")
	}
	if !strings.Contains(err.Error(), "loading signature") {
		t.Fatalf("VerifyIntegrity error = %v, want missing signature", err)
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

func TestVerifyIntegrity_UnsignedDisabledByPolicyFailsClosed(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bundlePath := filepath.Join(dir, testBundleFilename)
	bundleContent := []byte("name: unsigned-bundle\n")
	if err := os.WriteFile(bundlePath, bundleContent, 0o600); err != nil {
		t.Fatalf("writing bundle: %v", err)
	}

	hash := sha256.Sum256(bundleContent)
	expectedSHA := hex.EncodeToString(hash[:])

	err := VerifyIntegrityWithPolicy(dir, true, "", expectedSHA, TrustPolicy{})
	if err == nil {
		t.Fatal("expected unsigned bundle to fail closed when embedded keys are disabled")
	}
	if !strings.Contains(err.Error(), "unsigned bundles are disabled") {
		t.Fatalf("VerifyIntegrityWithPolicy error = %v, want unsigned disabled", err)
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

func TestVerifyIntegrityBytes_UnsignedMalformedSHAFailsClosed(t *testing.T) {
	t.Parallel()

	data := []byte("name: unsigned-bundle\n")
	hash := sha256.Sum256(data)
	actual := hex.EncodeToString(hash[:])
	tests := []struct {
		name string
		sha  string
	}{
		{name: "whitespace only", sha: "   "},
		{name: "wrong length", sha: "deadbeef"},
		{name: "non hex", sha: strings.Repeat("z", sha256.Size*2)},
		{name: "uppercase", sha: strings.ToUpper(actual)},
		{name: "0x prefix", sha: "0x" + actual},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyIntegrityBytes(data, t.TempDir(), true, "", tt.sha, nil)
			if err == nil {
				t.Fatal("expected malformed SHA-256 to fail closed")
			}
			if !strings.Contains(err.Error(), "SHA-256 mismatch") {
				t.Fatalf("VerifyIntegrityBytes error = %v, want SHA-256 mismatch", err)
			}
		})
	}
}

func TestVerifyIntegrityBytes_UnsignedMissingSHAFailsClosed(t *testing.T) {
	t.Parallel()

	err := VerifyIntegrityBytes([]byte("name: unsigned-bundle\n"), t.TempDir(), true, "", "", nil)
	if err == nil {
		t.Fatal("expected missing SHA-256 error for unsigned bundle")
	}
	if !strings.Contains(err.Error(), "missing SHA-256") {
		t.Errorf("error should mention missing SHA-256, got: %v", err)
	}
}

func TestVerifyIntegrityBytes_UnsignedDisabledByPolicyFailsClosed(t *testing.T) {
	t.Parallel()

	data := []byte("name: unsigned-bundle\n")
	hash := sha256.Sum256(data)
	expectedSHA := hex.EncodeToString(hash[:])

	err := VerifyIntegrityBytesWithPolicy(data, t.TempDir(), true, "", expectedSHA, TrustPolicy{})
	if err == nil {
		t.Fatal("expected unsigned bytes to fail closed when embedded keys are disabled")
	}
	if !strings.Contains(err.Error(), "unsigned bundles are disabled") {
		t.Fatalf("VerifyIntegrityBytesWithPolicy error = %v, want unsigned disabled", err)
	}
}

func TestVerifyIntegrityBytes_SignedSHAMismatch(t *testing.T) {
	// Non-parallel: mutates keyring globals.
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	setEmbeddedKeyringHexForTest(t, "", hex.EncodeToString(pub))

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
	// Non-parallel: mutates keyring globals.
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	setEmbeddedKeyringHexForTest(t, "", hex.EncodeToString(pub))

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
	// Non-parallel: mutates keyring globals.
	// Signature is valid but the lock file has a different SHA-256 digest.
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	setEmbeddedKeyringHexForTest(t, "", hex.EncodeToString(pub))

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
	// Non-parallel: mutates keyring globals.
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	setEmbeddedKeyringHexForTest(t, "", hex.EncodeToString(pub))

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
	// Non-parallel: mutates keyring globals.
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	setEmbeddedKeyringHexForTest(t, "", hex.EncodeToString(pub))

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
	// Non-parallel: mutates keyring globals.

	// Official key in keyring (NOT the signer).
	officialPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating official key: %v", err)
	}

	setEmbeddedKeyringHexForTest(t, "", hex.EncodeToString(officialPub))

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

	result, err := findSigner(data, sig, DefaultTrustPolicy(trustedKeys))
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

func TestVerifyBundleSignatureWithPolicy_DisabledEmbeddedKeyFailsClosed(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	setEmbeddedKeyringHexForTest(t, "", hex.EncodeToString(pub))

	dir := writeSignedTestBundle(t, priv)
	_, err = VerifyBundleSignatureWithPolicy(dir, TrustPolicy{})
	if err == nil {
		t.Fatal("expected de-trusted embedded key to fail closed")
	}
	if !strings.Contains(err.Error(), "no matching signer") {
		t.Fatalf("VerifyBundleSignatureWithPolicy error = %v, want no matching signer", err)
	}
}

func TestVerifyBundleSignatureWithPolicy_DisabledEmbeddedKeyCanBeExplicitlyTrustedAsThirdParty(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	setEmbeddedKeyringHexForTest(t, "", hex.EncodeToString(pub))

	dir := writeSignedTestBundle(t, priv)
	result, err := VerifyBundleSignatureWithPolicy(dir, TrustPolicy{
		TrustedKeys: []config.TrustedKey{
			{Name: "private-root", PublicKey: hex.EncodeToString(pub)},
		},
	})
	if err != nil {
		t.Fatalf("VerifyBundleSignatureWithPolicy() error: %v", err)
	}
	if result.Tier != TrustTierThirdParty {
		t.Fatalf("Tier = %q, want %q", result.Tier, TrustTierThirdParty)
	}
}

func TestVerifyIntegrity_SignedEmptySignatureFailsClosed(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bundlePath := filepath.Join(dir, testBundleFilename)
	bundleContent := []byte("name: signed-empty-signature\n")
	if err := os.WriteFile(bundlePath, bundleContent, 0o600); err != nil {
		t.Fatalf("writing bundle: %v", err)
	}
	// An EMPTY signature file is a distinct path from a MISSING one: the file
	// loads but cannot produce a valid signature, so verification must fail.
	if err := os.WriteFile(bundlePath+signing.SigExtension, []byte{}, 0o600); err != nil {
		t.Fatalf("writing empty signature: %v", err)
	}
	hash := sha256.Sum256(bundleContent)

	err := VerifyIntegrity(dir, false, "some-signer", hex.EncodeToString(hash[:]), nil)
	if err == nil {
		t.Fatal("expected empty signature to fail closed")
	}
	// Assert the specific empty-signature path (loads but is an invalid-length
	// signature), not a generic or missing-file failure.
	if !strings.Contains(err.Error(), "loading signature") {
		t.Fatalf("VerifyIntegrity error = %v, want a signature-loading failure", err)
	}
}
