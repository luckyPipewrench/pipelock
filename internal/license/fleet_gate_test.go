// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/signing"
)

func mustIssue(t *testing.T, priv ed25519.PrivateKey, id string, features []string) string {
	t.Helper()
	tok, err := Issue(License{
		ID:        id,
		Email:     "test@example.com",
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		Features:  features,
	}, priv)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return tok
}

func newKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pub, priv
}

func writeTestCRLFile(t *testing.T, priv ed25519.PrivateKey, revokedID string) string {
	t.Helper()
	crl := testCRL(t, priv, time.Now().UTC(), revokedID)
	data, err := json.Marshal(crl)
	if err != nil {
		t.Fatalf("Marshal CRL: %v", err)
	}
	path := filepath.Join(t.TempDir(), "license.crl.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile(CRL): %v", err)
	}
	return path
}

func writeTestIntermediateFile(t *testing.T, rootPriv ed25519.PrivateKey, intermediatePub ed25519.PublicKey, serial string, notBefore, notAfter time.Time) string {
	t.Helper()
	im, err := SignIntermediate(IntermediatePayload{
		Serial:    serial,
		Purpose:   PurposeLicenseSigning,
		Algorithm: AlgorithmEd25519,
		PublicKey: hex.EncodeToString(intermediatePub),
		NotBefore: notBefore.Unix(),
		NotAfter:  notAfter.Unix(),
		IssuedAt:  notBefore.Unix(),
	}, rootPriv)
	if err != nil {
		t.Fatalf("SignIntermediate: %v", err)
	}
	data, err := json.Marshal(im)
	if err != nil {
		t.Fatalf("Marshal intermediate: %v", err)
	}
	path := filepath.Join(t.TempDir(), "intermediate.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile(intermediate): %v", err)
	}
	return path
}

func TestRequireFleet_NoLicenseFailsClosed(t *testing.T) {
	t.Setenv(EnvLicenseKey, "")
	t.Setenv(EnvLicensePublicKey, "")
	t.Setenv(EnvLicenseCRLFile, "")
	err := RequireFleet("", "")
	if !errors.Is(err, ErrFleetLicenseRequired) {
		t.Fatalf("RequireFleet with no license: want ErrFleetLicenseRequired, got %v", err)
	}
}

func TestRequireFleet_AgentsOnlyLicenseRejected(t *testing.T) {
	pub, priv := newKeyPair(t)
	tok := mustIssue(t, priv, "test-license", []string{FeatureAgents}) // Pro tier - no fleet
	err := RequireFleet(tok, hex.EncodeToString(pub))
	if !errors.Is(err, ErrFleetLicenseRequired) {
		t.Fatalf("RequireFleet with Pro license: want ErrFleetLicenseRequired, got %v", err)
	}
	if !strings.Contains(err.Error(), "does not include the fleet feature") {
		t.Errorf("error should explain missing feature; got %v", err)
	}
}

func TestRequireFleet_FleetFeatureAccepted(t *testing.T) {
	pub, priv := newKeyPair(t)
	tok := mustIssue(t, priv, "test-license", []string{FeatureAgents, FeatureFleet}) // Enterprise
	if err := RequireFleet(tok, hex.EncodeToString(pub)); err != nil {
		t.Fatalf("RequireFleet with Enterprise license: want nil, got %v", err)
	}
}

func TestRequireFleet_AssessOnlyLicenseRejected(t *testing.T) {
	pub, priv := newKeyPair(t)
	tok := mustIssue(t, priv, "test-license", []string{FeatureAssess}) // Assess product - not fleet
	err := RequireFleet(tok, hex.EncodeToString(pub))
	if !errors.Is(err, ErrFleetLicenseRequired) {
		t.Fatalf("RequireFleet with Assess license: want ErrFleetLicenseRequired, got %v", err)
	}
}

func TestRequireFleet_ExpiredLicenseRejected(t *testing.T) {
	pub, priv := newKeyPair(t)
	expired, err := Issue(License{
		ID:        "expired",
		Email:     "test@example.com",
		IssuedAt:  time.Now().Add(-2 * time.Hour).Unix(),
		ExpiresAt: time.Now().Add(-time.Hour).Unix(),
		Features:  []string{FeatureAgents, FeatureFleet},
	}, priv)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	gotErr := RequireFleet(expired, hex.EncodeToString(pub))
	if !errors.Is(gotErr, ErrFleetLicenseRequired) {
		t.Fatalf("expired fleet license: want ErrFleetLicenseRequired, got %v", gotErr)
	}
}

func TestRequireFleet_MissingPublicKeyFailsClosed(t *testing.T) {
	_, priv := newKeyPair(t)
	tok := mustIssue(t, priv, "test-license", []string{FeatureFleet})
	// EmbeddedPublicKey() returns nil in dev builds; with no env override
	// and no caller-supplied key, fail closed.
	t.Setenv(EnvLicensePublicKey, "")
	err := RequireFleet(tok, "")
	if !errors.Is(err, ErrFleetLicenseRequired) {
		t.Fatalf("missing pubkey: want ErrFleetLicenseRequired, got %v", err)
	}
}

func TestRequireFleet_ReadsLicenseFromEnv(t *testing.T) {
	pub, priv := newKeyPair(t)
	tok := mustIssue(t, priv, "test-license", []string{FeatureFleet})
	t.Setenv(EnvLicenseKey, tok)
	t.Setenv(EnvLicensePublicKey, hex.EncodeToString(pub))
	t.Setenv(EnvLicenseCRLFile, "")
	if err := RequireFleet("", ""); err != nil {
		t.Fatalf("env-supplied fleet license: want nil, got %v", err)
	}
}

func TestRequireFleet_InvalidSignatureRejected(t *testing.T) {
	pub1, _ := newKeyPair(t)
	_, priv2 := newKeyPair(t)
	tok := mustIssue(t, priv2, "test-license", []string{FeatureFleet}) // signed by key 2
	// Verify with key 1 -> signature mismatch.
	err := RequireFleet(tok, hex.EncodeToString(pub1))
	if !errors.Is(err, ErrFleetLicenseRequired) {
		t.Fatalf("wrong-key signature: want ErrFleetLicenseRequired, got %v", err)
	}
}

// The verifier public key override (PIPELOCK_LICENSE_PUBLIC_KEY /
// FleetVerifyInputs.PublicKeyHex) must accept BOTH the durable versioned
// license.pub format and a raw 64-hex key, while still failing closed on
// malformed input. These tests exercise the signing.ParsePublicKey routing.
func TestRequireFleet_AcceptsVersionedPublicKeyFile(t *testing.T) {
	pub, priv := newKeyPair(t)
	tok := mustIssue(t, priv, "lic_versioned_pub", []string{FeatureFleet})
	// The versioned form is exactly what signing.EncodePublicKey writes to a
	// license.pub file: "pipelock-ed25519-public-v1\n<base64>\n".
	versioned := signing.EncodePublicKey(pub)
	if err := RequireFleet(tok, versioned); err != nil {
		t.Fatalf("RequireFleet with versioned license.pub key: want nil, got %v", err)
	}
}

func TestRequireFleet_AcceptsRawHexPublicKey(t *testing.T) {
	pub, priv := newKeyPair(t)
	tok := mustIssue(t, priv, "lic_raw_hex_pub", []string{FeatureFleet})
	// Raw lowercase hex is the historical form and must keep working.
	if err := RequireFleet(tok, hex.EncodeToString(pub)); err != nil {
		t.Fatalf("RequireFleet with raw hex key: want nil, got %v", err)
	}
}

func TestRequireFleet_GarbagePublicKeyFailsClosed(t *testing.T) {
	_, priv := newKeyPair(t)
	tok := mustIssue(t, priv, "lic_garbage_pub", []string{FeatureFleet})
	t.Setenv(EnvLicensePublicKey, "")
	cases := map[string]string{
		"non-hex garbage":      "this-is-not-a-key",
		"odd-length hex":       "abc",
		"short hex":            hex.EncodeToString([]byte("too-short")),
		"versioned bad b64":    "pipelock-ed25519-public-v1\n!!!notbase64!!!",
		"versioned wrong size": "pipelock-ed25519-public-v1\n" + "QUJD", // base64("ABC"), 3 bytes
	}
	for name, key := range cases {
		t.Run(name, func(t *testing.T) {
			err := RequireFleet(tok, key)
			// An unparseable override leaves pubKey nil, so verification fails
			// closed exactly as a missing key does.
			if !errors.Is(err, ErrFleetLicenseRequired) {
				t.Fatalf("garbage public key %q: want ErrFleetLicenseRequired, got %v", key, err)
			}
		})
	}
}

func TestRequireFleet_VersionedWrongKeyFailsSignature(t *testing.T) {
	pub1, _ := newKeyPair(t)
	_, priv2 := newKeyPair(t)
	tok := mustIssue(t, priv2, "lic_versioned_wrong_key", []string{FeatureFleet}) // signed by key 2
	// A well-formed versioned key for the WRONG signer must still fail the
	// signature check; routing through ParsePublicKey must not loosen trust.
	err := RequireFleet(tok, signing.EncodePublicKey(pub1))
	if !errors.Is(err, ErrFleetLicenseRequired) {
		t.Fatalf("versioned wrong-key signature: want ErrFleetLicenseRequired, got %v", err)
	}
}

func TestVerifyFleet_CRLRejectsRevokedFleetLicense(t *testing.T) {
	pub, priv := newKeyPair(t)
	tok := mustIssue(t, priv, "lic_revoked", []string{FeatureAgents, FeatureFleet})
	crlFile := writeTestCRLFile(t, priv, "lic_revoked")

	_, err := VerifyFleet(tok, hex.EncodeToString(pub), crlFile)
	if !errors.Is(err, ErrFleetLicenseRequired) {
		t.Fatalf("revoked fleet license: want ErrFleetLicenseRequired, got %v", err)
	}
	if !errors.Is(err, ErrLicenseRevoked) {
		t.Fatalf("revoked fleet license: want ErrLicenseRevoked in chain, got %v", err)
	}
}

func TestVerifyFleet_CRLAllowsUnrevokedFleetLicense(t *testing.T) {
	pub, priv := newKeyPair(t)
	tok := mustIssue(t, priv, "lic_active", []string{FeatureAgents, FeatureFleet})
	crlFile := writeTestCRLFile(t, priv, "lic_other")

	got, err := VerifyFleet(tok, hex.EncodeToString(pub), crlFile)
	if err != nil {
		t.Fatalf("unrevoked fleet license with CRL: %v", err)
	}
	if got.ID != "lic_active" {
		t.Fatalf("license ID = %q, want lic_active", got.ID)
	}
}

func TestVerifyFleet_ReadsCRLFromEnv(t *testing.T) {
	pub, priv := newKeyPair(t)
	tok := mustIssue(t, priv, "lic_revoked", []string{FeatureAgents, FeatureFleet})
	t.Setenv(EnvLicenseCRLFile, writeTestCRLFile(t, priv, "lic_revoked"))

	_, err := VerifyFleet(tok, hex.EncodeToString(pub), "")
	if !errors.Is(err, ErrLicenseRevoked) {
		t.Fatalf("env CRL revoked fleet license: want ErrLicenseRevoked, got %v", err)
	}
}

func TestVerifyFleetWithIntermediate_ValidChainAccepted(t *testing.T) {
	rootPub, rootPriv := newKeyPair(t)
	intermediatePub, intermediatePriv := newKeyPair(t)
	now := time.Now().UTC()
	intermediateFile := writeTestIntermediateFile(t, rootPriv, intermediatePub, "im_fleet_valid", now.Add(-time.Minute), now.Add(time.Hour))
	tok := mustIssue(t, intermediatePriv, "lic_fleet_intermediate", []string{FeatureFleet})

	got, err := VerifyFleetWithIntermediate(tok, hex.EncodeToString(rootPub), "", intermediateFile)
	if err != nil {
		t.Fatalf("VerifyFleetWithIntermediate: %v", err)
	}
	if got.ID != "lic_fleet_intermediate" {
		t.Fatalf("license ID = %q, want lic_fleet_intermediate", got.ID)
	}
}

func TestVerifyFleetWithIntermediate_BadConfiguredCertFailsClosed(t *testing.T) {
	rootPub, intermediatePriv := newKeyPair(t)
	tok := mustIssue(t, intermediatePriv, "lic_fleet_bad_im", []string{FeatureFleet})
	intermediateFile := filepath.Join(t.TempDir(), "intermediate.json")
	if err := os.WriteFile(intermediateFile, []byte("{bad json"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := VerifyFleetWithIntermediate(tok, hex.EncodeToString(rootPub), "", intermediateFile)
	if !errors.Is(err, ErrFleetLicenseRequired) {
		t.Fatalf("bad intermediate: want ErrFleetLicenseRequired, got %v", err)
	}
	if !strings.Contains(err.Error(), "intermediate") {
		t.Fatalf("error should mention intermediate, got %v", err)
	}
}

func TestVerifyFleetWithIntermediate_LoadIntermediateErrorFailsClosed(t *testing.T) {
	rootPub, rootPriv := newKeyPair(t)
	tok := mustIssue(t, rootPriv, "lic_fleet_missing_im", []string{FeatureFleet})
	intermediateFile := filepath.Join(t.TempDir(), "missing-intermediate.json")

	_, err := VerifyFleetWithIntermediate(tok, hex.EncodeToString(rootPub), "", intermediateFile)
	if !errors.Is(err, ErrFleetLicenseRequired) {
		t.Fatalf("missing intermediate: want ErrFleetLicenseRequired, got %v", err)
	}
	if !strings.Contains(err.Error(), "loading intermediate certificate") {
		t.Fatalf("error should mention intermediate load failure, got %v", err)
	}
}

func TestVerifyFleetWithIntermediate_ReadsIntermediateFromEnv(t *testing.T) {
	rootPub, rootPriv := newKeyPair(t)
	intermediatePub, intermediatePriv := newKeyPair(t)
	now := time.Now().UTC()
	intermediateFile := writeTestIntermediateFile(t, rootPriv, intermediatePub, "im_fleet_env", now.Add(-time.Minute), now.Add(time.Hour))
	tok := mustIssue(t, intermediatePriv, "lic_fleet_env_im", []string{FeatureFleet})
	t.Setenv(EnvLicenseIntermediateFile, intermediateFile)

	if _, err := VerifyFleet(tok, hex.EncodeToString(rootPub), ""); err != nil {
		t.Fatalf("env intermediate fleet license: %v", err)
	}
}
