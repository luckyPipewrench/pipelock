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
	tok := mustIssue(t, priv, "test-license", []string{FeatureAgents}) // Pro tier — no fleet
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
	tok := mustIssue(t, priv, "test-license", []string{FeatureAssess}) // Assess product — not fleet
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
