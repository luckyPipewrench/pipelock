// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
)

func mustIssue(t *testing.T, priv ed25519.PrivateKey, features []string) string {
	t.Helper()
	tok, err := Issue(License{
		ID:        "test-license",
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

func TestRequireFleet_NoLicenseFailsClosed(t *testing.T) {
	t.Setenv(EnvLicenseKey, "")
	t.Setenv(EnvLicensePublicKey, "")
	err := RequireFleet("", "")
	if !errors.Is(err, ErrFleetLicenseRequired) {
		t.Fatalf("RequireFleet with no license: want ErrFleetLicenseRequired, got %v", err)
	}
}

func TestRequireFleet_AgentsOnlyLicenseRejected(t *testing.T) {
	pub, priv := newKeyPair(t)
	tok := mustIssue(t, priv, []string{FeatureAgents}) // Pro tier — no fleet
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
	tok := mustIssue(t, priv, []string{FeatureAgents, FeatureFleet}) // Enterprise
	if err := RequireFleet(tok, hex.EncodeToString(pub)); err != nil {
		t.Fatalf("RequireFleet with Enterprise license: want nil, got %v", err)
	}
}

func TestRequireFleet_AssessOnlyLicenseRejected(t *testing.T) {
	pub, priv := newKeyPair(t)
	tok := mustIssue(t, priv, []string{FeatureAssess}) // Assess product — not fleet
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
	tok := mustIssue(t, priv, []string{FeatureFleet})
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
	tok := mustIssue(t, priv, []string{FeatureFleet})
	t.Setenv(EnvLicenseKey, tok)
	t.Setenv(EnvLicensePublicKey, hex.EncodeToString(pub))
	if err := RequireFleet("", ""); err != nil {
		t.Fatalf("env-supplied fleet license: want nil, got %v", err)
	}
}

func TestRequireFleet_InvalidSignatureRejected(t *testing.T) {
	pub1, _ := newKeyPair(t)
	_, priv2 := newKeyPair(t)
	tok := mustIssue(t, priv2, []string{FeatureFleet}) // signed by key 2
	// Verify with key 1 -> signature mismatch.
	err := RequireFleet(tok, hex.EncodeToString(pub1))
	if !errors.Is(err, ErrFleetLicenseRequired) {
		t.Fatalf("wrong-key signature: want ErrFleetLicenseRequired, got %v", err)
	}
}
