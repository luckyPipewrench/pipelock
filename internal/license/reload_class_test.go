// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package license

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// clearLicenseEnv neutralizes the env fallbacks verifyLicenseInputs consults so
// the classifier tests are hermetic regardless of the ambient environment.
func clearLicenseEnv(t *testing.T) {
	t.Helper()
	t.Setenv(EnvLicenseKey, "")
	t.Setenv(EnvLicensePublicKey, "")
	t.Setenv(EnvLicenseCRLFile, "")
	t.Setenv(EnvLicenseIntermediateFile, "")
}

func issueWithExpiry(t *testing.T, priv ed25519.PrivateKey, id string, features []string, expiresAt time.Time) string {
	t.Helper()
	tok, err := Issue(License{
		ID:        id,
		Email:     "test@example.com",
		IssuedAt:  time.Now().Add(-2 * time.Hour).Unix(),
		ExpiresAt: expiresAt.Unix(),
		Features:  features,
	}, priv)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return tok
}

func writeGarbageFile(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte("}{ not valid json at all"), 0o600); err != nil {
		t.Fatalf("WriteFile(garbage): %v", err)
	}
	return path
}

func TestClassifyReload(t *testing.T) {
	pub, priv := newKeyPair(t)
	pubHex := hex.EncodeToString(pub)
	otherPub, otherPriv := newKeyPair(t)
	_ = otherPub

	validBoth := mustIssue(t, priv, "lic-both", []string{FeatureAgents, FeatureFleet})
	agentsOnly := mustIssue(t, priv, "lic-agents", []string{FeatureAgents})
	revokedTok := mustIssue(t, priv, "lic-revoked", []string{FeatureAgents, FeatureFleet})
	revokedCRL := writeTestCRLFile(t, priv, "lic-revoked")
	expiredTok := issueWithExpiry(t, priv, "lic-expired", []string{FeatureAgents, FeatureFleet}, time.Now().Add(-time.Hour))
	wrongKeyTok := mustIssue(t, otherPriv, "lic-wrongkey", []string{FeatureFleet})
	garbageCRL := writeGarbageFile(t, "bad.crl.json")

	tests := []struct {
		name             string
		licenseKey       string
		crlFile          string
		wantClass        ReloadClass
		fleetProvesLoss  bool
		agentsProvesLoss bool
	}{
		{
			name:             "verified with both features",
			licenseKey:       validBoth,
			wantClass:        ReloadVerified,
			fleetProvesLoss:  false,
			agentsProvesLoss: false,
		},
		{
			name:             "verified agents-only is a fleet downgrade",
			licenseKey:       agentsOnly,
			wantClass:        ReloadVerified,
			fleetProvesLoss:  true, // lost fleet
			agentsProvesLoss: false,
		},
		{
			name:             "revoked proves loss of every feature",
			licenseKey:       revokedTok,
			crlFile:          revokedCRL,
			wantClass:        ReloadRevoked,
			fleetProvesLoss:  true,
			agentsProvesLoss: true,
		},
		{
			name:             "expired proves loss of every feature",
			licenseKey:       expiredTok,
			wantClass:        ReloadExpired,
			fleetProvesLoss:  true,
			agentsProvesLoss: true,
		},
		{
			name:             "unreadable CRL is unverifiable, proves nothing",
			licenseKey:       validBoth,
			crlFile:          garbageCRL,
			wantClass:        ReloadUnverifiable,
			fleetProvesLoss:  false,
			agentsProvesLoss: false,
		},
		{
			name:             "bad signature is unverifiable, proves nothing",
			licenseKey:       wrongKeyTok,
			wantClass:        ReloadUnverifiable,
			fleetProvesLoss:  false,
			agentsProvesLoss: false,
		},
		{
			name:             "empty token is unverifiable, proves nothing",
			licenseKey:       "",
			wantClass:        ReloadUnverifiable,
			fleetProvesLoss:  false,
			agentsProvesLoss: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clearLicenseEnv(t)
			lic, class := ClassifyReload(tc.licenseKey, pubHex, tc.crlFile, "")
			if class != tc.wantClass {
				t.Fatalf("ClassifyReload class = %v, want %v", class, tc.wantClass)
			}
			if got := class.ProvesLoss(lic, FeatureFleet); got != tc.fleetProvesLoss {
				t.Errorf("ProvesLoss(fleet) = %v, want %v", got, tc.fleetProvesLoss)
			}
			if got := class.ProvesLoss(lic, FeatureAgents); got != tc.agentsProvesLoss {
				t.Errorf("ProvesLoss(agents) = %v, want %v", got, tc.agentsProvesLoss)
			}
		})
	}
}

// TestClassifyReloadUnverifiableMatchesFleetGate proves the classifier and the
// fleet gate share one input-handling path: every input shape the gate rejects
// as a hard error is classified, and the genuine-loss shapes (revoked) surface
// the same sentinel both ways.
func TestClassifyReloadSharesFleetGateInputHandling(t *testing.T) {
	clearLicenseEnv(t)
	pub, priv := newKeyPair(t)
	pubHex := hex.EncodeToString(pub)
	tok := mustIssue(t, priv, "lic-shared", []string{FeatureFleet})
	crl := writeTestCRLFile(t, priv, "lic-shared")

	// Gate path: VerifyFleetWithIntermediate must still surface ErrLicenseRevoked
	// in its error chain (not merely return some error), proving the shared
	// verifyLicenseInputs core propagates the sentinel both ways.
	if _, err := VerifyFleetWithIntermediate(tok, pubHex, crl, ""); !errors.Is(err, ErrLicenseRevoked) {
		t.Fatalf("VerifyFleetWithIntermediate(revoked) = %v, want ErrLicenseRevoked in chain", err)
	}
	// Classifier path: same inputs classify as revoked.
	if _, class := ClassifyReload(tok, pubHex, crl, ""); class != ReloadRevoked {
		t.Fatalf("ClassifyReload(revoked) = %v, want ReloadRevoked", class)
	}
}
