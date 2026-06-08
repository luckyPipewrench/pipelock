// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/license"
)

// realValidAgentsLicense issues a genuine, currently-valid agents-feature token
// and returns it with its verifier public key (hex). No CRL.
func realValidAgentsLicense(t *testing.T) (token, pubHex string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	now := time.Now().UTC()
	tok, err := license.Issue(license.License{
		ID:        "reload-valid-agents",
		Email:     "test@example.com",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(),
		Features:  []string{license.FeatureAgents},
	}, priv)
	if err != nil {
		t.Fatalf("license.Issue: %v", err)
	}
	return tok, hex.EncodeToString(pub)
}

// realRevokedAgentsLicense issues a genuine agents-feature token AND a signed
// CRL that revokes it, writes the CRL to disk, and returns the token, its
// verifier public key (hex), and the CRL path. Verifying the token against the
// CRL yields a PROVEN revocation (ErrLicenseRevoked).
func realRevokedAgentsLicense(t *testing.T) (token, pubHex, crlPath string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	now := time.Now().UTC()
	const id = "reload-revoked-agents"
	tok, err := license.Issue(license.License{
		ID:        id,
		Email:     "test@example.com",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(),
		Features:  []string{license.FeatureAgents},
	}, priv)
	if err != nil {
		t.Fatalf("license.Issue: %v", err)
	}
	crl, err := license.SignCRL(license.CRLPayload{
		Version:   license.CRLVersion,
		IssuedAt:  now.Add(-time.Minute).Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(),
		Revoked: []license.RevokedLicense{{
			ID:        id,
			Reason:    "test revocation",
			RevokedAt: now.Unix(),
		}},
	}, priv)
	if err != nil {
		t.Fatalf("license.SignCRL: %v", err)
	}
	data, err := json.Marshal(crl)
	if err != nil {
		t.Fatalf("Marshal CRL: %v", err)
	}
	crlPath = filepath.Join(t.TempDir(), "revoke.crl.json")
	if err := os.WriteFile(crlPath, data, 0o600); err != nil {
		t.Fatalf("WriteFile(CRL): %v", err)
	}
	return tok, hex.EncodeToString(pub), crlPath
}

// TestServer_ReloadUnverifiableLicenseInputPreservesAgents proves the Item B
// fix on the agent surface: a reload that introduces an UNVERIFIABLE new
// license input (here a fat-fingered, unreadable CRL path) must NOT tear down a
// legitimately-licensed agent surface. License inputs are restart-only, so the
// effective entitlement is the old verified one; tearing down on a typo would be
// a denial-of-service, not fail-closed security. The named agents are preserved
// restart-only and a warning is surfaced.
func TestServer_ReloadUnverifiableLicenseInputPreservesAgents(t *testing.T) {
	s, buf := newTestServer(t, nil)
	tok, pubHex := realValidAgentsLicense(t)
	oldCfg := s.proxy.CurrentConfig()
	oldCfg.Agents = map[string]config.AgentProfile{
		"agent-a": {Mode: config.ModeStrict},
	}
	oldCfg.LicenseKey = tok
	oldCfg.LicensePublicKey = pubHex
	oldCfg.LicenseExpiresAt = time.Now().Add(time.Hour).Unix()

	// Simulate EnforceLicenseGate's strip at reload-Load (no _default profile, so
	// the failed verification leaves Agents nil) while the new CRL input is
	// unreadable. The effective license is unchanged.
	newCfg := oldCfg.Clone()
	newCfg.Agents = nil
	newCfg.LicenseCRLFile = filepath.Join(t.TempDir(), "missing.crl.json")

	if err := s.Reload(newCfg); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	live := s.proxy.CurrentConfig()
	if live.Agents == nil {
		t.Fatal("unverifiable new license input tore down a still-entitled agent surface (DoS on typo)")
	}
	if _, ok := live.Agents["agent-a"]; !ok {
		t.Fatalf("named agent not preserved restart-only: %+v", live.Agents)
	}
	if !buf.contains("new license inputs could not be verified") {
		t.Fatalf("stderr missing unverifiable-input warning:\n%s", buf.String())
	}
	if buf.contains("license revoked agents, shutting down agent listeners") {
		t.Fatalf("must not log a revocation shutdown for an unverifiable input:\n%s", buf.String())
	}
}
