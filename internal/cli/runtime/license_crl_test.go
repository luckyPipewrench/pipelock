// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
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

func TestCheckLicenseCRLRevokedFailsClosed(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	lic := license.License{
		ID:        "lic_runtime_revoked",
		Email:     "runtime@example.com",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(24 * time.Hour).Unix(),
		Features:  []string{license.FeatureAgents},
	}
	token, err := license.Issue(lic, priv)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := license.SignCRL(license.CRLPayload{
		Version:   license.CRLVersion,
		IssuedAt:  now.Add(-time.Hour).Unix(),
		ExpiresAt: now.Add(24 * time.Hour).Unix(),
		Revoked: []license.RevokedLicense{{
			ID:        lic.ID,
			RevokedAt: now.Add(-time.Hour).Unix(),
		}},
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	crlData, err := json.Marshal(crl)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	crlPath := filepath.Join(dir, "crl.json")
	if err := os.WriteFile(crlPath, crlData, 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := writeServerTestConfig(t, "mode: balanced\nlicense_key: "+token+"\nlicense_public_key: "+hex.EncodeToString(pub)+"\nlicense_crl_file: "+crlPath+"\n")
	s, _ := newTestServer(t, func(opts *ServerOpts) {
		opts.ConfigFile = cfgPath
	})

	failClosed, err := s.checkLicenseCRL()
	if err == nil {
		t.Fatal("expected revoked license error")
	}
	if !failClosed {
		t.Fatal("revoked license should fail closed")
	}
}

func TestCheckLicenseCRLUnreadableFailsClosed(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	lic := license.License{
		ID:        "lic_runtime_missing_crl",
		Email:     "runtime@example.com",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(24 * time.Hour).Unix(),
		Features:  []string{license.FeatureAgents},
	}
	token, err := license.Issue(lic, priv)
	if err != nil {
		t.Fatal(err)
	}
	crlPath := filepath.Join(t.TempDir(), "missing-crl.json")
	cfgPath := writeServerTestConfig(t, "mode: balanced\nlicense_key: "+token+"\nlicense_public_key: "+hex.EncodeToString(pub)+"\nlicense_crl_file: "+crlPath+"\n")
	s, _ := newTestServer(t, func(opts *ServerOpts) {
		opts.ConfigFile = cfgPath
	})

	failClosed, err := s.checkLicenseCRL()
	if err == nil {
		t.Fatal("expected missing CRL error")
	}
	if !failClosed {
		t.Fatal("unreadable configured CRL should fail closed")
	}
}

func TestCheckLicenseCRLAllowsValidUnrevokedLicense(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	lic := license.License{
		ID:        "lic_runtime_active",
		Email:     "runtime@example.com",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(24 * time.Hour).Unix(),
		Features:  []string{license.FeatureAgents},
	}
	token, err := license.Issue(lic, priv)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := license.SignCRL(license.CRLPayload{
		Version:   license.CRLVersion,
		IssuedAt:  now.Add(-time.Hour).Unix(),
		ExpiresAt: now.Add(24 * time.Hour).Unix(),
		Revoked: []license.RevokedLicense{{
			ID:        "lic_other",
			RevokedAt: now.Add(-time.Hour).Unix(),
		}},
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	crlData, err := json.Marshal(crl)
	if err != nil {
		t.Fatal(err)
	}
	crlPath := filepath.Join(t.TempDir(), "crl.json")
	if err := os.WriteFile(crlPath, crlData, 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := writeServerTestConfig(t, "mode: balanced\nlicense_key: "+token+"\nlicense_public_key: "+hex.EncodeToString(pub)+"\nlicense_crl_file: "+crlPath+"\n")
	s, _ := newTestServer(t, func(opts *ServerOpts) {
		opts.ConfigFile = cfgPath
	})

	failClosed, err := s.checkLicenseCRL()
	if err != nil {
		t.Fatalf("checkLicenseCRL: %v", err)
	}
	if failClosed {
		t.Fatal("valid unrevoked license should not fail closed")
	}
}

func TestRuntimeLicensePublicKeyErrors(t *testing.T) {
	tests := []struct {
		name string
		cfg  *config.Config
	}{
		{name: "empty-config", cfg: &config.Config{}},
		{name: "not-hex", cfg: &config.Config{LicensePublicKey: "not-hex"}},
		{name: "short-hex", cfg: &config.Config{LicensePublicKey: hex.EncodeToString([]byte("short"))}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := runtimeLicensePublicKey(tt.cfg); err == nil {
				t.Fatalf("runtimeLicensePublicKey(%+v) expected error", tt.cfg)
			}
		})
	}
	if auditLicenseCRLContext().Method() != "LICENSE_CRL" {
		t.Fatal("unexpected audit context")
	}
	if (&Server{}).refreshLicenseCRLOnce() {
		t.Fatal("empty server should not fail closed")
	}
}

func TestStartLicenseCRLWatcherReturnsOnCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	(&Server{}).startLicenseCRLWatcher(ctx)
}
