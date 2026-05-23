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
