//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package runtime

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise"
	"github.com/luckyPipewrench/pipelock/internal/edition"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/license"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestRuntimeCRLRevokesProfileSelection(t *testing.T) {
	oldFactory := edition.NewEditionFunc
	edition.NewEditionFunc = enterprise.NewEdition
	t.Cleanup(func() { edition.NewEditionFunc = oldFactory })
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	lic := license.License{ID: "lic_profile_runtime", Email: "runtime@example.com", IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(), Features: []string{license.FeatureAgents}}
	token, err := license.Issue(lic, priv)
	if err != nil {
		t.Fatal(err)
	}
	crlPath := filepath.Join(t.TempDir(), "crl.json")
	writeCRL := func(revoked bool) {
		t.Helper()
		payload := license.CRLPayload{Version: license.CRLVersion, Generation: 1, IssuedAt: now.Add(-time.Minute).Unix(), ExpiresAt: now.Add(time.Hour).Unix()}
		if revoked {
			payload.Generation = 2
			payload.Revoked = []license.RevokedLicense{{ID: lic.ID, RevokedAt: now.Unix()}}
		}
		crl, err := license.SignCRL(payload, priv)
		if err != nil {
			t.Fatal(err)
		}
		data, err := json.Marshal(crl)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(crlPath, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeCRL(false)
	cfgPath := writeServerTestConfig(t, "mode: balanced\ndefault_agent_identity: client\nbind_default_agent_identity: true\nlicense_require_intermediate: false\nlicense_key: "+token+"\nlicense_public_key: "+hex.EncodeToString(pub)+"\nlicense_crl_file: "+crlPath+"\nagents:\n  client:\n    source_cidrs: [192.0.2.0/24]\n")
	s, _ := newTestServer(t, func(opts *ServerOpts) { opts.ConfigFile = cfgPath })
	req := httptest.NewRequestWithContext(t.Context(), "GET", "http://api.vendor.example/", nil)
	req.RemoteAddr = "192.0.2.8:1234"
	ed := s.proxy.Edition()
	resolved, _ := ed.ResolveAgent(req.Context(), req)
	if resolved.Name != "client" {
		t.Fatalf("positive control: %s", resolved.Name)
	}
	if s.refreshLicenseCRLOnce() {
		t.Fatal("unrevoked license denied")
	}
	if err := os.Rename(crlPath, crlPath+".saved"); err != nil {
		t.Fatal(err)
	}
	if !s.refreshLicenseCRLOnce() {
		t.Fatal("missing CRL did not fail closed")
	}
	if _, ok := ed.LookupProfile("client"); ok {
		t.Fatal("missing CRL retained paid profile")
	}
	if err := os.Rename(crlPath+".saved", crlPath); err != nil {
		t.Fatal(err)
	}
	if s.refreshLicenseCRLOnce() {
		t.Fatal("valid CRL recovery denied")
	}
	if resolved, ok := ed.LookupProfile("client"); !ok || resolved.Name != "client" {
		t.Fatal("valid CRL recovery did not restore profile")
	}
	writeCRL(true)
	if !s.refreshLicenseCRLOnce() {
		t.Fatal("revocation not observed")
	}
	for _, ctx := range []bool{false, true} {
		context := req.Context()
		if ctx {
			context = edition.WithAgentOverride(context, "client")
		}
		resolved, id := ed.ResolveAgent(context, req)
		if resolved.Name != edition.ProfileDefault || id.Auth != envelope.ActorAuthUnknown {
			t.Errorf("revoked selection: %s %+v", resolved.Name, id)
		}
	}
	unbound := req.Clone(req.Context())
	unbound.RemoteAddr = "198.51.100.8:1234"
	if resolved, id := ed.ResolveAgent(unbound.Context(), unbound); resolved.Name != edition.ProfileDefault || id.Profile != edition.ProfileDefault || id.Auth != envelope.ActorAuthUnknown {
		t.Fatalf("default identity retained revoked profile: %s %+v", resolved.Name, id)
	}
	if resolved, ok := ed.LookupProfile("client"); ok || resolved.Name != edition.ProfileDefault {
		t.Error("explicit lookup retained revoked profile")
	}
	if resolved, ok := ed.LookupProfile(edition.ProfileDefault); !ok || resolved.Name != edition.ProfileDefault {
		t.Error("default profile unavailable")
	}
	for _, change := range []bool{false, true} {
		cfg := s.proxy.CurrentConfig().Clone()
		if change {
			cfg.Logging.IncludeAllowed = !cfg.Logging.IncludeAllowed
		}
		if !s.proxy.Reload(cfg, scanner.MustNew(cfg)) {
			t.Fatal("reload failed")
		}
		if resolved, ok := s.proxy.Edition().LookupProfile("client"); ok || resolved.Name != edition.ProfileDefault {
			t.Fatal("reload restored revoked profile")
		}
	}
	stale := s.proxy.CurrentConfig().Clone()
	if s.proxy.SetLicenseRevoked(stale, false) {
		t.Fatal("stale check applied")
	}
	if _, ok := s.proxy.Edition().LookupProfile("client"); ok {
		t.Fatal("stale check restored profile")
	}
	bad := s.proxy.CurrentConfig().Clone()
	bad.MediationEnvelope.VerifyInbound.Enabled = true
	bad.MediationEnvelope.VerifyInbound.TrustList = nil
	if s.proxy.Reload(bad, scanner.MustNew(bad)) {
		t.Fatal("bad reload accepted")
	}
	if _, ok := s.proxy.Edition().LookupProfile("client"); ok {
		t.Fatal("failed reload restored profile")
	}
}
