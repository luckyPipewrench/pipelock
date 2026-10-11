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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/edition"
	"github.com/luckyPipewrench/pipelock/internal/license"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// Removing one CIDR profile preserves the other under the same valid license.
func TestServerReloadProfileRemovalKeepsSurvivor(t *testing.T) {
	oldFactory := edition.NewEditionFunc
	edition.NewEditionFunc = enterprise.NewEdition
	t.Cleanup(func() { edition.NewEditionFunc = oldFactory })
	token, pub := realValidAgentsLicense(t)
	head := "mode: balanced\nlicense_require_intermediate: false\nlicense_key: " + token + "\nlicense_public_key: " + pub + "\n"
	path := writeServerTestConfig(t, head+"agents:\n  client:\n    source_cidrs: [192.0.2.0/24]\n  other:\n    source_cidrs: [198.51.100.0/24]\n")
	s, _ := newTestServer(t, func(o *ServerOpts) {
		o.ConfigFile = path
		o.Listen = serverTestEphemeralListen
		o.ListenChanged = true
	})
	ra, ok := s.proxy.Edition().LookupProfile("client")
	if !ok || ra.LicenseRevoked == nil {
		t.Fatal("positive control")
	}
	path2 := writeServerTestConfig(t, head+"agents:\n  client:\n    source_cidrs: [192.0.2.0/24]\n")
	next, err := config.Load(path2)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(next); err != nil {
		t.Fatalf("reload: %v", err)
	}
	select {
	case <-ra.LicenseRevoked:
		t.Errorf("surviving profile's generation ended by removing an unrelated profile")
	default:
	}
	if _, ok := s.proxy.Edition().LookupProfile("client"); !ok {
		t.Errorf("surviving profile falls back to _default under a valid licence")
	}
}

func TestServerReloadProvenLossEndsSharedGeneration(t *testing.T) {
	requireProvenLossReload(t, false, false)
}

func TestServerReloadProvenLossChangedInputs(t *testing.T) {
	requireProvenLossReload(t, true, false)
}

func TestServerReloadProvenLossRejectedProxySwap(t *testing.T) {
	for _, changed := range []bool{false, true} {
		t.Run(map[bool]string{false: "same_inputs", true: "changed_inputs"}[changed], func(t *testing.T) {
			requireProvenLossReload(t, changed, true)
		})
	}
}

func requireProvenLossReload(t *testing.T, changed, reject bool) {
	t.Helper()
	oldFactory := edition.NewEditionFunc
	edition.NewEditionFunc = enterprise.NewEdition
	t.Cleanup(func() { edition.NewEditionFunc = oldFactory })
	oldGate := config.EnforceLicenseGateFunc
	config.EnforceLicenseGateFunc = enterprise.EnforceLicenseGate
	t.Cleanup(func() { config.EnforceLicenseGateFunc = oldGate })
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	lic := license.License{ID: "reload-generation", Email: "test@example.com", IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(), Features: []string{license.FeatureAgents}}
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
	configText := func() string {
		return "mode: balanced\nlicense_require_intermediate: false\nlicense_key: " + token + "\nlicense_public_key: " + hex.EncodeToString(pub) + "\nlicense_crl_file: " + crlPath + "\nagents:\n  client:\n    source_cidrs: [192.0.2.0/24]\n"
	}
	path := writeServerTestConfig(t, configText())
	s, _ := newTestServer(t, func(o *ServerOpts) {
		o.ConfigFile = path
		o.Listen = serverTestEphemeralListen
		o.ListenChanged = true
	})
	ra, ok := s.proxy.Edition().LookupProfile("client")
	if !ok || ra.LicenseRevoked == nil {
		t.Fatal("positive control: licensed profile missing")
	}
	old := s.proxy.CurrentConfig()
	if changed {
		crlPath = filepath.Join(filepath.Dir(crlPath), "replacement-crl.json")
	}
	writeCRL(true)
	if changed {
		path = writeServerTestConfig(t, configText())
	}
	next, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if config.SameLicenseInputs(old, next) == changed || hasNamedAgentProfiles(next.Agents) {
		t.Fatal("precondition: verified revocation must strip profiles with the intended inputs")
	}
	if reject {
		keyPath := filepath.Join(t.TempDir(), "envelope.key")
		if err := signing.SavePrivateKey(priv, keyPath); err != nil {
			t.Fatal(err)
		}
		next.MediationEnvelope.Enabled = true
		next.MediationEnvelope.Sign = true
		next.MediationEnvelope.SigningKeyPath = keyPath
		if err := next.Validate(); err != nil {
			t.Fatal(err)
		}
		reachedSwap := false
		t.Cleanup(setReloadBeforeProxySwapHookForTest(func(server *Server) {
			if server != s {
				return
			}
			reachedSwap = true
			if err := os.WriteFile(keyPath, []byte("invalid signing key"), 0o600); err != nil {
				t.Fatal(err)
			}
		}))
		if err := s.Reload(next); err == nil {
			t.Fatal("invalid proxy candidate committed")
		}
		if !reachedSwap {
			t.Fatal("reload did not reach the proxy commit boundary")
		}
		if s.proxy.CurrentConfig() != old {
			t.Fatal("rejected reload replaced the old config")
		}
		select {
		case <-ra.LicenseRevoked:
			t.Fatal("rejected proven-loss reload ended the old generation")
		default:
		}
		current, ok := s.proxy.Edition().LookupProfile("client")
		if !ok || current.LicenseRevoked != ra.LicenseRevoked {
			t.Fatal("rejected reload changed the old licensed profile")
		}
		return
	}
	if err := s.Reload(next); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ra.LicenseRevoked:
	default:
		t.Fatal("committed proven loss left the shared generation open")
	}
	if _, ok := s.proxy.Edition().LookupProfile("client"); ok {
		t.Fatal("committed revocation retained paid selection")
	}
}
