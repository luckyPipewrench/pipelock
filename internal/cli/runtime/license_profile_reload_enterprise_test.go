//go:build enterprise

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
	path := writeServerTestConfig(t, "mode: balanced\nlicense_require_intermediate: false\nlicense_key: "+token+"\nlicense_public_key: "+hex.EncodeToString(pub)+"\nlicense_crl_file: "+crlPath+"\nagents:\n  client:\n    source_cidrs: [192.0.2.0/24]\n")
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
	writeCRL(true)
	next, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !config.SameLicenseInputs(old, next) || hasNamedAgentProfiles(next.Agents) {
		t.Fatal("precondition: same-input verified revocation must strip named profiles")
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
