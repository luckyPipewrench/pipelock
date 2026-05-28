// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/license"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// setTestFleetLicense issues a fresh Enterprise-tier license token (with the
// `fleet` feature) and installs it via PIPELOCK_LICENSE_KEY +
// PIPELOCK_LICENSE_PUBLIC_KEY env vars for the lifetime of t. Tests that
// enable conductor.enabled use this so the production license gate fires
// against real signed tokens — not a bypass — while still letting the test
// proceed without depending on a build-embedded key. t.Cleanup unsets the
// env vars via t.Setenv's normal restoration.
func setTestFleetLicense(t *testing.T) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tok, err := license.Issue(license.License{
		ID:        "test-fleet-license",
		Email:     "test@example.com",
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		Features:  []string{license.FeatureAgents, license.FeatureFleet},
		Tier:      "enterprise",
	}, priv)
	if err != nil {
		t.Fatalf("license.Issue: %v", err)
	}
	t.Setenv(license.EnvLicenseKey, tok)
	t.Setenv(license.EnvLicensePublicKey, hex.EncodeToString(pub))
	t.Setenv(license.EnvLicenseCRLFile, "")
}

func setRevokedTestFleetLicense(t *testing.T) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	now := time.Now().UTC()
	tok, err := license.Issue(license.License{
		ID:        "revoked-fleet-license",
		Email:     "test@example.com",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(),
		Features:  []string{license.FeatureAgents, license.FeatureFleet},
		Tier:      "enterprise",
	}, priv)
	if err != nil {
		t.Fatalf("license.Issue: %v", err)
	}
	crl, err := license.SignCRL(license.CRLPayload{
		Version:   license.CRLVersion,
		IssuedAt:  now.Add(-time.Minute).Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(),
		Revoked: []license.RevokedLicense{{
			ID:        "revoked-fleet-license",
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
	crlPath := filepath.Join(t.TempDir(), "license.crl.json")
	if err := os.WriteFile(crlPath, data, 0o600); err != nil {
		t.Fatalf("WriteFile(CRL): %v", err)
	}
	t.Setenv(license.EnvLicenseKey, tok)
	t.Setenv(license.EnvLicensePublicKey, hex.EncodeToString(pub))
	t.Setenv(license.EnvLicenseCRLFile, crlPath)
}

func conductorLicenseGateConfigYAML(t *testing.T) string {
	t.Helper()
	tmp, err := os.MkdirTemp(".", ".runtime-license-gate-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tmp) })
	tmp, err = filepath.Abs(tmp)
	if err != nil {
		t.Fatalf("Abs: %v", err)
	}
	_, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	keyPath := filepath.Join(tmp, "recorder.key")
	if err := signing.SavePrivateKey(priv, keyPath); err != nil {
		t.Fatalf("SavePrivateKey: %v", err)
	}
	clientPEM, clientKeyPEM := testTLSClientCert(t)
	certDir := filepath.Join(tmp, "tls")
	if err := os.Mkdir(certDir, 0o750); err != nil {
		t.Fatalf("Mkdir(tls): %v", err)
	}
	caPath := filepath.Join(certDir, "boss-ca.pem")
	clientCertPath := filepath.Join(certDir, "client.crt")
	clientKeyPath := filepath.Join(certDir, "client.key")
	trustPath := filepath.Join(certDir, "trust-roster.json")
	bundleCacheDir := filepath.Join(certDir, "bundles")
	auditQueueDir := filepath.Join(certDir, "audit-queue")
	if err := os.WriteFile(caPath, clientPEM, 0o600); err != nil {
		t.Fatalf("WriteFile(ca): %v", err)
	}
	if err := os.WriteFile(clientCertPath, clientPEM, 0o600); err != nil {
		t.Fatalf("WriteFile(client cert): %v", err)
	}
	if err := os.WriteFile(clientKeyPath, clientKeyPEM, 0o600); err != nil {
		t.Fatalf("WriteFile(client key): %v", err)
	}
	if err := os.WriteFile(trustPath, []byte(`{"keys":[]}`), 0o600); err != nil {
		t.Fatalf("WriteFile(trust roster): %v", err)
	}
	return "flight_recorder:\n" +
		"  enabled: true\n" +
		"  dir: " + strconv.Quote(filepath.Join(tmp, "recorder")) + "\n" +
		"  signing_key_path: " + strconv.Quote(keyPath) + "\n" +
		"conductor:\n" +
		"  enabled: true\n" +
		"  conductor_url: https://conductor.example\n" +
		"  org_id: o\n" +
		"  fleet_id: f\n" +
		"  instance_id: i\n" +
		"  server_ca_file: " + strconv.Quote(caPath) + "\n" +
		"  client_cert_path: " + strconv.Quote(clientCertPath) + "\n" +
		"  client_key_path: " + strconv.Quote(clientKeyPath) + "\n" +
		"  trust_roster_path: " + strconv.Quote(trustPath) + "\n" +
		"  bundle_cache_dir: " + strconv.Quote(bundleCacheDir) + "\n" +
		"  durable_audit_queue_dir: " + strconv.Quote(auditQueueDir) + "\n" +
		"  honor_remote_kill_switch: false\n"
}

// TestNewServer_ConductorEnabledRequiresFleetLicense locks in the runtime
// fleet-license gate: a config with conductor.enabled=true MUST fail to
// start when no fleet license is present, even if every other config field
// is valid. Otherwise an operator (or a misconfigured fleet) could activate
// central governance without an entitlement.
func TestNewServer_ConductorEnabledRequiresFleetLicense(t *testing.T) {
	t.Setenv(license.EnvLicenseKey, "")
	t.Setenv(license.EnvLicensePublicKey, "")
	// We don't need conductor to fully start; just reach the gate. A minimal
	// invalid config still fails validation BEFORE the gate, so we use the
	// existing conductor-enabled test fixture and assert the gate's error.
	// The fixture sets up flight_recorder + conductor; without a fleet
	// license env, NewServer must error with ErrFleetLicenseRequired.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("unexpected panic: %v", r)
		}
	}()
	// newConductorApplyTestServer asserts NewServer succeeds. We want it to
	// FAIL, so we replicate just enough config setup to trigger the gate.
	cfgPath := writeServerTestConfig(t, conductorLicenseGateConfigYAML(t))
	_, err := NewServer(ServerOpts{ConfigFile: cfgPath, Stdout: &syncBuffer{}, Stderr: &syncBuffer{}})
	if err == nil {
		t.Fatal("NewServer with conductor.enabled and no fleet license: want error, got nil")
	}
	if !errors.Is(err, license.ErrFleetLicenseRequired) {
		t.Fatalf("want ErrFleetLicenseRequired, got %v", err)
	}
}

func TestNewServer_ConductorEnabledRejectsRevokedFleetLicense(t *testing.T) {
	setRevokedTestFleetLicense(t)
	cfgPath := writeServerTestConfig(t, conductorLicenseGateConfigYAML(t))
	_, err := NewServer(ServerOpts{ConfigFile: cfgPath, Stdout: &syncBuffer{}, Stderr: &syncBuffer{}})
	if err == nil {
		t.Fatal("NewServer with revoked fleet license: want error, got nil")
	}
	if !errors.Is(err, license.ErrFleetLicenseRequired) {
		t.Fatalf("want ErrFleetLicenseRequired, got %v", err)
	}
	if !errors.Is(err, license.ErrLicenseRevoked) {
		t.Fatalf("want ErrLicenseRevoked in error chain, got %v", err)
	}
}

func TestServer_ReloadCannotActivateConductorWithNewLicense(t *testing.T) {
	setTestFleetLicense(t)
	s, _ := newTestServer(t, nil)
	newCfg := s.proxy.CurrentConfig().Clone()
	newCfg.Conductor.Enabled = true
	newCfg.Conductor.ConductorURL = "https://conductor.example"
	newCfg.Conductor.OrgID = "o"
	newCfg.Conductor.FleetID = "f"
	newCfg.Conductor.InstanceID = "i"

	if err := s.Reload(newCfg); err != nil {
		t.Fatalf("Reload enabling conductor: %v", err)
	}
	live := s.proxy.CurrentConfig()
	if live.Conductor.Enabled {
		t.Fatalf("reload activated conductor.enabled; live conductor = %+v", live.Conductor)
	}
	if s.conductorApply != nil || s.conductorAudit != nil || s.conductorProducer != nil || s.conductorRemoteKill != nil {
		t.Fatalf("reload initialized conductor runtime wiring: apply=%v audit=%v producer=%v remoteKill=%v",
			s.conductorApply, s.conductorAudit, s.conductorProducer, s.conductorRemoteKill)
	}
}
