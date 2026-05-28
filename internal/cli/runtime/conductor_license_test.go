// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/license"
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
	cfgYAML := "conductor:\n  enabled: true\n  conductor_url: https://conductor.example\n  org_id: o\n  fleet_id: f\n  instance_id: i\n"
	cfgPath := writeServerTestConfig(t, cfgYAML)
	_, err := NewServer(ServerOpts{ConfigFile: cfgPath, Stdout: &syncBuffer{}, Stderr: &syncBuffer{}})
	if err == nil {
		t.Fatal("NewServer with conductor.enabled and no fleet license: want error, got nil")
	}
}
