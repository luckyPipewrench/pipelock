// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package license

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func TestVerifyAgentsWithOptions_AgentsFeatureAccepted(t *testing.T) {
	pub, priv := newKeyPair(t)
	tok := mustIssue(t, priv, "lic_agents", []string{FeatureAgents}) // Pro tier
	lic, err := VerifyAgentsWithOptions(FleetVerifyInputs{
		LicenseKey:   tok,
		PublicKeyHex: hex.EncodeToString(pub),
	})
	if err != nil {
		t.Fatalf("VerifyAgentsWithOptions with Pro license: want nil, got %v", err)
	}
	if lic.ID != "lic_agents" {
		t.Errorf("license ID = %q, want lic_agents", lic.ID)
	}
}

func TestVerifyAgentsWithOptions_MissingFeatureRejected(t *testing.T) {
	pub, priv := newKeyPair(t)
	tok := mustIssue(t, priv, "lic_assess", []string{FeatureAssess}) // no agents
	_, err := VerifyAgentsWithOptions(FleetVerifyInputs{
		LicenseKey:   tok,
		PublicKeyHex: hex.EncodeToString(pub),
	})
	if !errors.Is(err, ErrAgentsLicenseRequired) {
		t.Fatalf("assess-only license: want ErrAgentsLicenseRequired, got %v", err)
	}
	if !strings.Contains(err.Error(), "does not include the agents feature") {
		t.Errorf("error should explain missing feature; got %v", err)
	}
}

func TestVerifyAgentsWithOptions_NoTokenRejected(t *testing.T) {
	t.Setenv(EnvLicenseKey, "")
	_, err := VerifyAgentsWithOptions(FleetVerifyInputs{})
	if !errors.Is(err, ErrAgentsLicenseRequired) {
		t.Fatalf("no license token: want ErrAgentsLicenseRequired, got %v", err)
	}
}

func TestVerifyAgentsWithOptions_WrongKeyRejected(t *testing.T) {
	_, priv := newKeyPair(t)
	otherPub, _ := newKeyPair(t)
	tok := mustIssue(t, priv, "lic_wrong_key", []string{FeatureAgents})
	_, err := VerifyAgentsWithOptions(FleetVerifyInputs{
		LicenseKey:   tok,
		PublicKeyHex: hex.EncodeToString(otherPub),
	})
	if !errors.Is(err, ErrAgentsLicenseRequired) {
		t.Fatalf("wrong verifier key: want ErrAgentsLicenseRequired, got %v", err)
	}
}
