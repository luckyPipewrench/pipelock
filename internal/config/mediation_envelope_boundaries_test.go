// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/signing"
)

func TestInboundEnvelopeTrustConfigurationBoundaries(t *testing.T) {
	t.Parallel()
	pub, _, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	validKey := MediationEnvelopeTrustedKey{
		KeyID: "partner-key", PublicKey: hex.EncodeToString(pub),
		TrustDomains: []string{"partner.example"},
	}
	tests := []struct {
		name string
		edit func(*Config)
		want string
	}{
		{name: "valid trust configuration", edit: func(*Config) {}},
		{name: "valid directory URL", edit: func(c *Config) {
			c.MediationEnvelope.VerifyInbound.TrustList[0].WellKnownURL = "https://partner.example/.well-known/keys"
		}},
		{name: "blank key identity", edit: func(c *Config) { c.MediationEnvelope.VerifyInbound.TrustList[0].KeyID = " \t" }, want: "trust_list[0].key_id is required"},
		{name: "duplicate trimmed identity", edit: func(c *Config) {
			key := validKey
			key.KeyID = " partner-key "
			c.MediationEnvelope.VerifyInbound.TrustList = append(c.MediationEnvelope.VerifyInbound.TrustList, key)
		}, want: "duplicates trust_list[0]"},
		{name: "missing public key", edit: func(c *Config) { c.MediationEnvelope.VerifyInbound.TrustList[0].PublicKey = " " }, want: "trust_list[0].public_key is required"},
		{name: "malformed public key", edit: func(c *Config) { c.MediationEnvelope.VerifyInbound.TrustList[0].PublicKey = "not-a-public-key" }, want: "trust_list[0].public_key:"},
		{name: "malformed directory URL", edit: func(c *Config) { c.MediationEnvelope.VerifyInbound.TrustList[0].WellKnownURL = "https://%zz" }, want: "well_known_url must be an https URL"},
		{name: "directory URL without host", edit: func(c *Config) { c.MediationEnvelope.VerifyInbound.TrustList[0].WellKnownURL = "https:/keys" }, want: "well_known_url must be an https URL"},
		{name: "blank trust domain", edit: func(c *Config) { c.MediationEnvelope.VerifyInbound.TrustList[0].TrustDomains = []string{" "} }, want: "trust_domains[0] must not be empty"},
		{name: "trust domain with port", edit: func(c *Config) {
			c.MediationEnvelope.VerifyInbound.TrustList[0].TrustDomains = []string{"partner.example:443"}
		}, want: "trust_domains[0]"},
		{name: "invalid replay duration", edit: func(c *Config) { c.MediationEnvelope.VerifyInbound.ReplayCache.Window = "invalid" }, want: "replay_cache.window:"},
		{name: "zero replay duration", edit: func(c *Config) { c.MediationEnvelope.VerifyInbound.ReplayCache.Window = "0s" }, want: "replay_cache.window must be > 0"},
		{name: "negative replay capacity", edit: func(c *Config) { c.MediationEnvelope.VerifyInbound.ReplayCache.MaxEntries = -1 }, want: "replay_cache.max_entries must be >= 0"},
		{name: "signature outlives replay window", edit: func(c *Config) {
			c.MediationEnvelope.SignatureExpires = (DefaultEnvelopeReplayWindow + time.Second).String()
		}, want: "must be <= mediation_envelope.verify_inbound.replay_cache.window"},
		{name: "signature matches replay window", edit: func(c *Config) { c.MediationEnvelope.SignatureExpires = DefaultEnvelopeReplayWindow.String() }},
		{name: "shorter signature accepted", edit: func(c *Config) { c.MediationEnvelope.SignatureExpires = (DefaultEnvelopeReplayWindow / 2).String() }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := Defaults()
			c.MediationEnvelope.VerifyInbound.Enabled = true
			c.MediationEnvelope.VerifyInbound.TrustList = []MediationEnvelopeTrustedKey{validKey}
			tt.edit(c)
			err := c.Validate()
			if tt.want == "" {
				if err != nil {
					t.Fatalf("valid inbound trust configuration: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Validate() = %v, want %q", err, tt.want)
			}
		})
	}
}
