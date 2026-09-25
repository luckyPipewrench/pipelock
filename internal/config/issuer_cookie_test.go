// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestIssuerBoundSessionCookieConfig(t *testing.T) {
	baseline := Defaults().computeCanonicalPolicyHash()
	disabledPolicy := Defaults()
	disabledPolicy.RequestBodyScanning.IssuerBoundSessionCookies = false
	if disabledPolicy.computeCanonicalPolicyHash() == baseline {
		t.Fatal("disabling issuer-bound cookies must change the canonical policy hash")
	}
	for _, tc := range []struct {
		name    string
		yaml    string
		enabled bool
	}{
		{name: "omitted", yaml: "{}", enabled: true},
		{name: "null", yaml: "issuer_bound_session_cookies: null", enabled: true},
		{name: "blank", yaml: "issuer_bound_session_cookies:", enabled: true},
		{name: "explicit false", yaml: "issuer_bound_session_cookies: false"},
		{name: "explicit true", yaml: "issuer_bound_session_cookies: true", enabled: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Defaults()
			if err := yaml.Unmarshal([]byte(tc.yaml), &cfg.RequestBodyScanning); err != nil {
				t.Fatal(err)
			}
			if cfg.RequestBodyScanning.IssuerBoundSessionCookies != tc.enabled {
				t.Fatalf("enabled = %t, want %t", cfg.RequestBodyScanning.IssuerBoundSessionCookies, tc.enabled)
			}
		})
	}
	// The setting is on by default, so it must never make an otherwise valid
	// policy invalid. Without interception or header scanning it is inert.
	for _, tc := range []struct {
		name   string
		change func(*Config)
	}{
		{name: "interception off", change: func(c *Config) { c.TLSInterception.Enabled = false }},
		{name: "interception on", change: func(c *Config) { c.TLSInterception.Enabled = true }},
		{name: "body scanning off", change: func(c *Config) { c.RequestBodyScanning.Enabled = false }},
		{name: "header scanning off", change: func(c *Config) { c.RequestBodyScanning.ScanHeaders = false }},
		{name: "all header mode", change: func(c *Config) { c.RequestBodyScanning.HeaderMode = HeaderModeAll }},
		{name: "Cookie unscanned", change: func(c *Config) { c.RequestBodyScanning.SensitiveHeaders = []string{"Authorization"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Defaults()
			tc.change(cfg)
			var warnings []Warning
			if err := cfg.validateRequestBodyScanning(&warnings); err != nil {
				t.Fatalf("default-on setting rejected a valid policy: %v", err)
			}
		})
	}
}
