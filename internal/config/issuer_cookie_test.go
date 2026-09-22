// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestIssuerBoundSessionCookieConfig(t *testing.T) {
	baseline := Defaults().computeCanonicalPolicyHash()
	enabledPolicy := Defaults()
	enabledPolicy.RequestBodyScanning.IssuerBoundSessionCookies = true
	if enabledPolicy.computeCanonicalPolicyHash() == baseline {
		t.Fatal("enabling issuer-bound cookies must change the canonical policy hash")
	}
	for _, tc := range []struct {
		name    string
		yaml    string
		enabled bool
	}{
		{name: "omitted", yaml: "{}"},
		{name: "null", yaml: "issuer_bound_session_cookies: null"},
		{name: "explicit false", yaml: "issuer_bound_session_cookies: false"},
		{name: "explicit true", yaml: "issuer_bound_session_cookies: true", enabled: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.TLSInterception.Enabled = true
			if err := yaml.Unmarshal([]byte(tc.yaml), &cfg.RequestBodyScanning); err != nil {
				t.Fatal(err)
			}
			if cfg.RequestBodyScanning.IssuerBoundSessionCookies != tc.enabled {
				t.Fatalf("enabled = %t, want %t", cfg.RequestBodyScanning.IssuerBoundSessionCookies, tc.enabled)
			}
			var warnings []Warning
			if err := cfg.validateRequestBodyScanning(&warnings); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, tc := range []struct {
		name   string
		change func(*Config)
	}{
		{name: "body scanning off", change: func(c *Config) { c.RequestBodyScanning.Enabled = false }},
		{name: "header scanning off", change: func(c *Config) { c.RequestBodyScanning.ScanHeaders = false }},
		{name: "interception off", change: func(c *Config) { c.TLSInterception.Enabled = false }},
		{name: "all header mode", change: func(c *Config) { c.RequestBodyScanning.HeaderMode = HeaderModeAll }},
		{name: "Cookie unscanned", change: func(c *Config) { c.RequestBodyScanning.SensitiveHeaders = []string{"Authorization"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.TLSInterception.Enabled = true
			cfg.RequestBodyScanning.IssuerBoundSessionCookies = true
			tc.change(cfg)
			var warnings []Warning
			if err := cfg.validateRequestBodyScanning(&warnings); err == nil || !strings.Contains(err.Error(), "issuer_bound_session_cookies") {
				t.Fatalf("validation error = %v, want issuer-bound setting error", err)
			}
		})
	}
}
