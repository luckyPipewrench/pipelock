// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

// TestTLSInterceptionCoverageAdvisory covers the predicate directly (no CA file
// dependency): the advisory fires whenever the forward proxy accepts CONNECT
// tunnels and TLS interception is off, and stays silent otherwise. It fires
// regardless of which content scanners are enabled, because every
// content-dependent control is blind to HTTPS-over-CONNECT without interception.
func TestTLSInterceptionCoverageAdvisory(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(c *Config)
		want   bool
	}{
		{
			name:   "forward proxy off (default) does not advise",
			mutate: func(c *Config) {},
			want:   false,
		},
		{
			name:   "forward proxy on, interception off advises",
			mutate: func(c *Config) { c.ForwardProxy.Enabled = true },
			want:   true,
		},
		{
			name: "forward proxy on, interception on does not advise",
			mutate: func(c *Config) {
				c.ForwardProxy.Enabled = true
				c.TLSInterception.Enabled = true
			},
			want: false,
		},
		{
			name: "forward proxy on, interception off, all content scanners off still advises",
			mutate: func(c *Config) {
				c.ForwardProxy.Enabled = true
				c.RequestBodyScanning.Enabled = false
				c.ResponseScanning.Enabled = false
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Defaults()
			tt.mutate(cfg)
			msg, ok := cfg.TLSInterceptionCoverageAdvisory()
			if ok != tt.want {
				t.Fatalf("TLSInterceptionCoverageAdvisory ok = %v, want %v", ok, tt.want)
			}
			if !ok {
				if msg != "" {
					t.Errorf("advisory not warranted but message non-empty: %q", msg)
				}
				return
			}
			// The message must name the blind content scanners AND state that
			// request_policy/contract rules matching inner HTTPS content require
			// interception, so it does not overstate protection (both directions).
			for _, want := range []string{
				"request_body_scanning",
				"response_scanning",
				"path/query entropy",
				"require tls_interception",
				"data budget",
			} {
				if !strings.Contains(msg, want) {
					t.Errorf("advisory message missing %q; got: %s", want, msg)
				}
			}
		})
	}
}

// TestValidate_TLSInterceptionCoverageWarningIntegration proves the advisory
// flows through ValidateWithWarnings as a non-fatal warning on the firing config
// (interception off, so no CA file is required).
func TestValidate_TLSInterceptionCoverageWarningIntegration(t *testing.T) {
	cfg := Defaults()
	cfg.ForwardProxy.Enabled = true

	warnings, err := cfg.ValidateWithWarnings()
	if err != nil {
		t.Fatalf("ValidateWithWarnings: %v", err)
	}
	for _, w := range warnings {
		if w.Field == "tls_interception" {
			return
		}
	}
	t.Fatalf("missing tls_interception coverage warning in %#v", warnings)
}
