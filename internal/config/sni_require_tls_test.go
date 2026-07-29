// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestForwardProxySNIRequireTLSValidation(t *testing.T) {
	cfg := Defaults()
	cfg.ForwardProxy.Enabled = true
	verification := false
	requireTLS := true
	cfg.ForwardProxy.SNIVerification = &verification
	cfg.ForwardProxy.SNIRequireTLS = &requireTLS

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "sni_require_tls requires") {
		t.Fatalf("Validate() error = %v, want require-TLS dependency refusal", err)
	}

	requireTLS = false
	cfg.ForwardProxy.SNIRequireTLS = &requireTLS
	if err := cfg.Validate(); err != nil {
		t.Fatalf("explicit legacy opt-out with SNI verification disabled: %v", err)
	}
}

func TestAuditPresetDoesNotEnforceSNIRequireTLS(t *testing.T) {
	path, err := filepath.Abs("../../configs/audit.yaml")
	if err != nil {
		t.Fatalf("Abs(audit preset): %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load(audit preset): %v", err)
	}
	if cfg.EnforceEnabled() {
		t.Fatal("audit preset unexpectedly enables enforcement")
	}
	if cfg.ForwardProxy.SNIRequireTLSEnabled() {
		t.Fatal("audit preset unexpectedly enforces TLS-only CONNECT")
	}
}

func TestForwardProxySNIRequireTLSBooleanLifecycle(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{name: "omitted", body: "forward_proxy: {}\n", want: false},
		{name: "yaml null", body: "forward_proxy:\n  sni_require_tls:\n", want: false},
		{name: "explicit false", body: "forward_proxy:\n  sni_require_tls: false\n", want: false},
		{name: "explicit true", body: "forward_proxy:\n  sni_require_tls: true\n", want: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var cfg Config
			if err := yaml.Unmarshal([]byte(tc.body), &cfg); err != nil {
				t.Fatalf("Unmarshal() error = %v", err)
			}
			if got := cfg.ForwardProxy.SNIRequireTLSEnabled(); got != tc.want {
				t.Fatalf("SNIRequireTLSEnabled() = %t, want %t", got, tc.want)
			}
		})
	}

	var first Config
	if err := yaml.Unmarshal([]byte("forward_proxy:\n  sni_require_tls: false\n"), &first); err != nil {
		t.Fatal(err)
	}
	var unchanged Config
	if err := yaml.Unmarshal([]byte("forward_proxy:\n  sni_require_tls: false\n"), &unchanged); err != nil {
		t.Fatal(err)
	}
	if first.ForwardProxy.SNIRequireTLSEnabled() != unchanged.ForwardProxy.SNIRequireTLSEnabled() {
		t.Fatal("reload without change drifted")
	}
	var changed Config
	if err := yaml.Unmarshal([]byte("forward_proxy:\n  sni_require_tls: true\n"), &changed); err != nil {
		t.Fatal(err)
	}
	if !changed.ForwardProxy.SNIRequireTLSEnabled() {
		t.Fatal("reload with change did not enable sni_require_tls")
	}
}
