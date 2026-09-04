// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidate_RequestBodyTrustedHosts(t *testing.T) {
	tests := []struct {
		name    string
		hosts   []string
		enabled bool
		wantErr string
	}{
		{name: "omitted", hosts: nil, enabled: true},
		{name: "empty list", hosts: []string{}, enabled: true},
		{name: "exact host", hosts: []string{"api.vendor.example"}, enabled: true},
		{name: "wildcard host", hosts: []string{"*.vendor.example"}, enabled: true},
		{name: "validated while scanning disabled", hosts: []string{""}, enabled: false, wantErr: "request_body_scanning.trusted_hosts"},
		{name: "blank entry", hosts: []string{""}, enabled: true, wantErr: "request_body_scanning.trusted_hosts"},
		{name: "bare wildcard", hosts: []string{"*"}, enabled: true, wantErr: "request_body_scanning.trusted_hosts"},
		{name: "url instead of host", hosts: []string{"https://api.vendor.example"}, enabled: true, wantErr: "request_body_scanning.trusted_hosts"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.RequestBodyScanning.Enabled = tt.enabled
			cfg.RequestBodyScanning.TrustedHosts = tt.hosts
			err := cfg.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want one naming %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoad_RequestBodyTrustedHostsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "pipelock.yaml")
	body := `
version: 1
request_body_scanning:
  enabled: true
  trusted_hosts:
    - api.vendor.example
    - "*.provider.example"
`
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := cfg.RequestBodyScanning.TrustedHosts; len(got) != 2 || got[0] != "api.vendor.example" || got[1] != "*.provider.example" {
		t.Fatalf("trusted_hosts = %v", got)
	}

	// Reload into a bad entry fails the same way first load does.
	bad := strings.Replace(body, "api.vendor.example", `"*"`, 1)
	if err := os.WriteFile(cfgPath, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(cfgPath); err == nil || !strings.Contains(err.Error(), "request_body_scanning.trusted_hosts") {
		t.Fatalf("reload error = %v, want trusted_hosts rejection", err)
	}
}
