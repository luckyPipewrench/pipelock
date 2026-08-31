// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func validSigV4CredentialRouteConfig() *Config {
	cfg := Defaults()
	cfg.RequestBodyScanning.Enabled = true
	cfg.RequestBodyScanning.SigV4CredentialRoutes = []RequestBodySigV4CredentialRoute{{
		Host: "API.VENDOR.EXAMPLE.", Path: "/v1/graphql", ContentTypes: []string{"application/json; charset=utf-8"},
		Methods: []string{"post"}, Reason: "register attachment URL", Owner: "platform", Expires: "2099-12-31",
	}}
	return cfg
}

func TestValidateRequestBodySigV4CredentialRoutesNormalizesExactScope(t *testing.T) {
	cfg := validSigV4CredentialRouteConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	got := cfg.RequestBodyScanning.SigV4CredentialRoutes[0]
	if got.Host != "api.vendor.example" || got.Path != "/v1/graphql" || got.ContentTypes[0] != "application/json" || got.Methods[0] != "POST" {
		t.Fatalf("route was not normalized: %+v", got)
	}
}

func TestLoadStrictYAMLRecognizesSigV4CredentialRoutes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pipelock.yaml")
	yaml := `mode: balanced
request_body_scanning:
  sigv4_credential_routes:
    - host: api.vendor.example
      path: /v1/graphql
      content_types: [application/json]
      methods: [POST]
      reason: register attachment URL
      owner: platform
      expires: 2099-12-31
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("strict Load rejected new route field: %v", err)
	}
	if len(cfg.RequestBodyScanning.SigV4CredentialRoutes) != 1 {
		t.Fatalf("loaded routes = %+v", cfg.RequestBodyScanning.SigV4CredentialRoutes)
	}
}

func TestValidateRequestBodySigV4CredentialRoutesRejectsUnsafeOrInertEntries(t *testing.T) {
	tests := []struct {
		name string
		edit func(*Config)
		want string
	}{
		{"body scanning disabled", func(c *Config) { c.RequestBodyScanning.Enabled = false }, "requires enabled request body scanning"},
		{"wildcard host", func(c *Config) { c.RequestBodyScanning.SigV4CredentialRoutes[0].Host = "*.vendor.example" }, "exact host"},
		{"root path", func(c *Config) { c.RequestBodyScanning.SigV4CredentialRoutes[0].Path = "/" }, "exact non-root canonical path"},
		{"encoded topology", func(c *Config) { c.RequestBodyScanning.SigV4CredentialRoutes[0].Path = "/v1%2fgraphql" }, "exact non-root canonical path"},
		{"missing content type", func(c *Config) { c.RequestBodyScanning.SigV4CredentialRoutes[0].ContentTypes = nil }, "content_types must contain"},
		{"invalid content type", func(c *Config) { c.RequestBodyScanning.SigV4CredentialRoutes[0].ContentTypes = []string{"not a type"} }, "is invalid"},
		{"missing method", func(c *Config) { c.RequestBodyScanning.SigV4CredentialRoutes[0].Methods = nil }, "methods must contain"},
		{"invalid method", func(c *Config) { c.RequestBodyScanning.SigV4CredentialRoutes[0].Methods = []string{"UPLOAD"} }, "supported HTTP method"},
		{"missing reason", func(c *Config) { c.RequestBodyScanning.SigV4CredentialRoutes[0].Reason = "" }, "reason is required"},
		{"missing owner", func(c *Config) { c.RequestBodyScanning.SigV4CredentialRoutes[0].Owner = "" }, "owner is required"},
		{"expired", func(c *Config) { c.RequestBodyScanning.SigV4CredentialRoutes[0].Expires = "2020-01-01" }, "already expired"},
		{"overlapping owner", func(c *Config) {
			duplicate := c.RequestBodyScanning.SigV4CredentialRoutes[0]
			duplicate.Owner = "other team"
			c.RequestBodyScanning.SigV4CredentialRoutes = append(c.RequestBodyScanning.SigV4CredentialRoutes, duplicate)
		}, "overlaps sigv4_credential_routes[0]"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validSigV4CredentialRouteConfig()
			tt.edit(cfg)
			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Validate error = %v, want substring %q", err, tt.want)
			}
		})
	}
}

func TestRuntimeCloneDeepCopiesSigV4CredentialRoutes(t *testing.T) {
	cfg := validSigV4CredentialRouteConfig()
	clone := cfg.Clone()
	clone.RequestBodyScanning.SigV4CredentialRoutes[0].Methods[0] = "PUT"
	clone.RequestBodyScanning.SigV4CredentialRoutes[0].ContentTypes[0] = "text/plain"
	if cfg.RequestBodyScanning.SigV4CredentialRoutes[0].Methods[0] != "post" || cfg.RequestBodyScanning.SigV4CredentialRoutes[0].ContentTypes[0] != "application/json; charset=utf-8" {
		t.Fatal("runtime clone aliases SigV4 credential route slices")
	}
}

func TestSigV4CredentialRoutesSurfaceReloadDowngradeWarnings(t *testing.T) {
	old := validSigV4CredentialRouteConfig()
	old.RequestBodyScanning.SigV4CredentialRoutes = nil
	updated := validSigV4CredentialRouteConfig()
	warnings, err := updated.ValidateWithWarnings()
	if err != nil {
		t.Fatalf("ValidateWithWarnings: %v", err)
	}
	if !hasConfigWarningField(warnings, "request_body_scanning.sigv4_credential_routes") {
		t.Fatalf("load warnings do not surface configured route: %+v", warnings)
	}
	if !hasReloadWarning(ValidateReload(old, updated), "request_body_scanning.sigv4_credential_routes") {
		t.Fatalf("reload warnings do not surface added route: %+v", ValidateReload(old, updated))
	}
	if hasReloadWarning(ValidateReload(updated, old), "request_body_scanning.sigv4_credential_routes") {
		t.Fatal("removing a SigV4 credential route was incorrectly reported as a downgrade")
	}
}
