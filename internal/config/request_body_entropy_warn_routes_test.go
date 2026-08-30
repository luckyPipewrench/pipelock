// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func validEntropyWarnRouteConfig() *Config {
	cfg := Defaults()
	cfg.RequestBodyScanning.Enabled = true
	cfg.RequestBodyScanning.ContentEntropyEnabled = true
	cfg.RequestBodyScanning.ContentEntropyAction = ActionBlock
	cfg.RequestBodyScanning.ContentEntropyWarnRoutes = []RequestBodyEntropyWarnRoute{{
		Host: "UPLOAD.VENDOR.EXAMPLE.", Path: "/v1/files", ContentTypes: []string{"application/octet-stream; charset=binary"},
		Methods: []string{"post"}, Reason: "encrypted customer archive", Owner: "storage team", Expires: "2099-12-31",
	}}
	return cfg
}

func TestValidateRequestBodyEntropyWarnRoutesNormalizesExactScope(t *testing.T) {
	cfg := validEntropyWarnRouteConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	got := cfg.RequestBodyScanning.ContentEntropyWarnRoutes[0]
	if got.Host != "upload.vendor.example" || got.Path != "/v1/files" || got.ContentTypes[0] != "application/octet-stream" || got.Methods[0] != "POST" {
		t.Fatalf("route was not normalized: %+v", got)
	}
}

func TestLoadStrictYAMLRecognizesEntropyWarnRoutes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pipelock.yaml")
	yaml := `mode: balanced
request_body_scanning:
  content_entropy_action: block
  content_entropy_warn_routes:
    - host: upload.vendor.example
      path: /v1/files
      content_types: [application/octet-stream]
      methods: [POST]
      reason: encrypted customer archive
      owner: storage team
      expires: 2099-12-31
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("strict Load rejected new route field: %v", err)
	}
	if len(cfg.RequestBodyScanning.ContentEntropyWarnRoutes) != 1 {
		t.Fatalf("loaded routes = %+v", cfg.RequestBodyScanning.ContentEntropyWarnRoutes)
	}
}

func TestValidateRequestBodyEntropyWarnRoutesRejectsUnsafeOrInertEntries(t *testing.T) {
	tests := []struct {
		name string
		edit func(*Config)
		want string
	}{
		{"global entropy is not block", func(c *Config) { c.RequestBodyScanning.ContentEntropyAction = ActionWarn }, "requires enabled request body scanning"},
		{"wildcard host", func(c *Config) { c.RequestBodyScanning.ContentEntropyWarnRoutes[0].Host = "*.vendor.example" }, "exact host"},
		{"root path", func(c *Config) { c.RequestBodyScanning.ContentEntropyWarnRoutes[0].Path = "/" }, "exact non-root canonical path"},
		{"encoded topology", func(c *Config) { c.RequestBodyScanning.ContentEntropyWarnRoutes[0].Path = "/v1%2ffiles" }, "exact non-root canonical path"},
		{"text content type", func(c *Config) {
			c.RequestBodyScanning.ContentEntropyWarnRoutes[0].ContentTypes = []string{"application/json"}
		}, "textual/scannable"},
		{"invalid method", func(c *Config) { c.RequestBodyScanning.ContentEntropyWarnRoutes[0].Methods = []string{"UPLOAD"} }, "supported HTTP method"},
		{"missing reason", func(c *Config) { c.RequestBodyScanning.ContentEntropyWarnRoutes[0].Reason = "" }, "reason is required"},
		{"missing owner", func(c *Config) { c.RequestBodyScanning.ContentEntropyWarnRoutes[0].Owner = "" }, "owner is required"},
		{"expired", func(c *Config) { c.RequestBodyScanning.ContentEntropyWarnRoutes[0].Expires = "2020-01-01" }, "already expired"},
		{"overlapping owner", func(c *Config) {
			duplicate := c.RequestBodyScanning.ContentEntropyWarnRoutes[0]
			duplicate.Methods = nil
			duplicate.Owner = "other team"
			c.RequestBodyScanning.ContentEntropyWarnRoutes = append(c.RequestBodyScanning.ContentEntropyWarnRoutes, duplicate)
		}, "overlaps content_entropy_warn_routes[0]"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validEntropyWarnRouteConfig()
			tt.edit(cfg)
			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Validate error = %v, want substring %q", err, tt.want)
			}
		})
	}
}

func TestRuntimeCloneDeepCopiesEntropyWarnRoutes(t *testing.T) {
	cfg := validEntropyWarnRouteConfig()
	clone := cfg.Clone()
	clone.RequestBodyScanning.ContentEntropyWarnRoutes[0].Methods[0] = "PUT"
	clone.RequestBodyScanning.ContentEntropyWarnRoutes[0].ContentTypes[0] = "image/png"
	if cfg.RequestBodyScanning.ContentEntropyWarnRoutes[0].Methods[0] != "post" || cfg.RequestBodyScanning.ContentEntropyWarnRoutes[0].ContentTypes[0] != "application/octet-stream; charset=binary" {
		t.Fatal("runtime clone aliases entropy warning route slices")
	}
}

func TestEntropyWarnRoutesSurfaceLoadAndReloadDowngradeWarnings(t *testing.T) {
	old := validEntropyWarnRouteConfig()
	old.RequestBodyScanning.ContentEntropyWarnRoutes = nil
	updated := validEntropyWarnRouteConfig()

	warnings, err := updated.ValidateWithWarnings()
	if err != nil {
		t.Fatalf("ValidateWithWarnings: %v", err)
	}
	if !hasConfigWarningField(warnings, "request_body_scanning.content_entropy_warn_routes") {
		t.Fatalf("load warnings do not surface entropy route downgrade: %+v", warnings)
	}
	if !hasReloadWarning(ValidateReload(old, updated), "request_body_scanning.content_entropy_warn_routes") {
		t.Fatalf("reload warnings do not surface added entropy route: %+v", ValidateReload(old, updated))
	}
	if hasReloadWarning(ValidateReload(updated, old), "request_body_scanning.content_entropy_warn_routes") {
		t.Fatal("removing an entropy warning route was incorrectly reported as a downgrade")
	}

	beforeExtension := validEntropyWarnRouteConfig()
	beforeExtension.RequestBodyScanning.ContentEntropyWarnRoutes[0].Expires = "2098-12-31"
	afterExtension := validEntropyWarnRouteConfig()
	if !hasReloadWarning(ValidateReload(beforeExtension, afterExtension), "request_body_scanning.content_entropy_warn_routes") {
		t.Fatal("extending an entropy warning route expiry did not surface a reload downgrade warning")
	}
}

func hasConfigWarningField(warnings []Warning, field string) bool {
	for _, warning := range warnings {
		if warning.Field == field {
			return true
		}
	}
	return false
}
