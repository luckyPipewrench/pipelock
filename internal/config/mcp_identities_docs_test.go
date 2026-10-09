// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/mcp/localservice"
)

const (
	mcpIdentitiesExampleNative = "native-binary"
	mcpIdentitiesExampleModule = "python-extension-module"
	mcpIdentitiesDocsPath      = "docs/configuration.md"
)

var mcpIdentitiesExampleBlock = regexp.MustCompile("(?s)```yaml\n# mcp-identities-example: ([a-z-]+)\n(.*?)```")

func readMCPIdentitiesDocs(t *testing.T) string {
	t.Helper()
	doc, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(mcpIdentitiesDocsPath)))
	if err != nil {
		t.Fatalf("read docs: %v", err)
	}
	return string(doc)
}

// TestDocumentedMCPIdentitiesExamplesLoad loads each mcp_identities example the
// configuration reference shows and checks the loaded fields, so a schema change
// cannot leave the documented examples stale.
func TestDocumentedMCPIdentitiesExamplesLoad(t *testing.T) {
	t.Parallel()
	doc := readMCPIdentitiesDocs(t)

	blocks := map[string]string{}
	for _, m := range mcpIdentitiesExampleBlock.FindAllStringSubmatch(doc, -1) {
		blocks[m[1]] = "mode: balanced\n" + m[2]
	}
	for _, id := range []string{mcpIdentitiesExampleNative, mcpIdentitiesExampleModule} {
		if _, ok := blocks[id]; !ok {
			t.Fatalf("%s no longer carries the %q mcp_identities example", mcpIdentitiesDocsPath, id)
		}
	}

	tests := []struct {
		example      string
		name         string
		scheme       string
		host         string
		path         string
		uid          uint32
		mappedFiles  int
		controlEnv   int
		sessionCarry string
	}{
		{mcpIdentitiesExampleNative, "vendor-indexer", MCPIdentitySchemeHTTP, MCPIdentityHostIPv4Loopback, "/rpc/v1", 1000, 0, 0, "PIPELOCK_VSCODE_INDEXER_AUTH"},
		{mcpIdentitiesExampleModule, "vendor-analysis", MCPIdentitySchemeWS, MCPIdentityHostIPv6Loopback, "/analysis", 1001, 2, 1, ""},
	}
	for _, tt := range tests {
		t.Run(tt.example, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "pipelock.yaml")
			if err := os.WriteFile(path, []byte(blocks[tt.example]), 0o600); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			cfg, err := Load(path)
			if err != nil {
				t.Fatalf("documented example does not load: %v", err)
			}
			if len(cfg.MCPIdentities) != 1 {
				t.Fatalf("identities = %+v", cfg.MCPIdentities)
			}
			id := cfg.MCPIdentities[0]
			svc := id.VerifiedLocalService
			if svc == nil {
				t.Fatalf("%s has no verified_local_service", id.Name)
			}
			if id.Name != tt.name || svc.Scheme != tt.scheme || svc.Host != tt.host || svc.Path != tt.path {
				t.Errorf("loaded %q %s://%s%s", id.Name, svc.Scheme, svc.Host, svc.Path)
			}
			if svc.PrincipalUID == nil || *svc.PrincipalUID != tt.uid {
				t.Errorf("principal_uid = %v, want %d", svc.PrincipalUID, tt.uid)
			}
			if len(svc.MappedFiles) != tt.mappedFiles || len(svc.ControlEnvironment) != tt.controlEnv {
				t.Errorf("mapped files %d, control env %d", len(svc.MappedFiles), len(svc.ControlEnvironment))
			}
			carrier := ""
			if svc.SessionHeader != nil {
				carrier = svc.SessionHeader.Carrier
			}
			if carrier != tt.sessionCarry {
				t.Errorf("session carrier = %q, want %q", carrier, tt.sessionCarry)
			}
		})
	}
}

// TestDocumentedMCPIdentitiesDenyListIsComplete requires the reference to name
// every control variable the verifier refuses, so the documented list cannot
// drift behind the one the connection check enforces.
func TestDocumentedMCPIdentitiesDenyListIsComplete(t *testing.T) {
	t.Parallel()
	doc := readMCPIdentitiesDocs(t)
	for _, name := range localservice.ControlEnvironmentDenyList() {
		if !strings.Contains(doc, "`"+name+"`") {
			t.Errorf("%s does not name deny-listed variable %s", mcpIdentitiesDocsPath, name)
		}
	}
}
