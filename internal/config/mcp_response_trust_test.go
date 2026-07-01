// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadMCPResponseTrustConfig(t *testing.T, body string) *Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pipelock.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return cfg
}

func TestMCPResponseTrustConfigStates(t *testing.T) {
	t.Run("omitted defaults to no explicit trust", func(t *testing.T) {
		cfg := loadMCPResponseTrustConfig(t, "version: 1\n")
		trust, ok := cfg.MCPResponseTrustForServer("codex")
		if ok {
			t.Fatal("omitted mcp_servers must not create an explicit trust entry")
		}
		if trust != ResponseTrustUntrusted {
			t.Fatalf("trust = %q, want %q", trust, ResponseTrustUntrusted)
		}
	})

	t.Run("null defaults to no explicit trust", func(t *testing.T) {
		cfg := loadMCPResponseTrustConfig(t, "version: 1\nresponse_scanning:\n  mcp_servers: null\n")
		if len(cfg.ResponseScanning.MCPServers) != 0 {
			t.Fatalf("MCPServers len = %d, want 0", len(cfg.ResponseScanning.MCPServers))
		}
	})

	t.Run("blank trust fails closed at load", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "pipelock.yaml")
		err := os.WriteFile(path, []byte("version: 1\nresponse_scanning:\n  mcp_servers:\n    - server: codex\n      trust: \"\"\n"), 0o600)
		if err != nil {
			t.Fatalf("write config: %v", err)
		}
		_, err = Load(path)
		if err == nil || !strings.Contains(err.Error(), "response_scanning.mcp_servers[0].trust") {
			t.Fatalf("Load err = %v, want trust validation error", err)
		}
	})

	t.Run("explicit untrusted maps to block", func(t *testing.T) {
		cfg := loadMCPResponseTrustConfig(t, "version: 1\nresponse_scanning:\n  mcp_servers:\n    - server: web-fetch\n      trust: untrusted\n")
		trust, ok := cfg.MCPResponseTrustForServer("web-fetch")
		if !ok || trust != ResponseTrustUntrusted {
			t.Fatalf("trust=%q ok=%v, want explicit %q", trust, ok, ResponseTrustUntrusted)
		}
		if got := MCPResponseActionForTrust(trust); got != ActionBlock {
			t.Fatalf("action = %q, want %q", got, ActionBlock)
		}
	})

	t.Run("explicit reasoning maps to warn", func(t *testing.T) {
		cfg := loadMCPResponseTrustConfig(t, "version: 1\nresponse_scanning:\n  mcp_servers:\n    - server: codex\n      trust: reasoning\n")
		trust, ok := cfg.MCPResponseTrustForServer("codex")
		if !ok || trust != ResponseTrustReasoning {
			t.Fatalf("trust=%q ok=%v, want explicit %q", trust, ok, ResponseTrustReasoning)
		}
		if got := MCPResponseActionForTrust(trust); got != ActionWarn {
			t.Fatalf("action = %q, want %q", got, ActionWarn)
		}
	})
}

func TestMCPResponseTrustValidationRejectsUnknownAndInertConfigWarns(t *testing.T) {
	cfg := Defaults()
	cfg.ResponseScanning.MCPServers = []MCPResponseServerTrust{{Server: "codex", Trust: "analysis"}}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "must be") {
		t.Fatalf("Validate err = %v, want unknown trust rejection", err)
	}

	cfg = Defaults()
	cfg.ResponseScanning.MCPServers = []MCPResponseServerTrust{{Server: `codex\prod`, Trust: ResponseTrustReasoning}}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "without URL syntax or slashes") {
		t.Fatalf("Validate err = %v, want backslash separator rejection", err)
	}

	cfg = Defaults()
	cfg.ResponseScanning.MCPServers = []MCPResponseServerTrust{{Server: "docs cache", Trust: ResponseTrustReasoning}}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "whitespace/control characters") {
		t.Fatalf("Validate err = %v, want whitespace rejection", err)
	}

	cfg = Defaults()
	cfg.ResponseScanning.Enabled = false
	cfg.ResponseScanning.MCPServers = []MCPResponseServerTrust{{Server: "codex", Trust: ResponseTrustReasoning}}
	warnings, err := cfg.ValidateWithWarnings()
	if err != nil {
		t.Fatalf("ValidateWithWarnings: %v", err)
	}
	for _, warning := range warnings {
		if warning.Field == "response_scanning.mcp_servers" {
			return
		}
	}
	t.Fatalf("missing disabled-scanner warning in %#v", warnings)
}

func TestValidateReload_MCPResponseTrustReasoningAddedWarns(t *testing.T) {
	old := Defaults()
	updated := Defaults()
	updated.ResponseScanning.MCPServers = []MCPResponseServerTrust{{Server: "codex", Trust: ResponseTrustReasoning}}

	for _, warning := range ValidateReload(old, updated) {
		if warning.Field == "response_scanning.mcp_servers" {
			return
		}
	}
	t.Fatal("missing reload warning when MCP response trust changes to reasoning")
}

func TestValidateReload_MCPResponseTrustMultipleReasoningWarnings(t *testing.T) {
	old := Defaults()
	updated := Defaults()
	updated.ResponseScanning.MCPServers = []MCPResponseServerTrust{
		{Server: "codex", Trust: ResponseTrustReasoning},
		{Server: "security-reviewer", Trust: ResponseTrustReasoning},
	}

	warnings := ValidateReload(old, updated)
	var got []string
	for _, warning := range warnings {
		if warning.Field == "response_scanning.mcp_servers" {
			got = append(got, warning.Message)
		}
	}
	if len(got) != 2 {
		t.Fatalf("MCP trust reload warning count = %d, want 2: %#v", len(got), got)
	}
	for _, server := range []string{"codex", "security-reviewer"} {
		found := false
		for _, message := range got {
			if strings.Contains(message, server) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing reload warning for %s in %#v", server, got)
		}
	}
}

func TestValidateReload_MCPResponseTrustUnchangedNoWarning(t *testing.T) {
	old := Defaults()
	updated := Defaults()
	old.ResponseScanning.MCPServers = []MCPResponseServerTrust{{Server: "codex", Trust: ResponseTrustReasoning}}
	updated.ResponseScanning.MCPServers = []MCPResponseServerTrust{{Server: "codex", Trust: ResponseTrustReasoning}}

	for _, warning := range ValidateReload(old, updated) {
		if warning.Field == "response_scanning.mcp_servers" {
			t.Fatalf("unexpected MCP trust reload warning: %#v", warning)
		}
	}
}

func TestCanonicalPolicyHash_MCPResponseTrustOrderInvariant(t *testing.T) {
	a := Defaults()
	a.ResponseScanning.MCPServers = []MCPResponseServerTrust{
		{Server: "web-fetch", Trust: ResponseTrustUntrusted},
		{Server: "codex", Trust: ResponseTrustReasoning},
	}
	b := Defaults()
	b.ResponseScanning.MCPServers = []MCPResponseServerTrust{
		{Server: "codex", Trust: ResponseTrustReasoning},
		{Server: "web-fetch", Trust: ResponseTrustUntrusted},
	}

	if gotA, gotB := a.CanonicalPolicyHash(), b.CanonicalPolicyHash(); gotA != gotB {
		t.Fatalf("CanonicalPolicyHash reordered mcp_servers mismatch:\nA=%s\nB=%s", gotA, gotB)
	}
}
