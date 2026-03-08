// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestConfigPathsNotEmpty(t *testing.T) {
	paths := configPaths("/fake/home")
	if len(paths) == 0 {
		t.Fatal("configPaths returned empty slice")
	}
}

func TestConfigPathsExpandHome(t *testing.T) {
	paths := configPaths("/home/testuser")
	for _, p := range paths {
		if p.Path == "" {
			t.Errorf("empty path for client %s", p.Client)
		}
		if p.Client == "" {
			t.Error("empty client name")
		}
		if p.Key == "" {
			t.Errorf("empty key for client %s", p.Client)
		}
		if p.Scope == "" {
			t.Errorf("empty scope for client %s", p.Client)
		}
	}
	// Linux should have all 6 clients
	if runtime.GOOS == "linux" {
		if len(paths) < 6 {
			t.Errorf("expected at least 6 paths on linux, got %d", len(paths))
		}
	}
}

func TestConfigPathsContainExpectedClients(t *testing.T) {
	paths := configPaths("/home/testuser")
	clients := make(map[string]bool)
	for _, p := range paths {
		clients[p.Client] = true
	}

	expected := []string{"claude-code", "claude-desktop", "cursor", "vscode", "cline", "continue"}
	for _, c := range expected {
		if !clients[c] {
			t.Errorf("missing expected client %q", c)
		}
	}
}

func TestConfigPathsVSCodeUsesServersKey(t *testing.T) {
	paths := configPaths("/home/testuser")
	for _, p := range paths {
		if p.Client == "vscode" {
			if p.Key != "servers" {
				t.Errorf("vscode key = %q, want 'servers'", p.Key)
			}
			return
		}
	}
	t.Error("vscode not found in paths")
}

func TestDiscoverWithTestFixtures(t *testing.T) {
	home := t.TempDir()

	// Create a Claude Code config with one wrapped and one bare server
	content := `{"mcpServers":{
		"brain":{"command":"pipelock","args":["mcp","proxy","--","node","brain.js"]},
		"raw":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","/tmp"]}
	}}`
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	report, err := Discover(home)
	if err != nil {
		t.Fatal(err)
	}

	if report.Summary.TotalServers != 2 {
		t.Errorf("total servers = %d, want 2", report.Summary.TotalServers)
	}
	if report.Summary.ProtectedPipelock != 1 {
		t.Errorf("protected_pipelock = %d, want 1", report.Summary.ProtectedPipelock)
	}
	if report.Summary.Unprotected != 1 {
		t.Errorf("unprotected = %d, want 1", report.Summary.Unprotected)
	}
	if report.Summary.TotalClients != 1 {
		t.Errorf("total_clients = %d, want 1", report.Summary.TotalClients)
	}
	if report.Summary.HighRisk != 1 {
		t.Errorf("high_risk = %d, want 1", report.Summary.HighRisk)
	}
}

func TestDiscoverEmptyHome(t *testing.T) {
	home := t.TempDir()

	report, err := Discover(home)
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.TotalServers != 0 {
		t.Errorf("expected 0 servers, got %d", report.Summary.TotalServers)
	}
	if report.Summary.TotalClients != 0 {
		t.Errorf("expected 0 clients, got %d", report.Summary.TotalClients)
	}
}

func TestDiscoverMultipleClients(t *testing.T) {
	home := t.TempDir()

	// Claude Code config
	cc := `{"mcpServers":{"brain":{"command":"pipelock","args":["mcp","proxy","--","node","brain.js"]}}}`
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(cc), 0o600); err != nil {
		t.Fatal(err)
	}

	// Cursor config
	cursorDir := filepath.Join(home, ".cursor")
	if err := os.MkdirAll(cursorDir, 0o750); err != nil {
		t.Fatal(err)
	}
	cursor := `{"mcpServers":{"fs":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","/tmp"]}}}`
	if err := os.WriteFile(filepath.Join(cursorDir, "mcp.json"), []byte(cursor), 0o600); err != nil {
		t.Fatal(err)
	}

	report, err := Discover(home)
	if err != nil {
		t.Fatal(err)
	}

	if report.Summary.TotalClients != 2 {
		t.Errorf("total_clients = %d, want 2", report.Summary.TotalClients)
	}
	if report.Summary.TotalServers != 2 {
		t.Errorf("total_servers = %d, want 2", report.Summary.TotalServers)
	}
}

func TestDiscoverSortsHighRiskFirst(t *testing.T) {
	home := t.TempDir()

	content := `{"mcpServers":{
		"memory":{"command":"npx","args":["-y","@modelcontextprotocol/server-memory"]},
		"filesystem":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem"]},
		"brain":{"command":"pipelock","args":["mcp","proxy","--","node","brain.js"]}
	}}`
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	report, err := Discover(home)
	if err != nil {
		t.Fatal(err)
	}

	if len(report.Servers) < 2 {
		t.Fatal("expected at least 2 servers")
	}
	// High risk should sort before medium/low
	if report.Servers[0].Risk != RiskHigh {
		t.Errorf("first server risk = %q, want high", report.Servers[0].Risk)
	}
}

func TestDiscoverJSONContract(t *testing.T) {
	home := t.TempDir()

	content := `{"mcpServers":{
		"brain":{"command":"pipelock","args":["mcp","proxy","--","node","brain.js"]},
		"raw":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem"]}
	}}`
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	report, err := Discover(home)
	if err != nil {
		t.Fatal(err)
	}

	// Marshal to JSON and verify the contract shape
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}

	// Verify required top-level keys exist
	var result map[string]json.RawMessage
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"clients", "servers", "summary"} {
		if _, ok := result[key]; !ok {
			t.Errorf("missing top-level key %q", key)
		}
	}

	// Verify server fields match the contract
	var servers []map[string]json.RawMessage
	if err := json.Unmarshal(result["servers"], &servers); err != nil {
		t.Fatal(err)
	}
	requiredFields := []string{
		"client", "config_path", "server_name", "transport",
		"command", "args", "url", "protection_state", "risk",
		"evidence", "parse_warnings",
	}
	for _, srv := range servers {
		for _, f := range requiredFields {
			if _, ok := srv[f]; !ok {
				t.Errorf("server missing required field %q", f)
			}
		}
	}

	// Verify parse_warnings is [] not null
	for _, srv := range report.Servers {
		if srv.ParseWarnings == nil {
			t.Errorf("server %q has nil ParseWarnings, want empty slice", srv.ServerName)
		}
	}

	// Verify args is [] not null
	for _, srv := range report.Servers {
		if srv.Args == nil {
			t.Errorf("server %q has nil Args, want empty slice", srv.ServerName)
		}
	}
}

func TestDiscoverMalformedConfig(t *testing.T) {
	home := t.TempDir()

	// Write a broken Claude Code config
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(`{broken json`), 0o600); err != nil {
		t.Fatal(err)
	}

	report, err := Discover(home)
	if err != nil {
		t.Fatal(err)
	}

	// Should still report the client, but with parse error
	if report.Summary.TotalClients != 1 {
		t.Errorf("total_clients = %d, want 1", report.Summary.TotalClients)
	}
	if report.Summary.ParseErrors != 1 {
		t.Errorf("parse_errors = %d, want 1", report.Summary.ParseErrors)
	}
	if report.Summary.TotalServers != 0 {
		t.Errorf("total_servers = %d, want 0", report.Summary.TotalServers)
	}
	if report.Clients[0].ParseError == "" {
		t.Error("expected non-empty parse error on client")
	}
}

func TestDiscoverProjectIdentity(t *testing.T) {
	home := t.TempDir()

	content := `{
		"projects": {
			"/home/user/project-a": {
				"mcpServers": {"filesystem": {"command": "node", "args": ["a.js"]}}
			},
			"/home/user/project-b": {
				"mcpServers": {"filesystem": {"command": "node", "args": ["b.js"]}}
			}
		}
	}`
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	report, err := Discover(home)
	if err != nil {
		t.Fatal(err)
	}

	if len(report.Servers) != 2 {
		t.Fatalf("expected 2 servers, got %d", len(report.Servers))
	}

	// Both named "filesystem" but should have different ProjectPath
	projects := map[string]bool{}
	for _, s := range report.Servers {
		if s.ServerName != "filesystem" {
			t.Errorf("unexpected server name %q", s.ServerName)
		}
		if s.ProjectPath == "" {
			t.Error("expected non-empty ProjectPath for project-scoped server")
		}
		projects[s.ProjectPath] = true
	}
	if len(projects) != 2 {
		t.Errorf("expected 2 distinct project paths, got %d", len(projects))
	}
}

func TestDiscoverGlobalServersHaveNoProjectPath(t *testing.T) {
	home := t.TempDir()

	content := `{"mcpServers": {"brain": {"command": "node", "args": ["brain.js"]}}}`
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	report, err := Discover(home)
	if err != nil {
		t.Fatal(err)
	}

	if len(report.Servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(report.Servers))
	}
	if report.Servers[0].ProjectPath != "" {
		t.Errorf("global server should have empty ProjectPath, got %q", report.Servers[0].ProjectPath)
	}
}

func TestDiscoverDeterministicSort(t *testing.T) {
	home := t.TempDir()

	// Three servers with the same risk level, should sort by name
	content := `{"mcpServers":{
		"charlie":{"command":"npx","args":["-y","@modelcontextprotocol/server-memory"]},
		"alpha":{"command":"npx","args":["-y","@modelcontextprotocol/server-memory"]},
		"bravo":{"command":"npx","args":["-y","@modelcontextprotocol/server-memory"]}
	}}`
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	// Run multiple times to verify ordering is stable
	for i := 0; i < 10; i++ {
		report, err := Discover(home)
		if err != nil {
			t.Fatal(err)
		}

		if len(report.Servers) != 3 {
			t.Fatalf("run %d: expected 3 servers, got %d", i, len(report.Servers))
		}
		if report.Servers[0].ServerName != "alpha" {
			t.Errorf("run %d: first server = %q, want alpha", i, report.Servers[0].ServerName)
		}
		if report.Servers[1].ServerName != "bravo" {
			t.Errorf("run %d: second server = %q, want bravo", i, report.Servers[1].ServerName)
		}
		if report.Servers[2].ServerName != "charlie" {
			t.Errorf("run %d: third server = %q, want charlie", i, report.Servers[2].ServerName)
		}
	}
}

func TestDiscoverConfigExistsButEmpty(t *testing.T) {
	home := t.TempDir()

	// Cursor config exists but has zero servers
	cursorDir := filepath.Join(home, ".cursor")
	if err := os.MkdirAll(cursorDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cursorDir, "mcp.json"), []byte(`{"mcpServers":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	report, err := Discover(home)
	if err != nil {
		t.Fatal(err)
	}
	// File exists but no servers: should NOT appear in clients list
	if report.Summary.TotalClients != 0 {
		t.Errorf("total_clients = %d, want 0 (empty config shouldn't count)", report.Summary.TotalClients)
	}
}

func TestBuildSummaryAllStates(t *testing.T) {
	clients := []ClientConfig{
		{Client: "a", ParseError: "broken"},
		{Client: "b"},
	}
	servers := []MCPServer{
		{Protection: ProtectedPipelock, Risk: RiskLow},
		{Protection: ProtectedOther, Risk: RiskLow},
		{Protection: Unprotected, Risk: RiskHigh},
		{Protection: Unknown, Risk: RiskLow},
	}
	s := buildSummary(clients, servers)
	if s.TotalClients != 2 {
		t.Errorf("TotalClients = %d, want 2", s.TotalClients)
	}
	if s.TotalServers != 4 {
		t.Errorf("TotalServers = %d, want 4", s.TotalServers)
	}
	if s.ProtectedPipelock != 1 {
		t.Errorf("ProtectedPipelock = %d, want 1", s.ProtectedPipelock)
	}
	if s.ProtectedOther != 1 {
		t.Errorf("ProtectedOther = %d, want 1", s.ProtectedOther)
	}
	if s.Unprotected != 1 {
		t.Errorf("Unprotected = %d, want 1", s.Unprotected)
	}
	if s.Unknown != 1 {
		t.Errorf("Unknown = %d, want 1", s.Unknown)
	}
	if s.HighRisk != 1 {
		t.Errorf("HighRisk = %d, want 1", s.HighRisk)
	}
	if s.ParseErrors != 1 {
		t.Errorf("ParseErrors = %d, want 1", s.ParseErrors)
	}
}

func TestDiscoverSortRiskThenName(t *testing.T) {
	home := t.TempDir()

	content := `{"mcpServers":{
		"memory":{"command":"npx","args":["-y","@modelcontextprotocol/server-memory"]},
		"zz-database":{"command":"npx","args":["-y","@modelcontextprotocol/server-postgres"]},
		"aa-filesystem":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem"]},
		"wrapped":{"command":"pipelock","args":["mcp","proxy","--","node","s.js"]}
	}}`
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	report, err := Discover(home)
	if err != nil {
		t.Fatal(err)
	}

	if len(report.Servers) != 4 {
		t.Fatalf("expected 4 servers, got %d", len(report.Servers))
	}

	// High risk first (alphabetically), then medium, then low
	if report.Servers[0].Risk != RiskHigh {
		t.Errorf("server[0] risk = %q, want high", report.Servers[0].Risk)
	}
	if report.Servers[0].ServerName != "aa-filesystem" {
		t.Errorf("server[0] name = %q, want aa-filesystem", report.Servers[0].ServerName)
	}
	if report.Servers[1].ServerName != "zz-database" {
		t.Errorf("server[1] name = %q, want zz-database", report.Servers[1].ServerName)
	}
	if report.Servers[2].Risk != RiskMedium {
		t.Errorf("server[2] risk = %q, want medium", report.Servers[2].Risk)
	}
	if report.Servers[3].Risk != RiskLow {
		t.Errorf("server[3] risk = %q, want low", report.Servers[3].Risk)
	}
}
