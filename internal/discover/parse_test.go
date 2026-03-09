// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseMCPServersStdio(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	content := `{"mcpServers":{"brain":{"command":"pipelock","args":["mcp","proxy","--","node","server.js"],"env":{"KEY":"val"}}}}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	servers, err := parseConfigFile(path, "mcpServers", "claude-code")
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(servers))
	}
	s := servers[0]
	if s.ServerName != "brain" {
		t.Errorf("name = %q, want brain", s.ServerName)
	}
	if s.Command != "pipelock" {
		t.Errorf("command = %q, want pipelock", s.Command)
	}
	if s.Transport != "stdio" {
		t.Errorf("transport = %q, want stdio", s.Transport)
	}
	if s.Client != "claude-code" {
		t.Errorf("client = %q, want claude-code", s.Client)
	}
}

func TestParseMCPServersHTTP(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	content := `{"mcpServers":{"remote":{"url":"https://api.example.com/mcp","headers":{"Authorization":"Bearer tok"}}}}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	servers, err := parseConfigFile(path, "mcpServers", "cursor")
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(servers))
	}
	s := servers[0]
	if s.Transport != "http" {
		t.Errorf("transport = %q, want http", s.Transport)
	}
	if s.URL != "https://api.example.com/mcp" {
		t.Errorf("url = %q", s.URL)
	}
	// Headers present should produce a parse warning
	if len(s.ParseWarnings) == 0 {
		t.Error("expected parse warning when headers are present")
	}
}

func TestParseMCPServersNoHeadersNoWarning(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	content := `{"mcpServers":{"remote":{"url":"https://api.example.com/mcp"}}}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	servers, err := parseConfigFile(path, "mcpServers", "cursor")
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(servers))
	}
	if len(servers[0].ParseWarnings) != 0 {
		t.Errorf("expected no parse warnings without headers, got %v", servers[0].ParseWarnings)
	}
}

func TestParseVSCodeServersKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.json")
	content := `{"servers":{"memory":{"type":"stdio","command":"npx","args":["-y","@modelcontextprotocol/server-memory"]}}}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	servers, err := parseConfigFile(path, "servers", "vscode")
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(servers))
	}
	if servers[0].ServerName != "memory" {
		t.Errorf("name = %q, want memory", servers[0].ServerName)
	}
}

func TestParseMissingFile(t *testing.T) {
	_, err := parseConfigFile("/nonexistent/path.json", "mcpServers", "test")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestParseServerURL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	content := `{"mcpServers":{"remote":{"serverUrl":"https://example.com/mcp"}}}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	servers, err := parseConfigFile(path, "mcpServers", "windsurf")
	if err != nil {
		t.Fatal(err)
	}
	if servers[0].URL != "https://example.com/mcp" {
		t.Errorf("url = %q, want https://example.com/mcp", servers[0].URL)
	}
	if servers[0].Transport != "http" {
		t.Errorf("transport = %q, want http", servers[0].Transport)
	}
}

func TestParseEmptyServers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	content := `{"mcpServers":{}}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	servers, err := parseConfigFile(path, "mcpServers", "claude-code")
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 0 {
		t.Errorf("expected 0 servers, got %d", len(servers))
	}
}

func TestParseMalformedJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{broken json`), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := parseConfigFile(path, "mcpServers", "test")
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestParseMalformedServersValue(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	content := `{"mcpServers": "not_an_object"}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := parseConfigFile(path, "mcpServers", "test")
	if err == nil {
		t.Fatal("expected error for non-object mcpServers")
	}
}

func TestParseMissingKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	content := `{"otherKey": {}}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	servers, err := parseConfigFile(path, "mcpServers", "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(servers) != 0 {
		t.Errorf("expected 0 servers, got %d", len(servers))
	}
}

func TestParseMultipleServers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	content := `{"mcpServers":{
		"brain":{"command":"pipelock","args":["mcp","proxy","--","node","brain.js"]},
		"fs":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem"]},
		"remote":{"url":"https://api.example.com/mcp"}
	}}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	servers, err := parseConfigFile(path, "mcpServers", "cursor")
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 3 {
		t.Fatalf("expected 3 servers, got %d", len(servers))
	}

	transports := map[string]int{}
	for _, s := range servers {
		transports[s.Transport]++
	}
	if transports["stdio"] != 2 {
		t.Errorf("expected 2 stdio servers, got %d", transports["stdio"])
	}
	if transports["http"] != 1 {
		t.Errorf("expected 1 http server, got %d", transports["http"])
	}
}

func TestParseNilArgs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	content := `{"mcpServers":{"noargs":{"command":"myserver"}}}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	servers, err := parseConfigFile(path, "mcpServers", "test")
	if err != nil {
		t.Fatal(err)
	}
	if servers[0].Args == nil {
		t.Error("Args should be empty slice, not nil")
	}
}

func TestParseEmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := parseConfigFile(path, "mcpServers", "test")
	if err == nil {
		t.Fatal("expected error for empty file")
	}
}

func TestParseClaudeCodeProjectServers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "claude.json")
	content := `{
		"mcpServers": {"global": {"command": "node", "args": ["global.js"]}},
		"projects": {
			"/home/user/dev/myproject": {
				"mcpServers": {"local": {"command": "node", "args": ["local.js"]}}
			}
		}
	}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	servers, err := parseClaudeCodeConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 2 {
		t.Fatalf("expected 2 servers, got %d", len(servers))
	}
	names := map[string]bool{}
	for _, s := range servers {
		names[s.ServerName] = true
	}
	if !names["global"] || !names["local"] {
		t.Errorf("expected global and local, got %v", names)
	}
}

func TestParseClaudeCodeGlobalOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "claude.json")
	content := `{"mcpServers": {"brain": {"command": "node", "args": ["brain.js"]}}}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	servers, err := parseClaudeCodeConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(servers))
	}
}

func TestParseClaudeCodeMultipleProjects(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "claude.json")
	content := `{
		"mcpServers": {"global": {"command": "node", "args": ["global.js"]}},
		"projects": {
			"/home/user/project-a": {
				"mcpServers": {"server-a": {"command": "node", "args": ["a.js"]}}
			},
			"/home/user/project-b": {
				"mcpServers": {"server-b": {"command": "node", "args": ["b.js"]}}
			}
		}
	}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	servers, err := parseClaudeCodeConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 3 {
		t.Fatalf("expected 3 servers, got %d", len(servers))
	}
}

func TestParseClaudeCodeEmptyProjects(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "claude.json")
	content := `{"mcpServers": {}, "projects": {}}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	servers, err := parseClaudeCodeConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 0 {
		t.Errorf("expected 0 servers, got %d", len(servers))
	}
}

func TestParseClaudeCodeMalformedProjects(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "claude.json")
	// projects key is not a map
	content := `{"mcpServers": {"a": {"command": "node"}}, "projects": "not_a_map"}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	servers, err := parseClaudeCodeConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	// Should get global server + placeholder for malformed projects
	if len(servers) != 2 {
		t.Fatalf("expected 2 servers, got %d", len(servers))
	}

	// Find the placeholder
	var placeholder *MCPServer
	for i := range servers {
		if servers[i].ServerName == "(projects)" {
			placeholder = &servers[i]
			break
		}
	}
	if placeholder == nil {
		t.Fatal("expected placeholder server for malformed projects")
	}
	if len(placeholder.ParseWarnings) == 0 {
		t.Error("expected parse_warnings on placeholder")
	}
	if placeholder.Transport != TransportUnknown {
		t.Errorf("placeholder transport = %q, want unknown", placeholder.Transport)
	}
}

func TestParseClaudeCodeMalformedProjectEntry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "claude.json")
	// One valid project, one malformed project entry
	content := `{
		"projects": {
			"/good": {"mcpServers": {"s1": {"command": "node", "args": ["a.js"]}}},
			"/bad": "not_an_object"
		}
	}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	servers, err := parseClaudeCodeConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	// Should get server from /good + placeholder for /bad
	if len(servers) != 2 {
		t.Fatalf("expected 2 servers, got %d", len(servers))
	}

	var placeholder *MCPServer
	for i := range servers {
		if servers[i].ServerName == "(malformed project)" {
			placeholder = &servers[i]
			break
		}
	}
	if placeholder == nil {
		t.Fatal("expected placeholder server for malformed project entry")
	}
	if placeholder.ProjectPath != "/bad" {
		t.Errorf("placeholder ProjectPath = %q, want /bad", placeholder.ProjectPath)
	}
	if len(placeholder.ParseWarnings) == 0 {
		t.Error("expected parse_warnings on placeholder")
	}
}

func TestParseClaudeCodeMalformedProjectMCPServers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "claude.json")
	content := `{
		"projects": {
			"/good": {"mcpServers": {"s1": {"command": "node", "args": ["a.js"]}}},
			"/bad": {"mcpServers": "not_an_object"}
		}
	}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	servers, err := parseClaudeCodeConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	// Should get server from /good + placeholder for /bad
	if len(servers) != 2 {
		t.Fatalf("expected 2 servers, got %d", len(servers))
	}

	var placeholder *MCPServer
	for i := range servers {
		if servers[i].ServerName == "(malformed mcpServers)" {
			placeholder = &servers[i]
			break
		}
	}
	if placeholder == nil {
		t.Fatal("expected placeholder server for malformed mcpServers")
	}
	if placeholder.ProjectPath != "/bad" {
		t.Errorf("placeholder ProjectPath = %q, want /bad", placeholder.ProjectPath)
	}
	if len(placeholder.ParseWarnings) == 0 {
		t.Error("expected parse_warnings on placeholder")
	}
}

func TestParseClaudeCodeProjectPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "claude.json")
	content := `{
		"projects": {
			"/home/user/myproject": {
				"mcpServers": {"local": {"command": "node", "args": ["local.js"]}}
			}
		}
	}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	servers, err := parseClaudeCodeConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(servers))
	}
	if servers[0].ProjectPath != "/home/user/myproject" {
		t.Errorf("ProjectPath = %q, want /home/user/myproject", servers[0].ProjectPath)
	}
}

func TestParseClaudeCodeMissingFile(t *testing.T) {
	_, err := parseClaudeCodeConfig("/nonexistent/claude.json")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestParseClaudeCodeMalformedTopLevel(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "claude.json")
	if err := os.WriteFile(path, []byte(`not json at all`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := parseClaudeCodeConfig(path)
	if err == nil {
		t.Fatal("expected error for malformed top-level JSON")
	}
}

func TestParseClaudeCodeMalformedGlobalMCPServers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "claude.json")
	content := `{"mcpServers": "not_a_map"}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := parseClaudeCodeConfig(path)
	if err == nil {
		t.Fatal("expected error for malformed global mcpServers")
	}
}

func TestParseUnknownTransport(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	// No command, no url = unknown transport
	content := `{"mcpServers":{"mystery":{"env":{"KEY":"val"}}}}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	servers, err := parseConfigFile(path, "mcpServers", "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(servers))
	}
	if servers[0].Transport != "unknown" {
		t.Errorf("transport = %q, want unknown", servers[0].Transport)
	}
}
