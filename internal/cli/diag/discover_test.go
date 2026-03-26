// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/discover"
)

func TestDiscoverCmd_JSONEmptyHome(t *testing.T) {
	var buf bytes.Buffer
	cmd := DiscoverCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--json", "--home", t.TempDir()})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	// Should produce valid JSON with zero servers
	var report discover.Report
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("invalid JSON output: %v\n%s", err, buf.String())
	}
	if report.Summary.TotalServers != 0 {
		t.Errorf("expected 0 servers, got %d", report.Summary.TotalServers)
	}
}

func TestDiscoverCmd_JSONWithServers(t *testing.T) {
	home := t.TempDir()

	content := `{"mcpServers":{
		"brain":{"command":"pipelock","args":["mcp","proxy","--","node","brain.js"]},
		"raw":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem"]}
	}}`
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	cmd := DiscoverCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{"--json", "--home", home})

	err := cmd.Execute()

	// Should exit 1 because unprotected servers exist
	var exitErr *cliutil.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected ExitError, got %v", err)
	}
	if exitErr.Code != 1 {
		t.Errorf("exit code = %d, want 1", exitErr.Code)
	}

	var report discover.Report
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, stdout.String())
	}
	if report.Summary.TotalServers != 2 {
		t.Errorf("total_servers = %d, want 2", report.Summary.TotalServers)
	}
}

func TestDiscoverCmd_HumanOutput(t *testing.T) {
	home := t.TempDir()
	content := `{"mcpServers":{"brain":{"command":"pipelock","args":["mcp","proxy","--","node","brain.js"]}}}`
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	cmd := DiscoverCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--home", home})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}

	output := buf.String()
	if !bytes.Contains([]byte(output), []byte("Pipelock Discovery")) {
		t.Error("expected 'Pipelock Discovery' header")
	}
	if !bytes.Contains([]byte(output), []byte("All servers are protected")) {
		t.Errorf("expected 'All servers are protected', got:\n%s", output)
	}
}

func TestDiscoverCmd_ExitCodeZeroAllProtected(t *testing.T) {
	home := t.TempDir()
	content := `{"mcpServers":{"brain":{"command":"pipelock","args":["mcp","proxy","--","node","brain.js"]}}}`
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	cmd := DiscoverCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--home", home})
	err := cmd.Execute()
	if err != nil {
		t.Errorf("expected nil error (exit 0), got %v", err)
	}
}

func TestDiscoverCmd_ExitCodeOneUnprotected(t *testing.T) {
	home := t.TempDir()
	content := `{"mcpServers":{"raw":{"command":"npx","args":["-y","@mcp/server-fs"]}}}`
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	cmd := DiscoverCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--home", home})
	err := cmd.Execute()

	var exitErr *cliutil.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected ExitError, got %v", err)
	}
	if exitErr.Code != 1 {
		t.Errorf("exit code = %d, want 1", exitErr.Code)
	}
}

func TestDiscoverCmd_GenerateFlag(t *testing.T) {
	home := t.TempDir()
	content := `{"mcpServers":{"fs":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem"]}}}`
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	cmd := DiscoverCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--generate", "--home", home})
	_ = cmd.Execute() // exit 1 expected

	output := buf.String()
	if !bytes.Contains([]byte(output), []byte("Wrapper suggestions")) {
		t.Errorf("expected wrapper suggestions, got:\n%s", output)
	}
	if !bytes.Contains([]byte(output), []byte("pipelock")) {
		t.Error("suggestion should mention pipelock")
	}
}

func TestDiscoverCmd_NoConfigs(t *testing.T) {
	var buf bytes.Buffer
	cmd := DiscoverCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--home", t.TempDir()})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}

	output := buf.String()
	if !bytes.Contains([]byte(output), []byte("No AI agent configs found")) {
		t.Errorf("expected 'No AI agent configs found', got:\n%s", output)
	}
}

func TestDiscoverCmd_MalformedConfigExitOne(t *testing.T) {
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(`{broken`), 0o600); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	cmd := DiscoverCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{"--home", home})
	err := cmd.Execute()

	var exitErr *cliutil.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected ExitError for malformed config, got %v", err)
	}
	if exitErr.Code != 1 {
		t.Errorf("exit code = %d, want 1", exitErr.Code)
	}

	output := buf.String()
	if !bytes.Contains([]byte(output), []byte("PARSE ERROR")) {
		t.Errorf("expected PARSE ERROR in output, got:\n%s", output)
	}
}

func TestDiscoverCmd_ProjectPathInOutput(t *testing.T) {
	home := t.TempDir()
	content := `{
		"projects": {
			"/home/user/myproject": {
				"mcpServers": {"fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem"]}}
			}
		}
	}`
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	cmd := DiscoverCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--home", home})
	_ = cmd.Execute() // exit 1 expected

	output := buf.String()
	if !bytes.Contains([]byte(output), []byte("/home/user/myproject")) {
		t.Errorf("expected project path in output, got:\n%s", output)
	}
}

func TestDiscoverCmd_ProjectPathInGenerate(t *testing.T) {
	home := t.TempDir()
	content := `{
		"projects": {
			"/home/user/myproject": {
				"mcpServers": {"fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem"]}}
			}
		}
	}`
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	cmd := DiscoverCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--generate", "--home", home})
	_ = cmd.Execute() // exit 1 expected

	output := buf.String()
	if !bytes.Contains([]byte(output), []byte("project: /home/user/myproject")) {
		t.Errorf("expected project path in wrapper suggestion, got:\n%s", output)
	}
}

func TestDiscoverCmd_PartialParseFailureSurfaced(t *testing.T) {
	home := t.TempDir()
	content := `{
		"mcpServers": {"global": {"command": "pipelock", "args": ["mcp", "proxy", "--", "node", "s.js"]}},
		"projects": {
			"/good": {"mcpServers": {"s1": {"command": "node", "args": ["a.js"]}}},
			"/bad": "not_an_object"
		}
	}`
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	cmd := DiscoverCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{"--json", "--home", home})
	_ = cmd.Execute()

	var report discover.Report
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, stdout.String())
	}

	// Should have 3 servers: global + s1 from /good + placeholder for /bad
	if report.Summary.TotalServers != 3 {
		t.Errorf("total_servers = %d, want 3", report.Summary.TotalServers)
	}

	// Find the placeholder server
	found := false
	for _, s := range report.Servers {
		if s.ServerName == "(malformed project)" {
			found = true
			if len(s.ParseWarnings) == 0 {
				t.Error("expected parse_warnings on placeholder server")
			}
			if s.ProjectPath != "/bad" {
				t.Errorf("placeholder ProjectPath = %q, want /bad", s.ProjectPath)
			}
		}
	}
	if !found {
		t.Error("expected placeholder server for malformed project entry")
	}
}

func TestDiscoverCmd_MalformedConfigJSON(t *testing.T) {
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(`{broken`), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	cmd := DiscoverCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{"--json", "--home", home})
	_ = cmd.Execute()

	var report discover.Report
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, stdout.String())
	}
	if report.Summary.ParseErrors != 1 {
		t.Errorf("parse_errors = %d, want 1", report.Summary.ParseErrors)
	}
	if report.Clients[0].ParseError == "" {
		t.Error("expected non-empty parse_error on client")
	}
}

func TestServerDescription(t *testing.T) {
	tests := []struct {
		name   string
		server discover.MCPServer
		want   string
	}{
		{
			name: "command with args",
			server: discover.MCPServer{
				Command: "npx",
				Args:    []string{"-y", "@example/server"},
			},
			want: "npx -y @example/server",
		},
		{
			name: "command without args",
			server: discover.MCPServer{
				Command: "my-server",
			},
			want: "my-server",
		},
		{
			name: "url only",
			server: discover.MCPServer{
				URL: "https://api.example.com/mcp",
			},
			want: "https://api.example.com/mcp",
		},
		{
			name:   "unknown (empty)",
			server: discover.MCPServer{},
			want:   "(unknown)",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := serverDescription(tc.server); got != tc.want {
				t.Errorf("serverDescription() = %q, want %q", got, tc.want)
			}
		})
	}
}
