// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"strings"
	"testing"
)

func TestGenerateWrapperStdio(t *testing.T) {
	server := MCPServer{
		ServerName: "filesystem",
		Client:     "cursor",
		Command:    "npx",
		Args:       []string{"-y", "@modelcontextprotocol/server-filesystem", "/tmp"},
		Transport:  "stdio",
		Protection: Unprotected,
	}

	suggestion := GenerateWrapper(server)
	if suggestion == "" {
		t.Fatal("expected non-empty suggestion")
	}
	if !strings.Contains(suggestion, "pipelock") {
		t.Error("suggestion should contain pipelock")
	}
	if !strings.Contains(suggestion, "mcp") {
		t.Error("suggestion should contain mcp")
	}
	if !strings.Contains(suggestion, "proxy") {
		t.Error("suggestion should contain proxy")
	}
	if !strings.Contains(suggestion, "npx") {
		t.Error("suggestion should contain original command")
	}
}

func TestGenerateWrapperHTTP(t *testing.T) {
	server := MCPServer{
		ServerName: "remote",
		Client:     "cursor",
		URL:        "https://api.example.com/mcp",
		Transport:  "http",
		Protection: Unprotected,
	}

	suggestion := GenerateWrapper(server)
	if !strings.Contains(suggestion, "--upstream") {
		t.Error("HTTP suggestion should contain --upstream")
	}
	if !strings.Contains(suggestion, "https://api.example.com/mcp") {
		t.Error("suggestion should contain original URL")
	}
}

func TestGenerateWrapperUnknown(t *testing.T) {
	server := MCPServer{
		ServerName: "mystery",
		Transport:  "unknown",
		Protection: Unprotected,
	}

	suggestion := GenerateWrapper(server)
	if !strings.Contains(suggestion, "no suggestion") {
		t.Error("should indicate no suggestion available")
	}
}

func TestGenerateWrapperStdioWithEnv(t *testing.T) {
	server := MCPServer{
		ServerName: "brain",
		Client:     "claude-code",
		Command:    "node",
		Args:       []string{"server.js"},
		Env:        map[string]string{"BRAIN_DIR": "/data", "API_KEY": "secret"},
		Transport:  "stdio",
		Protection: Unprotected,
	}

	suggestion := GenerateWrapper(server)
	if !strings.Contains(suggestion, `"--env"`) {
		t.Error("suggestion should contain --env flags for env vars")
	}
	if !strings.Contains(suggestion, `"API_KEY"`) {
		t.Error("suggestion should contain API_KEY env var name")
	}
	if !strings.Contains(suggestion, `"BRAIN_DIR"`) {
		t.Error("suggestion should contain BRAIN_DIR env var name")
	}
	// Verify --env flags come before the -- separator
	envIdx := strings.Index(suggestion, `"--env"`)
	sepIdx := strings.Index(suggestion, `"--"`)
	if envIdx > sepIdx {
		t.Error("--env flags should appear before -- separator")
	}
}

func TestGenerateWrapperNoArgs(t *testing.T) {
	server := MCPServer{
		ServerName: "simple",
		Client:     "cursor",
		Command:    "myserver",
		Args:       []string{},
		Transport:  "stdio",
		Protection: Unprotected,
	}

	suggestion := GenerateWrapper(server)
	if !strings.Contains(suggestion, "pipelock") {
		t.Error("suggestion should contain pipelock")
	}
	if !strings.Contains(suggestion, "myserver") {
		t.Error("suggestion should contain original command")
	}
}
