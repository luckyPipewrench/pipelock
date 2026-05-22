// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"strings"
	"testing"
)

func TestGenerateWrapperStdio(t *testing.T) {
	server := MCPServer{
		ServerName: kwFilesystem,
		Client:     clientCursor,
		Command:    testCmdNpx,
		Args:       []string{"-y", testServerFilesystemPkg, "/tmp"},
		Transport:  TransportStdio,
		Protection: Unprotected,
	}

	suggestion := GenerateWrapper(server)
	if suggestion == "" {
		t.Fatal("expected non-empty suggestion")
	}
	if !strings.Contains(suggestion, wrapperCommand) {
		t.Error("suggestion should contain pipelock")
	}
	if !strings.Contains(suggestion, wrapperArgMCP) {
		t.Error("suggestion should contain mcp")
	}
	if !strings.Contains(suggestion, wrapperArgProxy) {
		t.Error("suggestion should contain proxy")
	}
	if !strings.Contains(suggestion, testCmdNpx) {
		t.Error("suggestion should contain original command")
	}
}

func TestGenerateWrapperHTTP(t *testing.T) {
	server := MCPServer{
		ServerName: "remote",
		Client:     clientCursor,
		URL:        testHTTPMCPURL,
		Transport:  TransportHTTP,
		Protection: Unprotected,
	}

	suggestion := GenerateWrapper(server)
	if !strings.Contains(suggestion, "--upstream") {
		t.Error("HTTP suggestion should contain --upstream")
	}
	if !strings.Contains(suggestion, testHTTPMCPURL) {
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
		Client:     clientClaudeCode,
		Command:    testCmdNode,
		Args:       []string{testServerJS},
		Env:        map[string]string{"BRAIN_DIR": testDataDir, "API_KEY": secretMarker},
		Transport:  TransportStdio,
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
		Client:     clientCursor,
		Command:    "myserver",
		Args:       []string{},
		Transport:  TransportStdio,
		Protection: Unprotected,
	}

	suggestion := GenerateWrapper(server)
	if !strings.Contains(suggestion, wrapperCommand) {
		t.Error("suggestion should contain pipelock")
	}
	if !strings.Contains(suggestion, "myserver") {
		t.Error("suggestion should contain original command")
	}
}
