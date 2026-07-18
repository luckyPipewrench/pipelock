// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewServerRejectsMCPAuthenticationErrorsBeforeConstruction(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		opts    ServerOpts
		wantErr string
	}{
		{
			name: "authentication flag without listener",
			opts: ServerOpts{
				MCPAllowUnauthenticated: true,
			},
			wantErr: "MCP listener authentication flags require --mcp-listen",
		},
		{
			name: "malformed allowed origin",
			opts: ServerOpts{
				MCPListen:         "127.0.0.1:0",
				MCPUpstream:       "http://127.0.0.1:1",
				MCPAllowedOrigins: []string{"https://console.vendor.example/path"},
			},
			wantErr: "invalid MCP listener allowed origin",
		},
		{
			name: "unreadable token file",
			opts: ServerOpts{
				MCPListen:        "127.0.0.1:0",
				MCPUpstream:      "http://127.0.0.1:1",
				MCPAuthTokenFile: filepath.Join(t.TempDir(), "missing-token"),
			},
			wantErr: "reading MCP listener auth token",
		},
		{
			name: "malformed listener address",
			opts: ServerOpts{
				MCPListen:   "not-an-address",
				MCPUpstream: "http://127.0.0.1:1",
			},
			wantErr: "invalid MCP listener address",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := NewServer(tt.opts)
			if err == nil {
				t.Fatalf("NewServer(%+v) returned nil error", tt.opts)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("NewServer error = %q, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestMCPCommandsRejectMalformedInputBeforeTransportStartup(t *testing.T) {
	t.Parallel()

	missingConfig := filepath.Join(t.TempDir(), "missing.yaml")
	tests := []struct {
		name    string
		args    []string
		stdin   string
		wantErr string
	}{
		{
			name:    "scan missing config",
			args:    []string{"scan", "--config", missingConfig},
			wantErr: missingConfig,
		},
		{
			name:    "proxy missing config",
			args:    []string{"proxy", "--config", missingConfig, "--", "unreachable-child"},
			wantErr: missingConfig,
		},
		{
			name:    "proxy malformed listener address",
			args:    []string{"proxy", "--listen", "not-an-address", "--upstream", "http://127.0.0.1:1"},
			wantErr: "invalid MCP listener address",
		},
		{
			name:    "proxy malformed allowed origin",
			args:    []string{"proxy", "--listen", "127.0.0.1:0", "--upstream", "http://127.0.0.1:1", "--listener-allowed-origin", "null"},
			wantErr: "invalid MCP listener allowed origin",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cmd := McpCmd()
			cmd.SetIn(strings.NewReader(tt.stdin))
			cmd.SetOut(&bytes.Buffer{})
			cmd.SetErr(&bytes.Buffer{})
			cmd.SetArgs(tt.args)

			err := cmd.Execute()
			if err == nil {
				t.Fatalf("Execute(%v) returned nil error", tt.args)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Execute(%v) error = %q, want substring %q", tt.args, err, tt.wantErr)
			}
		})
	}
}

type failingRuntimeInput struct{}

func (failingRuntimeInput) Read([]byte) (int, error) {
	return 0, errors.New("forced input read failure")
}

func TestMCPScanPropagatesInputReadFailure(t *testing.T) {
	t.Parallel()

	cmd := McpCmd()
	cmd.SetIn(failingRuntimeInput{})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"scan"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("Execute(scan) returned nil error after input read failure")
	}
	if !strings.Contains(err.Error(), "reading input: forced input read failure") {
		t.Fatalf("Execute(scan) error = %q, want wrapped input read failure", err)
	}
}

func TestReadHeaderFileRejectsNonRegularInput(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil { // #nosec G302 -- directory fixture requires execute permission.
		t.Fatalf("Chmod(%s): %v", dir, err)
	}

	_, err := readHeaderFile(dir)
	if err == nil {
		t.Fatal("readHeaderFile(directory) returned nil error")
	}
	if !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("readHeaderFile(directory) error = %q, want non-regular-file refusal", err)
	}
}
