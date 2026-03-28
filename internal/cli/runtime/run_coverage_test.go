// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"testing"
)

// Tests for RunCmd flag validation paths. These exercise the early-return
// error paths without starting the proxy server.

func TestRunCmd_MCPListenWithoutUpstream(t *testing.T) {
	t.Parallel()
	cmd := RunCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--mcp-listen", "0.0.0.0:9999"})
	err := cmd.Execute()
	if err == nil {
		t.Error("expected error for --mcp-listen without --mcp-upstream")
	}
}

func TestRunCmd_MCPUpstreamWithoutListen(t *testing.T) {
	t.Parallel()
	cmd := RunCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--mcp-upstream", "http://localhost:3000/mcp"})
	err := cmd.Execute()
	if err == nil {
		t.Error("expected error for --mcp-upstream without --mcp-listen")
	}
}

func TestRunCmd_MCPUpstreamInvalidURL(t *testing.T) {
	t.Parallel()
	cmd := RunCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--mcp-listen", "0.0.0.0:9999", "--mcp-upstream", "not-a-url"})
	err := cmd.Execute()
	if err == nil {
		t.Error("expected error for invalid --mcp-upstream URL")
	}
}

func TestRunCmd_MCPUpstreamFTPScheme(t *testing.T) {
	t.Parallel()
	cmd := RunCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--mcp-listen", "0.0.0.0:9999", "--mcp-upstream", "ftp://localhost/mcp"})
	err := cmd.Execute()
	if err == nil {
		t.Error("expected error for ftp:// scheme in --mcp-upstream")
	}
}

func TestRunCmd_InvalidConfig(t *testing.T) {
	t.Parallel()
	cmd := RunCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--config", "/nonexistent/pipelock.yaml"})
	err := cmd.Execute()
	if err == nil {
		t.Error("expected error for nonexistent config file")
	}
}

func TestRunCmd_Help(t *testing.T) {
	t.Parallel()
	cmd := RunCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"--help"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("help failed: %v", err)
	}
	if buf.Len() == 0 {
		t.Error("expected help output")
	}
}
