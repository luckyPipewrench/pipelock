// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp"
)

const (
	testMCPServerName       = "code-assistant"
	testMCPResponseSuppress = "mcp://code-assistant/response"
)

func TestApplyMCPResponseSuppressOpts(t *testing.T) {
	cfg := config.Defaults()
	cfg.Suppress = []config.SuppressEntry{
		{
			Rule:   "Credential Solicitation",
			Path:   testMCPResponseSuppress,
			Reason: "false positive on first-party server code-assistant",
		},
	}
	opts := mcp.MCPProxyOpts{}

	applyMCPResponseSuppressOpts(&opts, cfg, testMCPServerName)

	if opts.ServerName != testMCPServerName {
		t.Fatalf("ServerName = %q, want %s", opts.ServerName, testMCPServerName)
	}
	if len(opts.Suppress) != 1 {
		t.Fatalf("Suppress entries = %d, want 1", len(opts.Suppress))
	}
	if opts.Suppress[0].Path != testMCPResponseSuppress {
		t.Fatalf("Suppress[0].Path = %q", opts.Suppress[0].Path)
	}
}

func TestApplyMCPResponseSuppressOpts_NilConfigKeepsExistingRules(t *testing.T) {
	opts := mcp.MCPProxyOpts{
		Suppress: []config.SuppressEntry{{Rule: "stale", Path: "mcp://stale/response"}},
	}

	applyMCPResponseSuppressOpts(&opts, nil, testMCPServerName)

	if opts.ServerName != testMCPServerName {
		t.Fatalf("ServerName = %q, want %s", opts.ServerName, testMCPServerName)
	}
	if len(opts.Suppress) != 1 {
		t.Fatalf("nil config must not rewrite existing suppress entries, got %d", len(opts.Suppress))
	}
}

func TestMCPProxyCmd_AdaptiveResetFileRejectedForUpstream(t *testing.T) {
	cmd := mcpProxyCmd()
	cmd.SetArgs([]string{
		"--upstream", "http://127.0.0.1:1/mcp",
		"--adaptive-reset-file", "/tmp/pipelock-reset",
	})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected --adaptive-reset-file with --upstream to fail")
	}
	if !strings.Contains(err.Error(), "--adaptive-reset-file is only supported with local subprocess MCP servers") {
		t.Fatalf("unexpected error: %v", err)
	}
}
