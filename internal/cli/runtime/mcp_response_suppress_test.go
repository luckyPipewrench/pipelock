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
	if opts.ResponseTrustClass != config.ResponseTrustUntrusted || opts.ResponseActionOverride != config.ActionBlock {
		t.Fatalf("default trust/action = %q/%q, want untrusted/block", opts.ResponseTrustClass, opts.ResponseActionOverride)
	}
	if opts.TaintTrustedSource {
		t.Fatal("default MCP server must not be taint-trusted")
	}
}

func TestApplyMCPResponseSuppressOpts_ReasoningTrustWarnsMatchingServer(t *testing.T) {
	cfg := config.Defaults()
	cfg.ResponseScanning.MCPServers = []config.MCPResponseServerTrust{
		{Server: testMCPServerName, Trust: config.ResponseTrustReasoning},
		{Server: "web-fetch", Trust: config.ResponseTrustUntrusted},
	}
	opts := mcp.MCPProxyOpts{}

	applyMCPResponseSuppressOpts(&opts, cfg, testMCPServerName)

	if opts.ResponseTrustClass != config.ResponseTrustReasoning {
		t.Fatalf("ResponseTrustClass = %q, want %q", opts.ResponseTrustClass, config.ResponseTrustReasoning)
	}
	if opts.ResponseActionOverride != config.ActionWarn {
		t.Fatalf("ResponseActionOverride = %q, want %q", opts.ResponseActionOverride, config.ActionWarn)
	}
}

func TestApplyMCPResponseSuppressOpts_TaintTrustedMatchingServer(t *testing.T) {
	cfg := config.Defaults()
	cfg.Taint.TrustedMCPServers = []string{testMCPServerName}
	opts := mcp.MCPProxyOpts{}

	applyMCPResponseSuppressOpts(&opts, cfg, testMCPServerName)

	if !opts.TaintTrustedSource {
		t.Fatal("expected matching server to be taint-trusted")
	}
}

func TestApplyMCPResponseSuppressOpts_MissingServerFailsClosed(t *testing.T) {
	cfg := config.Defaults()
	cfg.ResponseScanning.MCPServers = []config.MCPResponseServerTrust{
		{Server: "codex", Trust: config.ResponseTrustReasoning},
	}
	opts := mcp.MCPProxyOpts{}

	applyMCPResponseSuppressOpts(&opts, cfg, "web-fetch")

	if opts.ResponseTrustClass != config.ResponseTrustUntrusted || opts.ResponseActionOverride != config.ActionBlock {
		t.Fatalf("missing server trust/action = %q/%q, want untrusted/block", opts.ResponseTrustClass, opts.ResponseActionOverride)
	}
}

func TestMCPResponseLogFieldsShowsEffectivePosture(t *testing.T) {
	opts := mcp.MCPProxyOpts{}
	action, trust, server := mcpResponseLogFields(opts)
	if action != config.ActionBlock || trust != config.ResponseTrustUntrusted || server != "(unnamed)" {
		t.Fatalf("empty opts log fields = %q/%q/%q, want block/untrusted/(unnamed)", action, trust, server)
	}

	opts = mcp.MCPProxyOpts{
		ServerName:             testMCPServerName,
		ResponseTrustClass:     config.ResponseTrustReasoning,
		ResponseActionOverride: config.ActionWarn,
	}
	action, trust, server = mcpResponseLogFields(opts)
	if action != config.ActionWarn || trust != config.ResponseTrustReasoning || server != testMCPServerName {
		t.Fatalf("reasoning opts log fields = %q/%q/%q, want warn/reasoning/%s", action, trust, server, testMCPServerName)
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
