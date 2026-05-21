// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package discover

import "testing"

func TestClassifyRisk(t *testing.T) {
	tests := []struct {
		name     string
		server   MCPServer
		wantRisk RiskLevel
	}{
		{
			name:     "filesystem server",
			server:   MCPServer{ServerName: kwFilesystem, Command: testCmdNpx, Args: []string{"-y", testServerFilesystemPkg}, Protection: Unprotected},
			wantRisk: RiskHigh,
		},
		{
			name:     "postgres server",
			server:   MCPServer{ServerName: "postgres", Command: testCmdNpx, Args: []string{"-y", "@modelcontextprotocol/server-postgres"}, Protection: Unprotected},
			wantRisk: RiskHigh,
		},
		{
			name:     "shell server",
			server:   MCPServer{ServerName: "shell", Command: testCmdNode, Args: []string{"shell-server.js"}, Protection: Unprotected},
			wantRisk: RiskHigh,
		},
		{
			name:     "slack server",
			server:   MCPServer{ServerName: "slack", Command: testCmdNpx, Args: []string{"-y", "@modelcontextprotocol/server-slack"}, Protection: Unprotected},
			wantRisk: RiskHigh,
		},
		{
			name:     "everything server",
			server:   MCPServer{ServerName: "everything", Command: testCmdNpx, Args: []string{"-y", "@modelcontextprotocol/server-everything"}, Protection: Unprotected},
			wantRisk: RiskHigh,
		},
		{
			name:     "browser server via playwright",
			server:   MCPServer{ServerName: "browser", Command: testCmdNpx, Args: []string{"-y", "@playwright/mcp-server"}, Protection: Unprotected},
			wantRisk: RiskHigh,
		},
		{
			name:     "memory server",
			server:   MCPServer{ServerName: "memory", Command: testCmdNpx, Args: []string{"-y", "@modelcontextprotocol/server-memory"}, Protection: Unprotected},
			wantRisk: RiskMedium,
		},
		{
			name:     "brave search server",
			server:   MCPServer{ServerName: "brave-search", Command: testCmdNpx, Args: []string{"-y", "@modelcontextprotocol/server-brave-search"}, Protection: Unprotected},
			wantRisk: RiskMedium,
		},
		{
			name:     "unknown unprotected server",
			server:   MCPServer{ServerName: "custom-tool", Command: "my-tool", Protection: Unprotected},
			wantRisk: RiskMedium,
		},
		{
			name:     "protected pipelock gets low risk",
			server:   MCPServer{ServerName: kwFilesystem, Command: wrapperCommand, Args: []string{wrapperArgMCP, wrapperArgProxy}, Protection: ProtectedPipelock},
			wantRisk: RiskLow,
		},
		{
			name:     "protected other gets low risk",
			server:   MCPServer{ServerName: "postgres", Command: "runlayer", Args: []string{"wrap"}, Protection: ProtectedOther},
			wantRisk: RiskLow,
		},
		{
			name:     "unknown protection gets low risk",
			server:   MCPServer{ServerName: "custom", Protection: Unknown},
			wantRisk: RiskLow,
		},
		{
			name:     "git server",
			server:   MCPServer{ServerName: "git-ops", Command: testCmdNpx, Args: []string{"-y", "mcp-server-git"}, Protection: Unprotected},
			wantRisk: RiskHigh,
		},
		{
			name:     "trunk does not match run",
			server:   MCPServer{ServerName: "trunk", Command: "trunk-server", Protection: Unprotected},
			wantRisk: RiskMedium,
		},
		{
			name:     "debugger does not match db",
			server:   MCPServer{ServerName: "debugger", Command: "debug-tool", Protection: Unprotected},
			wantRisk: RiskMedium,
		},
		{
			name:     "hyphenated fs still matches",
			server:   MCPServer{ServerName: "my-fs-server", Command: testCmdNode, Protection: Unprotected},
			wantRisk: RiskHigh,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			risk, reason := classifyRisk(tt.server)
			if risk != tt.wantRisk {
				t.Errorf("risk = %q, want %q (reason: %s)", risk, tt.wantRisk, reason)
			}
		})
	}
}

func TestClassifyRiskReturnsReason(t *testing.T) {
	risk, reason := classifyRisk(MCPServer{
		ServerName: kwFilesystem,
		Command:    testCmdNpx,
		Protection: Unprotected,
	})
	if risk != RiskHigh {
		t.Errorf("risk = %q, want high", risk)
	}
	if reason == "" {
		t.Error("expected non-empty reason")
	}
}
