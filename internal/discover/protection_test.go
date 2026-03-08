// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package discover

import "testing"

func TestClassifyProtection(t *testing.T) {
	tests := []struct {
		name   string
		server MCPServer
		want   ProtectionStatus
	}{
		{
			name:   "pipelock wrapped stdio with full path",
			server: MCPServer{Command: "/home/user/.local/bin/pipelock", Args: []string{"mcp", "proxy", "--config", "local.yaml", "--", "node", "server.js"}},
			want:   ProtectedPipelock,
		},
		{
			name:   "pipelock bare command",
			server: MCPServer{Command: "pipelock", Args: []string{"mcp", "proxy", "--", "uvx", "some-server"}},
			want:   ProtectedPipelock,
		},
		{
			name:   "pipelock with tilde path",
			server: MCPServer{Command: "~/.local/bin/pipelock", Args: []string{"mcp", "proxy", "--", "node", "s.js"}},
			want:   ProtectedPipelock,
		},
		{
			name:   "pipelock command but no mcp arg",
			server: MCPServer{Command: "pipelock", Args: []string{"run", "--config", "config.yaml"}},
			want:   Unprotected,
		},
		{
			name:   "pipelock command but no proxy arg",
			server: MCPServer{Command: "pipelock", Args: []string{"mcp", "scan", "file.txt"}},
			want:   Unprotected,
		},
		{
			name:   "bare npx command",
			server: MCPServer{Command: "npx", Args: []string{"-y", "@modelcontextprotocol/server-filesystem"}},
			want:   Unprotected,
		},
		{
			name:   "http server",
			server: MCPServer{Transport: "http", URL: "https://api.example.com/mcp"},
			want:   Unprotected,
		},
		{
			name:   "empty server",
			server: MCPServer{},
			want:   Unknown,
		},
		{
			name:   "command only, no wrapper",
			server: MCPServer{Command: "node", Args: []string{"server.js"}},
			want:   Unprotected,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyProtection(tt.server)
			if got != tt.want {
				t.Errorf("classifyProtection() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestProtectionEvidence(t *testing.T) {
	tests := []struct {
		status ProtectionStatus
		want   string
	}{
		{ProtectedPipelock, "command=pipelock, args contain mcp+proxy"},
		{ProtectedOther, "wrapped by recognized security proxy"},
		{Unknown, "no command or url configured"},
		{Unprotected, "no proxy wrapper detected"},
	}
	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			s := MCPServer{Protection: tt.status}
			got := protectionEvidence(s)
			if got != tt.want {
				t.Errorf("protectionEvidence() = %q, want %q", got, tt.want)
			}
		})
	}
}
