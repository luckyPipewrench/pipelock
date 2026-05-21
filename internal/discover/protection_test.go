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
			server: MCPServer{Command: "/home/user/.local/bin/pipelock", Args: []string{wrapperArgMCP, wrapperArgProxy, flagConfig, "local.yaml", "--", testCmdNode, testServerJS}},
			want:   ProtectedPipelock,
		},
		{
			name:   "pipelock bare command",
			server: MCPServer{Command: wrapperCommand, Args: []string{wrapperArgMCP, wrapperArgProxy, "--", "uvx", "some-server"}},
			want:   ProtectedPipelock,
		},
		{
			name:   "pipelock with tilde path",
			server: MCPServer{Command: "~/.local/bin/pipelock", Args: []string{wrapperArgMCP, wrapperArgProxy, "--", testCmdNode, "s.js"}},
			want:   ProtectedPipelock,
		},
		{
			name:   "pipelock command but no mcp arg",
			server: MCPServer{Command: wrapperCommand, Args: []string{"run", flagConfig, "config.yaml"}},
			want:   Unprotected,
		},
		{
			name:   "pipelock command but no proxy arg",
			server: MCPServer{Command: wrapperCommand, Args: []string{wrapperArgMCP, "scan", "file.txt"}},
			want:   Unprotected,
		},
		{
			name:   "bare npx command",
			server: MCPServer{Command: testCmdNpx, Args: []string{"-y", testServerFilesystemPkg}},
			want:   Unprotected,
		},
		{
			name:   "http server",
			server: MCPServer{Transport: TransportHTTP, URL: testHTTPMCPURL},
			want:   Unprotected,
		},
		{
			name:   "empty server",
			server: MCPServer{},
			want:   Unknown,
		},
		{
			name:   "command only, no wrapper",
			server: MCPServer{Command: testCmdNode, Args: []string{testServerJS}},
			want:   Unprotected,
		},
		{
			name:   "windows exe path",
			server: MCPServer{Command: `C:\Program Files\pipelock.exe`, Args: []string{wrapperArgMCP, wrapperArgProxy, "--", testCmdNode, "s.js"}},
			want:   ProtectedPipelock,
		},
		{
			name:   "false positive pipelock-helper",
			server: MCPServer{Command: "/opt/pipelock-helper", Args: []string{wrapperArgMCP, wrapperArgProxy}},
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
