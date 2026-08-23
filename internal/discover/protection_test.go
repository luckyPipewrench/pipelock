// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"os"
	"testing"
)

func TestClassifyProtection(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	tests := []struct {
		name   string
		server MCPServer
		want   ProtectionStatus
	}{
		{
			name:   "current executable wrapped stdio",
			server: MCPServer{Command: self, Args: []string{wrapperArgMCP, wrapperArgProxy, flagConfig, "local.yaml", "--", testCmdNode, testServerJS}},
			want:   ProtectedPipelock,
		},
		{
			name:   "bare name is not identity proof",
			server: MCPServer{Command: wrapperCommand, Args: []string{wrapperArgMCP, wrapperArgProxy, "--", "uvx", "some-server"}},
			want:   Unprotected,
		},
		{
			name:   "unexpanded path is not identity proof",
			server: MCPServer{Command: "~/.local/bin/pipelock", Args: []string{wrapperArgMCP, wrapperArgProxy, "--", testCmdNode, "s.js"}},
			want:   Unprotected,
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
			name:   "foreign windows path is not identity proof",
			server: MCPServer{Command: `C:\Program Files\pipelock.exe`, Args: []string{wrapperArgMCP, wrapperArgProxy, "--", testCmdNode, "s.js"}},
			want:   Unprotected,
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
		server MCPServer
		want   string
	}{
		{MCPServer{Protection: ProtectedPipelock}, "command is this pipelock executable and args begin mcp proxy"},
		{MCPServer{Protection: ProtectedOther}, "wrapped by recognized security proxy"},
		{MCPServer{Protection: Unknown}, "no command or url configured"},
		{MCPServer{Protection: Unprotected}, "no proxy wrapper detected"},
		{MCPServer{Protection: Unprotected, Command: "/opt/other/pipelock", Args: []string{"mcp", "proxy"}}, "mcp proxy wrapper found, but its executable identity is unconfirmed"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := protectionEvidence(tt.server)
			if got != tt.want {
				t.Errorf("protectionEvidence() = %q, want %q", got, tt.want)
			}
		})
	}
}
