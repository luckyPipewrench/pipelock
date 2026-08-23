// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package discover

import "github.com/luckyPipewrench/pipelock/internal/mcpwrap"

// classifyProtection determines if a server is wrapped by a security proxy.
func classifyProtection(s MCPServer) ProtectionStatus {
	if s.Command == "" && s.URL == "" {
		return Unknown
	}

	if isPipelockWrapped(s) {
		return ProtectedPipelock
	}

	// Future: check for other known proxy wrappers here.
	// For v1, anything not pipelock-wrapped with a command or URL is unprotected.
	return Unprotected
}

// isPipelockWrapped checks that the server invokes this executable with the
// exact MCP proxy subcommand prefix. A basename or config-authored marker is not
// evidence that Pipelock will mediate the traffic.
func isPipelockWrapped(s MCPServer) bool {
	return mcpwrap.ClassifyInvocation(s.Command, s.Args) == mcpwrap.WrapperSelf
}

// protectionEvidence returns a human-readable explanation for a protection classification.
func protectionEvidence(s MCPServer) string {
	switch s.Protection {
	case ProtectedPipelock:
		return "command is this pipelock executable and args begin mcp proxy"
	case ProtectedOther:
		return "wrapped by recognized security proxy"
	case Unknown:
		return "no command or url configured"
	default:
		if mcpwrap.ClassifyInvocation(s.Command, s.Args) == mcpwrap.WrapperForeign {
			return "mcp proxy wrapper found, but its executable identity is unconfirmed"
		}
		return evidenceNoProxy
	}
}
