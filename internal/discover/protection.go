// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"path/filepath"
	"strings"
)

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

// isPipelockWrapped checks if the server command is pipelock with mcp proxy args.
func isPipelockWrapped(s MCPServer) bool {
	base := filepath.Base(s.Command)
	if base != "pipelock" && !strings.Contains(s.Command, "/pipelock") {
		return false
	}

	hasMCP := false
	hasProxy := false
	for _, arg := range s.Args {
		switch arg {
		case "mcp":
			hasMCP = true
		case "proxy":
			hasProxy = true
		}
	}
	return hasMCP && hasProxy
}

// protectionEvidence returns a human-readable explanation for a protection classification.
func protectionEvidence(s MCPServer) string {
	switch s.Protection {
	case ProtectedPipelock:
		return "command=pipelock, args contain mcp+proxy"
	case ProtectedOther:
		return "wrapped by recognized security proxy"
	case Unknown:
		return "no command or url configured"
	default:
		return "no proxy wrapper detected"
	}
}
