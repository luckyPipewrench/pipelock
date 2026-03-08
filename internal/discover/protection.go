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
// Handles Windows paths (pipelock.exe) and avoids false positives on names
// like "pipelock-helper" by stripping the extension and comparing exactly.
func isPipelockWrapped(s MCPServer) bool {
	base := commandBase(s.Command)
	name := strings.TrimSuffix(base, filepath.Ext(base))
	if !strings.EqualFold(name, "pipelock") {
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

// commandBase extracts the final path component from a command string,
// handling both forward slashes and backslashes. This is needed because
// JSON configs may contain Windows paths (e.g., C:\Program Files\pipelock.exe)
// that are read on Linux where filepath.Base only splits on forward slashes.
func commandBase(cmd string) string {
	// Use filepath.Base for the native separator, then also check for
	// the non-native separator in case the path uses the other convention.
	base := filepath.Base(cmd)
	if i := strings.LastIndexByte(base, '\\'); i >= 0 {
		base = base[i+1:]
	}
	return base
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
