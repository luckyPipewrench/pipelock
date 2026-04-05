// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import "net/http"

// ClassifyHTTP infers an action type from an HTTP method.
// GET/HEAD/OPTIONS → read, POST/PUT/PATCH/DELETE → write.
// Unknown methods are classified as unclassified (high-risk by definition).
func ClassifyHTTP(method string) ActionType {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return ActionRead
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return ActionWrite
	case http.MethodTrace:
		return ActionRead
	case http.MethodConnect:
		// CONNECT establishes a tunnel — classified as read because
		// the tunnel itself doesn't mutate; the tunneled requests do.
		return ActionRead
	default:
		return ActionUnclassified
	}
}

// SideEffectFromMethod infers a side-effect class from an HTTP method.
func SideEffectFromMethod(method string) SideEffectClass {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace, http.MethodConnect:
		return SideEffectExternalRead
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return SideEffectExternalWrite
	default:
		return SideEffectNone
	}
}

// ReversibilityFromMethod infers reversibility from an HTTP method.
// DELETE is irreversible; POST/PUT/PATCH are compensatable; reads are fully reversible.
func ReversibilityFromMethod(method string) Reversibility {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace, http.MethodConnect:
		return ReversibilityFull
	case http.MethodDelete:
		return ReversibilityIrreversible
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		return ReversibilityCompensatable
	default:
		return ReversibilityUnknown
	}
}

// ClassifyMCPTool infers an action type from an MCP tool name and method.
// This is best-effort based on naming conventions. Returns unclassified
// for tools that can't be categorized from name alone.
func ClassifyMCPTool(toolName, mcpMethod string) ActionType {
	// tools/list is a read operation — listing available tools
	if mcpMethod == "tools/list" || mcpMethod == "resources/list" || mcpMethod == "prompts/list" {
		return ActionRead
	}
	// resources/read is always a read
	if mcpMethod == "resources/read" {
		return ActionRead
	}
	// prompts/get is a read
	if mcpMethod == "prompts/get" {
		return ActionRead
	}

	// tools/call — infer from tool name patterns
	if mcpMethod == "tools/call" {
		return classifyToolName(toolName)
	}

	return ActionUnclassified
}

// classifyToolName attempts to classify an MCP tool call by name.
// Uses common prefixes/keywords. Defaults to unclassified for unknown tools.
func classifyToolName(name string) ActionType {
	if name == "" {
		return ActionUnclassified
	}

	// Check for common read-like prefixes
	readPrefixes := []string{"get", "list", "read", "search", "find", "query", "fetch", "show", "describe", "check"}
	for _, prefix := range readPrefixes {
		if hasPrefix(name, prefix) {
			return ActionRead
		}
	}

	// Check for common write-like prefixes
	writePrefixes := []string{"set", "create", "update", "delete", "remove", "write", "put", "post", "add", "modify", "edit", "patch"}
	for _, prefix := range writePrefixes {
		if hasPrefix(name, prefix) {
			return ActionWrite
		}
	}

	// Check for execution/delegation patterns
	execPrefixes := []string{"run", "exec", "execute", "spawn", "invoke", "call"}
	for _, prefix := range execPrefixes {
		if hasPrefix(name, prefix) {
			return ActionDelegate
		}
	}

	return ActionUnclassified
}

// hasPrefix checks if name starts with prefix followed by a separator
// (underscore, hyphen, or uppercase letter for camelCase).
func hasPrefix(name, prefix string) bool {
	if len(name) < len(prefix) {
		return false
	}

	// Case-insensitive prefix match
	for i := range prefix {
		nc := name[i]
		pc := prefix[i]
		if nc != pc && toLowerASCII(nc) != toLowerASCII(pc) {
			return false
		}
	}

	// Must be exact match or followed by a separator
	if len(name) == len(prefix) {
		return true
	}

	next := name[len(prefix)]
	return next == '_' || next == '-' || (next >= 'A' && next <= 'Z')
}

func toLowerASCII(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}
