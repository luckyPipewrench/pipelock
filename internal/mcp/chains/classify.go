// Package chains implements MCP tool call chain pattern detection.
// It classifies tool names into categories and detects attack patterns
// in sequences of tool calls using subsequence matching.
package chains

import (
	"path/filepath"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// categoryKeywords maps tool categories to keywords that appear in tool names.
// Used as fallback classification when no config override matches.
var categoryKeywords = map[string][]string{
	"read":    {"read", "get", "view", "cat", "head", "tail", "open", "load", "retrieve", "access"},
	"write":   {"write", "create", "save", "update", "edit", "modify", "put", "append", "insert"},
	"exec":    {"shell", "bash", "run", "execute", "cmd", "spawn", "eval", "sh", "zsh", "powershell"},
	"network": {"fetch", "curl", "wget", "http", "request", "send", "post", "upload", "download", "api"},
	"list":    {"list", "ls", "dir", "find", "glob", "search", "scan", "enumerate", "walk"},
	"env":     {"env", "environ", "getenv", "secret", "credential", "config", "token", "key", "password"},
}

// categoryUnknown is returned when a tool name does not match any category.
const categoryUnknown = "unknown"

// categoryPriority defines the priority order for keyword matching.
// Higher priority categories win when a tool name matches multiple categories.
// exec > env > network > write > read > list.
var categoryPriority = []string{"exec", "env", "network", "write", "read", "list"}

// toolNameDelimiters defines characters used to split tool names into segments.
var toolNameDelimiters = "_-."

// classifyTool determines the category of a tool based on its name.
// Returns "unknown" if no category matches.
//
// Classification logic:
//  1. Check config overrides first (exact match, then glob with filepath.Match)
//  2. Split tool name on delimiters (_-.) and double underscore (__)
//  3. Match segments against keyword table (first match by priority wins)
//  4. No match -> "unknown"
func classifyTool(toolName string, cfg *config.ToolChainDetection) string {
	if toolName == "" {
		return categoryUnknown
	}

	// Check config overrides first.
	if cat := classifyByOverride(toolName, cfg.ToolCategories); cat != "" {
		return cat
	}

	// Split tool name into segments.
	segments := splitToolName(toolName)

	// Match segments against keyword table using priority order.
	return matchByPriority(segments)
}

// classifyByOverride checks config-defined tool category overrides.
// Tries exact match first, then glob patterns.
// Uses categoryPriority order so overlapping overrides are deterministic.
func classifyByOverride(toolName string, categories map[string][]string) string {
	if len(categories) == 0 {
		return ""
	}

	// Check all categories for exact match first (priority order).
	for _, category := range categoryPriority {
		for _, pat := range categories[category] {
			if pat == toolName {
				return category
			}
		}
	}

	// Check all categories for glob match (priority order).
	for _, category := range categoryPriority {
		for _, pat := range categories[category] {
			if matched, _ := filepath.Match(pat, toolName); matched {
				return category
			}
		}
	}

	return ""
}

// splitToolName splits a tool name into segments on delimiters.
// Handles _, -, ., and __ (double underscore for MCP namespacing).
func splitToolName(name string) []string {
	// First replace __ with a single delimiter to handle MCP namespacing
	// (e.g., "mcp__filesystem__read_file" -> "mcp_filesystem_read_file")
	normalized := strings.ReplaceAll(name, "__", "_")

	// Split on all delimiter characters
	return strings.FieldsFunc(normalized, func(r rune) bool {
		return strings.ContainsRune(toolNameDelimiters, r)
	})
}

// matchByPriority matches segments against the keyword table using priority order.
// Returns the highest-priority category that matches, or "unknown".
func matchByPriority(segments []string) string {
	for _, category := range categoryPriority {
		keywords := categoryKeywords[category]
		for _, seg := range segments {
			lower := strings.ToLower(seg)
			for _, kw := range keywords {
				if lower == kw {
					return category
				}
			}
		}
	}
	return categoryUnknown
}
