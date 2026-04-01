// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package chains implements MCP tool call chain pattern detection.
// It classifies tool names into categories and detects attack patterns
// in sequences of tool calls using subsequence matching.
package chains

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// categoryKeywords maps tool categories to keywords that appear in tool names.
// Used as fallback classification when no config override matches.
var categoryKeywords = map[string][]string{
	"read":          {"read", "get", "view", "cat", "head", "tail", "open", "load", "retrieve", "access"},
	"write":         {"write", "create", "save", "update", "edit", "modify", "put", "append", "insert"},
	"exec":          {"shell", "bash", "run", "execute", "cmd", "spawn", "eval", "sh", "zsh", "powershell"},
	"network":       {"fetch", "curl", "wget", "http", "request", "send", "post", "upload", "download", "api"},
	"list":          {"list", "ls", "dir", "find", "glob", "search", "scan", "enumerate", "walk"},
	"env":           {"env", "environ", "getenv", "secret", "credential", "config", "token", "key", "password"},
	categoryPersist: {"crontab", "cron", "systemctl", "systemd", "launchd", "launchctl", "autostart"},
}

// categoryUnknown is returned when a tool name does not match any category.
const categoryUnknown = "unknown"

// categoryPersist is the classification for persistence operations.
const categoryPersist = "persist"

// categoryPriority defines the priority order for keyword matching.
// Higher priority categories win when a tool name matches multiple categories.
// exec > persist > env > network > write > read > list.
var categoryPriority = []string{"exec", categoryPersist, "env", "network", "write", "read", "list"}

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

// readIndicatorSegments are tool name segments indicating read-only operations.
// When a tool matches "persist" by keyword but also has a read indicator segment,
// the persist match is skipped to avoid false positives (e.g., "systemd_status"
// or "launchctl_list" should classify as read/list, not persist).
var readIndicatorSegments = map[string]bool{
	"status": true, "list": true, "show": true, "info": true,
	"describe": true, "get": true, "view": true, "check": true,
	"inspect": true, "cat": true, "log": true, "logs": true,
	"read": true, "query": true, "monitor": true,
}

// hasReadIndicator returns true if any segment is a read-only indicator.
func hasReadIndicator(segments []string) bool {
	for _, seg := range segments {
		if readIndicatorSegments[strings.ToLower(seg)] {
			return true
		}
	}
	return false
}

// matchByPriority matches segments against the keyword table using priority order.
// Returns the highest-priority category that matches, or "unknown".
//
// Special case: if a tool matches "persist" by keyword but also contains a
// read-indicator segment (status, list, get, etc.), the persist classification
// is skipped. This prevents read-only tools like "systemd_status" or
// "launchctl_list" from being classified as persistence operations.
func matchByPriority(segments []string) string {
	for _, category := range categoryPriority {
		keywords := categoryKeywords[category]
		for _, seg := range segments {
			lower := strings.ToLower(seg)
			for _, kw := range keywords {
				if lower == kw {
					if category == categoryPersist && hasReadIndicator(segments) {
						break // skip persist, try lower-priority categories
					}
					return category
				}
			}
		}
	}
	return categoryUnknown
}

// persistArgPattern matches persistence commands in tool arguments.
// Used to reclassify "exec" tools (bash, shell) as "persist" when
// the arguments contain persistence-related commands.
//
// Only matches explicit persistence commands (crontab -e, systemctl enable,
// launchctl load). Bare persistence path matches (/etc/cron.d/) are
// intentionally excluded because they false-positive on read-only commands
// like "cat /etc/cron.d/backup". Path-based write detection is handled
// separately by MCP tool policy rules ("Persistence Path Write via Command").
var persistArgPattern = regexp.MustCompile(
	`(?i)(\bcrontab\s+(-\w+\s+\S+\s+)*-e\b|\bcrontab\s+(-\w+\s+\S+\s+)*[^-\s]|\|\s*crontab\b|\bsystemctl\s+(-{1,2}\w+\s+)*(enable|daemon-reload)\b|\blaunchctl\s+(load|enable)\b)`,
)

// persistWritePathPattern matches persistence-related file paths in tool
// arguments. Used to reclassify "write" tools as "persist" when arguments
// target crontab, systemd unit, or launchd plist paths. Safe for "write"
// category because write + persist-path = persistence by definition.
// NOT used for "exec" category (those use persistArgPattern instead)
// because "exec" + path could be read-only (e.g., "cat /etc/cron.d/backup").
var persistWritePathPattern = regexp.MustCompile(
	`(?i)(/var/spool/cron|/etc/cron\b|/etc/cron\.d/|/etc/crontab\b|/etc/systemd/|/lib/systemd/|\.config/systemd/user/|/etc/init\.d/|/Library/LaunchDaemons/|/Library/LaunchAgents/|~/Library/LaunchAgents/)`,
)

// reclassifyByArgs upgrades tool classification to "persist" when
// the tool's arguments indicate persistence activity:
//   - "exec" tools: matches explicit commands (crontab -e, systemctl enable)
//   - "write" tools: matches persistence file paths (crontab, systemd, launchd)
func reclassifyByArgs(category, argHint string) string {
	if argHint == "" {
		return category
	}
	switch category {
	case "exec":
		if persistArgPattern.MatchString(argHint) {
			return categoryPersist
		}
	case "write":
		if persistWritePathPattern.MatchString(argHint) {
			return categoryPersist
		}
	}
	return category
}
