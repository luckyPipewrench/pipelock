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
// Tries exact match first, then glob patterns. Uses categoryPriority order
// so overlapping overrides are deterministic.
func classifyByOverride(toolName string, categories map[string][]string) string {
	return matchOverrideWithPriority(toolName, categoryPriority, categories)
}

// matchOverrideWithPriority returns the first label whose pattern list matches
// toolName, walked in priority order with an exact-match pass before a glob
// pass. Shared between category (classifyByOverride) and sensitivity
// (classifySensitivityByOverride) so the two axes can't drift apart.
func matchOverrideWithPriority(toolName string, priority []string, labels map[string][]string) string {
	if len(labels) == 0 {
		return ""
	}

	// Exact match first, walked in priority order.
	for _, label := range priority {
		for _, pat := range labels[label] {
			if pat == toolName {
				return label
			}
		}
	}

	// Glob match second, walked in priority order.
	for _, label := range priority {
		for _, pat := range labels[label] {
			if matched, _ := filepath.Match(pat, toolName); matched {
				return label
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

// ClassifyTool returns the best-effort category for a tool name and arguments.
// Nil cfg uses the built-in keyword classifier with no overrides.
func ClassifyTool(toolName, argHint string, cfg *config.ToolChainDetection) string {
	if cfg == nil {
		cfg = &config.ToolChainDetection{}
	}
	return reclassifyByArgs(classifyTool(toolName, cfg), argHint)
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

// Sensitivity label constants. These run orthogonally to category: a tool
// has a category (read/write/exec/network/list/env/persist) AND a sensitivity
// label (untrusted source / sensitive source / external sink / neutral).
//
// Lethal-trifecta attack pattern: untrusted-source -> sensitive-source ->
// external-sink within one session. Three independent sources flag this
// shape: Invariantlabs GitHub MCP, parasitic toolchain (arXiv 2509.06572),
// and Toxic Flow Analysis. Pipelock detects it via subsequence matching
// on the sensitivity axis rather than the category axis.
const (
	SensitivityUntrustedSource = "untrusted_source"
	SensitivitySensitiveSource = "sensitive_source"
	SensitivityExternalSink    = "external_sink"
	SensitivityNeutral         = "neutral"
)

// sensitivityKeywords maps sensitivity labels to keywords that appear as
// segments in tool names. Used as fallback classification when no config
// override matches. Operator overrides take precedence.
//
// untrusted_source: pulls content from where attackers can inject (external
// data, user-controlled inputs, third-party APIs, public registries).
// sensitive_source: pulls private/sensitive data (secrets, credentials,
// private repos, internal systems, personal messages).
// external_sink: sends data to a destination outside the trust boundary
// (public PR creation, message send, external webhook, file upload).
//
// Segments are matched after splitToolName, so plurals and variants must
// be enumerated explicitly. Multi-segment shapes (e.g. "create_pull_request",
// "post_webhook") are handled by sensitivitySubstrings, not this map.
var sensitivityKeywords = map[string][]string{
	SensitivityUntrustedSource: {
		"issue", "issues", "comment", "comments", "review", "reviews",
		"webpage", "scrape", "browse",
		"chat", "chats", "message", "messages", "messaging", "dm", "dms",
		"email", "emails", "inbox", "ticket", "tickets", "feedback",
		"public", "external", "rss", "feed", "feeds",
	},
	SensitivitySensitiveSource: {
		"secret", "secrets", "credential", "credentials",
		"token", "tokens", "password", "passwords",
		"private", "ssh", "vault",
		"env", "environ", "getenv",
		"profile", "billing", "payroll", "salary", "wage",
		"phi", "pii", "patient", "ssn",
	},
	SensitivityExternalSink: {
		"send", "post", "publish", "upload", "share",
		"webhook", "notify", "alert", "tweet",
		"broadcast", "announce",
	},
}

// sensitivitySubstrings supplements segment matching with multi-segment
// shapes that don't reduce to a single keyword. Each entry is checked
// against the FULL lowercased tool name via strings.Contains, so
// "create_pull_request" hits "pull_request" and "create_issue" hits
// "create_issue". Keep this list tight: ambiguous matches go in
// sensitivityKeywords instead.
var sensitivitySubstrings = map[string][]string{
	SensitivityUntrustedSource: {
		"pull_request_review", "issue_comment", "pr_comment",
	},
	SensitivitySensitiveSource: {
		"private_repo", "private_repos", "private_repository",
		"ssh_key", "ssh_id_rsa", "api_key",
		"chat_history", "message_history", "conversation_history",
	},
	SensitivityExternalSink: {
		"pull_request", "create_pull", "create_issue", "create_comment",
		"post_webhook", "send_webhook", "share_link", "public_url",
	},
}

// sensitivityPriority defines tie-breaking when a tool name matches multiple
// labels. external_sink > sensitive_source > untrusted_source > neutral.
// Sinks rank highest because that's the action that completes the trifecta;
// sensitive_source ranks above untrusted_source because true positives in
// the sensitive class are higher-stakes than untrusted-input false positives.
var sensitivityPriority = []string{
	SensitivityExternalSink,
	SensitivitySensitiveSource,
	SensitivityUntrustedSource,
}

// ClassifySensitivity returns the sensitivity label for a tool name +
// optional argument hint. Nil cfg uses keyword-only classification.
//
// Resolution order:
//  1. Config override exact match (highest priority)
//  2. Config override glob match
//  3. Built-in keyword match against tool-name segments using sensitivityPriority
//  4. Built-in substring match against full lowercased tool name (handles
//     multi-segment shapes like "create_pull_request")
//  5. Fallback: neutral
//
// argHint is reserved for future arg-based refinement (e.g., a generic
// "http_request" tool becomes external_sink when args include POST verb).
// Currently unused but accepted to keep the API stable.
func ClassifySensitivity(toolName, argHint string, cfg *config.ToolChainDetection) string {
	_ = argHint
	if toolName == "" {
		return SensitivityNeutral
	}
	if cfg == nil {
		cfg = &config.ToolChainDetection{}
	}

	if lbl := classifySensitivityByOverride(toolName, cfg.SensitivityLabels); lbl != "" {
		return lbl
	}

	segments := splitToolName(toolName)
	if lbl := matchSensitivityByPriority(segments); lbl != SensitivityNeutral {
		return lbl
	}

	// Substring pass for multi-segment shapes.
	// Normalize delimiters (-, ., __, etc.) to underscores so needles like
	// "pull_request" match tool names shaped "create-pull-request" or
	// "create.pull.request". Without this, only delimiter-equivalent forms
	// match and multi-segment needles silently miss.
	lower := strings.ToLower(strings.Join(splitToolName(toolName), "_"))
	for _, label := range sensitivityPriority {
		for _, needle := range sensitivitySubstrings[label] {
			if strings.Contains(lower, needle) {
				return label
			}
		}
	}

	return SensitivityNeutral
}

// classifySensitivityByOverride checks config-defined sensitivity overrides.
// Mirrors classifyByOverride on the category axis (exact match first, then
// glob, in priority order). The two share matchOverrideWithPriority so
// behavioral changes can't drift between axes.
func classifySensitivityByOverride(toolName string, labels map[string][]string) string {
	return matchOverrideWithPriority(toolName, sensitivityPriority, labels)
}

// matchSensitivityByPriority walks segments against the sensitivity keyword
// table using priority order. Returns the highest-priority label that matches,
// or "neutral".
func matchSensitivityByPriority(segments []string) string {
	for _, label := range sensitivityPriority {
		keywords := sensitivityKeywords[label]
		for _, seg := range segments {
			lower := strings.ToLower(seg)
			for _, kw := range keywords {
				if lower == kw {
					return label
				}
			}
		}
	}
	return SensitivityNeutral
}
