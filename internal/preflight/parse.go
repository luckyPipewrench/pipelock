// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package preflight

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/projectscan"
)

// claudeSettings represents Claude Code .claude/settings.json.
type claudeSettings struct {
	Hooks                      map[string][]hookGroup     `json:"hooks"`
	Env                        map[string]json.RawMessage `json:"env"`
	EnableAllProjectMcpServers bool                       `json:"enableAllProjectMcpServers"`
	EnabledMcpServers          []string                   `json:"enabledMcpServers"`
	Permissions                *claudePermissions         `json:"permissions"`
	StatusLine                 *statusLineEntry           `json:"statusLine"`
}

type hookGroup struct {
	Matcher string    `json:"matcher"`
	Hooks   []hookDef `json:"hooks"`
}

type hookDef struct {
	Type    string `json:"type"`
	Command string `json:"command"`
}

type statusLineEntry struct {
	Type    string `json:"type"`
	Command string `json:"command"`
}

type claudePermissions struct {
	Allow []string `json:"allow"`
	Deny  []string `json:"deny"`
}

// mcpJSON represents .mcp.json and .cursor/mcp.json.
type mcpJSON struct {
	MCPServers map[string]mcpServerDef `json:"mcpServers"`
}

type mcpServerDef struct {
	Command string                     `json:"command"`
	Args    []string                   `json:"args"`
	Type    string                     `json:"type"`
	Env     map[string]json.RawMessage `json:"env"`
	URL     string                     `json:"url"`
}

// cursorHooksJSON represents .cursor/hooks.json (v1 format: hooks keyed by event name).
type cursorHooksJSON struct {
	Version int                          `json:"version"`
	Hooks   map[string][]cursorHookEntry `json:"hooks"`
}

// cursorHooksLegacyJSON represents the pre-v0.3.4 hooks.json format
// where hooks was a flat array with an "event" field per entry.
type cursorHooksLegacyJSON struct {
	Hooks []cursorHookLegacyEntry `json:"hooks"`
}

type cursorHookLegacyEntry struct {
	Event   string   `json:"event"`
	Command string   `json:"command"`
	Args    []string `json:"args"`
	Timeout int      `json:"timeout"`
}

type cursorHookEntry struct {
	Command string   `json:"command"`
	Args    []string `json:"args"`
	Timeout int      `json:"timeout"`
}

// parseClaudeSettings scans a Claude Code settings.json file.
func parseClaudeSettings(data []byte, filePath string) []projectscan.Finding {
	var settings claudeSettings
	if err := json.Unmarshal(data, &settings); err != nil {
		// Fail-closed: malformed config = critical finding
		return []projectscan.Finding{{
			Severity: SevCritical,
			Category: CatConfig,
			Message:  fmt.Sprintf("malformed JSON prevents security analysis: %s: %s", filePath, err),
			File:     filePath,
		}}
	}

	var findings []projectscan.Finding

	// Scan hooks (Class A)
	for eventName, groups := range settings.Hooks {
		for _, g := range groups {
			for _, h := range g.Hooks {
				findings = append(findings, checkHookCommand(h.Command, filePath, fmt.Sprintf("hook[%s]", eventName))...)
			}
		}
	}

	// Scan statusLine (Class A)
	if settings.StatusLine != nil {
		findings = append(findings, checkHookCommand(settings.StatusLine.Command, filePath, "statusLine")...)
	}

	// Scan env vars (Class C)
	findings = append(findings, checkEnvVarsRaw(settings.Env, filePath, "settings env")...)

	// Scan auto-approval (Class D)
	findings = append(findings, checkAutoApproval(data, filePath)...)

	return findings
}

// parseMCPJSON scans a .mcp.json or .cursor/mcp.json file.
func parseMCPJSON(data []byte, filePath string) []projectscan.Finding {
	var mcp mcpJSON
	if err := json.Unmarshal(data, &mcp); err != nil {
		return []projectscan.Finding{{
			Severity: SevCritical,
			Category: CatConfig,
			Message:  fmt.Sprintf("malformed JSON prevents security analysis: %s: %s", filePath, err),
			File:     filePath,
		}}
	}

	var findings []projectscan.Finding

	// Info: list servers found (sorted for deterministic output)
	if len(mcp.MCPServers) > 0 {
		names := sortedKeys(mcp.MCPServers)
		findings = append(findings, projectscan.Finding{
			Severity: SevInfo,
			Category: CatConfig,
			Message:  fmt.Sprintf("found %d MCP server(s): %s", len(names), strings.Join(names, ", ")),
			File:     filePath,
		})
	}

	// Scan each server in sorted order (Classes B, C, E)
	for _, name := range sortedKeys(mcp.MCPServers) {
		server := mcp.MCPServers[name]
		findings = append(findings, checkMCPServer(name, server, filePath)...)
	}

	return findings
}

// parseCursorHooks scans a .cursor/hooks.json file. Supports both the v1
// format (hooks as a map keyed by event name) and the legacy format (flat
// array with an "event" field per entry).
func parseCursorHooks(data []byte, filePath string) []projectscan.Finding {
	// Try v1 format first (map-based).
	var hooks cursorHooksJSON
	if err := json.Unmarshal(data, &hooks); err == nil && hooks.Hooks != nil {
		var findings []projectscan.Finding
		for event, entries := range hooks.Hooks {
			for _, h := range entries {
				cmd := h.Command
				if len(h.Args) > 0 {
					cmd += " " + strings.Join(h.Args, " ")
				}
				findings = append(findings, checkHookCommand(cmd, filePath, fmt.Sprintf("cursor hook[%s]", event))...)
			}
		}
		return findings
	}

	// Try legacy format (flat array).
	var legacy cursorHooksLegacyJSON
	if err := json.Unmarshal(data, &legacy); err != nil {
		return []projectscan.Finding{{
			Severity: SevCritical,
			Category: CatConfig,
			Message:  fmt.Sprintf("malformed JSON prevents security analysis: %s: %s", filePath, err),
			File:     filePath,
		}}
	}

	var findings []projectscan.Finding
	for _, h := range legacy.Hooks {
		cmd := h.Command
		if len(h.Args) > 0 {
			cmd += " " + strings.Join(h.Args, " ")
		}
		findings = append(findings, checkHookCommand(cmd, filePath, fmt.Sprintf("cursor hook[%s]", h.Event))...)
	}

	return findings
}
