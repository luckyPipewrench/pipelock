// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"os"
	"path/filepath"
	"sort"
)

// ProtectionStatus classifies how (or if) an MCP server is wrapped.
type ProtectionStatus string

const (
	ProtectedPipelock ProtectionStatus = "protected_pipelock"
	ProtectedOther    ProtectionStatus = "protected_other"
	Unprotected       ProtectionStatus = "unprotected"
	Unknown           ProtectionStatus = "unknown"
)

// RiskLevel for unprotected servers based on capability heuristics.
type RiskLevel string

const (
	RiskHigh   RiskLevel = "high"
	RiskMedium RiskLevel = "medium"
	RiskLow    RiskLevel = "low"
)

// Transport type constants.
const (
	TransportStdio   = "stdio"
	TransportHTTP    = "http"
	TransportUnknown = "unknown"
)

// MCPServer is a single discovered MCP server configuration.
type MCPServer struct {
	Client        string            `json:"client"`
	ConfigPath    string            `json:"config_path"`
	ProjectPath   string            `json:"project_path,omitempty"`
	ServerName    string            `json:"server_name"`
	Transport     string            `json:"transport"` // "stdio", "http", "sse", "unknown"
	Command       string            `json:"command"`
	Args          []string          `json:"args"`
	Env           map[string]string `json:"env,omitempty"`
	URL           string            `json:"url"`
	Protection    ProtectionStatus  `json:"protection_state"`
	Risk          RiskLevel         `json:"risk"`
	Evidence      string            `json:"evidence"`
	ParseWarnings []string          `json:"parse_warnings"`
}

// ClientConfig is one discovered agent client installation.
type ClientConfig struct {
	Client      string `json:"client"`
	ConfigPath  string `json:"config_path"`
	Scope       string `json:"scope"` // "user", "project"
	ServerCount int    `json:"server_count"`
	ParseError  string `json:"parse_error,omitempty"`
}

// Report is the full discovery result.
type Report struct {
	Clients []ClientConfig `json:"clients"`
	Servers []MCPServer    `json:"servers"`
	Summary Summary        `json:"summary"`
}

// Summary has aggregate counts.
type Summary struct {
	TotalClients      int `json:"total_clients"`
	TotalServers      int `json:"total_servers"`
	ProtectedPipelock int `json:"protected_pipelock"`
	ProtectedOther    int `json:"protected_other"`
	Unprotected       int `json:"unprotected"`
	Unknown           int `json:"unknown"`
	HighRisk          int `json:"high_risk"`
	ParseErrors       int `json:"parse_errors"`
}

// clientPath maps a client tool to its config file location.
type clientPath struct {
	Client string // "claude-code", "claude-desktop", "cursor", etc.
	Path   string // absolute path to config file
	Key    string // JSON key containing servers: "mcpServers" or "servers"
	Scope  string // "user" or "project"
}

// Discover scans the home directory for AI agent client configs and reports
// which MCP servers are configured, their protection status, and risk level.
func Discover(home string) (*Report, error) {
	paths := configPaths(home)

	var clients []ClientConfig
	var servers []MCPServer

	for _, cp := range paths {
		if !fileExists(cp.Path) {
			continue
		}

		var parsed []MCPServer
		var err error

		// Claude Code has nested per-project servers
		if cp.Client == "claude-code" {
			parsed, err = parseClaudeCodeConfig(cp.Path)
		} else {
			parsed, err = parseConfigFile(cp.Path, cp.Key, cp.Client)
		}

		if err != nil {
			// Non-fatal: record the client with a parse error so operators
			// know a config exists but could not be read.
			clients = append(clients, ClientConfig{
				Client:      cp.Client,
				ConfigPath:  cp.Path,
				Scope:       cp.Scope,
				ServerCount: 0,
				ParseError:  err.Error(),
			})
			continue
		}

		if len(parsed) > 0 {
			clients = append(clients, ClientConfig{
				Client:      cp.Client,
				ConfigPath:  cp.Path,
				Scope:       cp.Scope,
				ServerCount: len(parsed),
			})
		}

		// Classify each server
		for i := range parsed {
			parsed[i].Protection = classifyProtection(parsed[i])
			parsed[i].Evidence = protectionEvidence(parsed[i])
			risk, reason := classifyRisk(parsed[i])
			parsed[i].Risk = risk
			if parsed[i].Evidence == "no proxy wrapper detected" {
				parsed[i].Evidence = reason
			}
			if parsed[i].ParseWarnings == nil {
				parsed[i].ParseWarnings = []string{}
			}
		}

		servers = append(servers, parsed...)
	}

	// Deterministic sort: risk (high first), then client, config path, project path, server name.
	sort.SliceStable(servers, func(i, j int) bool {
		ri, rj := riskOrder(servers[i].Risk), riskOrder(servers[j].Risk)
		if ri != rj {
			return ri < rj
		}
		if servers[i].Client != servers[j].Client {
			return servers[i].Client < servers[j].Client
		}
		if servers[i].ConfigPath != servers[j].ConfigPath {
			return servers[i].ConfigPath < servers[j].ConfigPath
		}
		if servers[i].ProjectPath != servers[j].ProjectPath {
			return servers[i].ProjectPath < servers[j].ProjectPath
		}
		return servers[i].ServerName < servers[j].ServerName
	})

	summary := buildSummary(clients, servers)

	return &Report{
		Clients: clients,
		Servers: servers,
		Summary: summary,
	}, nil
}

func riskOrder(r RiskLevel) int {
	switch r {
	case RiskHigh:
		return 0
	case RiskMedium:
		return 1
	default:
		return 2
	}
}

func buildSummary(clients []ClientConfig, servers []MCPServer) Summary {
	s := Summary{
		TotalClients: len(clients),
		TotalServers: len(servers),
	}
	for _, c := range clients {
		if c.ParseError != "" {
			s.ParseErrors++
		}
	}
	for _, srv := range servers {
		switch srv.Protection {
		case ProtectedPipelock:
			s.ProtectedPipelock++
		case ProtectedOther:
			s.ProtectedOther++
		case Unprotected:
			s.Unprotected++
		case Unknown:
			s.Unknown++
		}
		if srv.Risk == RiskHigh {
			s.HighRisk++
		}
	}
	return s
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// configPaths returns all known MCP client config paths for the given home directory.
func configPaths(home string) []clientPath {
	return []clientPath{
		{
			Client: "claude-code",
			Path:   filepath.Join(home, ".claude.json"),
			Key:    "mcpServers",
			Scope:  "user",
		},
		{
			Client: "claude-desktop",
			Path:   filepath.Join(home, ".config", "Claude", "claude_desktop_config.json"),
			Key:    "mcpServers",
			Scope:  "user",
		},
		{
			Client: "cursor",
			Path:   filepath.Join(home, ".cursor", "mcp.json"),
			Key:    "mcpServers",
			Scope:  "user",
		},
		{
			Client: "vscode",
			Path:   filepath.Join(home, ".config", "Code", "User", "mcp.json"),
			Key:    "servers",
			Scope:  "user",
		},
		{
			Client: "cline",
			Path:   filepath.Join(home, ".config", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"),
			Key:    "mcpServers",
			Scope:  "user",
		},
		{
			Client: "continue",
			Path:   filepath.Join(home, ".continue", "config.json"),
			Key:    "mcpServers",
			Scope:  "user",
		},
	}
}
