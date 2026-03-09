// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"encoding/json"
	"fmt"
	"os"
)

// rawServer is the JSON shape of a single MCP server entry across all clients.
type rawServer struct {
	Type      string            `json:"type"`
	Command   string            `json:"command"`
	Args      []string          `json:"args"`
	Env       map[string]string `json:"env"`
	URL       string            `json:"url"`
	ServerURL string            `json:"serverUrl"` // Windsurf uses this
	Headers   map[string]string `json:"headers"`
}

// parseConfigFile reads a JSON config file and extracts MCP server entries
// from the given top-level key (e.g., "mcpServers" or "servers").
func parseConfigFile(path, key, client string) ([]MCPServer, error) {
	data, err := os.ReadFile(path) //nolint:gosec // paths are constructed from known config locations
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	serversRaw, ok := raw[key]
	if !ok {
		return nil, nil // key not present, not an error
	}

	servers, err := parseServerMap(serversRaw, path, client)
	if err != nil {
		return nil, fmt.Errorf("parsing %s[%s]: %w", path, key, err)
	}

	return servers, nil
}

// parseClaudeCodeConfig handles Claude Code's nested structure where per-project
// servers live under projects.<path>.mcpServers alongside global mcpServers.
func parseClaudeCodeConfig(path string) ([]MCPServer, error) {
	data, err := os.ReadFile(path) //nolint:gosec // paths are constructed from known config locations
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	var servers []MCPServer

	// Parse global mcpServers
	if serversRaw, ok := raw["mcpServers"]; ok {
		global, err := parseServerMap(serversRaw, path, "claude-code")
		if err != nil {
			return nil, fmt.Errorf("parsing %s[mcpServers]: %w", path, err)
		}
		servers = append(servers, global...)
	}

	// Parse per-project mcpServers, tagging each with its project path.
	// Malformed entries emit a placeholder server with parse_warnings
	// so operators know something was unreadable.
	if projectsRaw, ok := raw["projects"]; ok {
		var projects map[string]json.RawMessage
		if err := json.Unmarshal(projectsRaw, &projects); err != nil {
			servers = append(servers, MCPServer{
				Client:        "claude-code",
				ConfigPath:    path,
				ServerName:    "(projects)",
				Transport:     TransportUnknown,
				Args:          []string{},
				ParseWarnings: []string{"projects key is not a valid object: " + err.Error()},
			})
			return servers, nil
		}
		for projPath, projRaw := range projects {
			var proj map[string]json.RawMessage
			if err := json.Unmarshal(projRaw, &proj); err != nil {
				servers = append(servers, MCPServer{
					Client:        "claude-code",
					ConfigPath:    path,
					ProjectPath:   projPath,
					ServerName:    "(malformed project)",
					Transport:     TransportUnknown,
					Args:          []string{},
					ParseWarnings: []string{"project entry is not a valid object: " + err.Error()},
				})
				continue
			}
			if mcpRaw, ok := proj["mcpServers"]; ok {
				projServers, err := parseServerMap(mcpRaw, path, "claude-code")
				if err != nil {
					servers = append(servers, MCPServer{
						Client:        "claude-code",
						ConfigPath:    path,
						ProjectPath:   projPath,
						ServerName:    "(malformed mcpServers)",
						Transport:     TransportUnknown,
						Args:          []string{},
						ParseWarnings: []string{"mcpServers is not a valid object: " + err.Error()},
					})
					continue
				}
				for i := range projServers {
					projServers[i].ProjectPath = projPath
				}
				servers = append(servers, projServers...)
			}
		}
	}

	return servers, nil
}

// parseServerMap unmarshals a mcpServers/servers JSON object into MCPServer structs.
func parseServerMap(raw json.RawMessage, path, client string) ([]MCPServer, error) {
	var serverMap map[string]rawServer
	if err := json.Unmarshal(raw, &serverMap); err != nil {
		return nil, err
	}

	servers := make([]MCPServer, 0, len(serverMap))
	for name, rs := range serverMap {
		s := MCPServer{
			Client:     client,
			ConfigPath: path,
			ServerName: name,
			Command:    rs.Command,
			Args:       rs.Args,
			Env:        rs.Env,
		}

		switch {
		case rs.URL != "":
			s.URL = rs.URL
		case rs.ServerURL != "":
			s.URL = rs.ServerURL
		}

		s.Transport = inferTransport(rs, s.URL)

		if s.Args == nil {
			s.Args = []string{}
		}

		if len(rs.Headers) > 0 {
			s.ParseWarnings = append(s.ParseWarnings, "headers present but not preserved in wrapper suggestions")
		}

		servers = append(servers, s)
	}

	return servers, nil
}

// inferTransport determines the transport type from the server config.
// If the config has an explicit "type" field, that takes precedence.
func inferTransport(rs rawServer, url string) string {
	switch rs.Type {
	case TransportStdio, TransportHTTP, "sse":
		return rs.Type
	}
	if rs.Command != "" {
		return TransportStdio
	}
	if url != "" {
		return TransportHTTP
	}
	return TransportUnknown
}
