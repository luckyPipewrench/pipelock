// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// MCP server JSON field keys used across wrap/unwrap operations.
const (
	MCPFieldCommand  = "command"
	MCPFieldArgs     = "args"
	MCPFieldURL      = "url"
	MCPFieldHeaders  = "headers"
	MCPFieldType     = "type"
	MCPFieldPipelock = "_pipelock"
)

// MCPConfig is a generic MCP config file with a server map under a
// configurable key. Unknown top-level fields are preserved.
type MCPConfig struct {
	Servers map[string]map[string]interface{}
}

// ReadMCPConfig reads and parses an MCP config file. Returns an empty config
// if the file doesn't exist.
func ReadMCPConfig(path, serversKey string) (*MCPConfig, []byte, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		if os.IsNotExist(err) {
			return &MCPConfig{Servers: make(map[string]map[string]interface{})}, nil, nil
		}
		return nil, nil, fmt.Errorf("reading %s: %w", path, err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	cfg := &MCPConfig{Servers: make(map[string]map[string]interface{})}
	if serversRaw, ok := raw[serversKey]; ok {
		if err := json.Unmarshal(serversRaw, &cfg.Servers); err != nil {
			return nil, nil, fmt.Errorf("parsing %s servers: %w", path, err)
		}
	}

	return cfg, data, nil
}

// MarshalMCPConfig marshals the config while preserving unknown top-level
// fields from the original file data.
func MarshalMCPConfig(originalData []byte, cfg *MCPConfig, serversKey string) ([]byte, error) {
	if len(originalData) > 0 {
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(originalData, &raw); err == nil && raw != nil {
			serversJSON, err := json.Marshal(cfg.Servers)
			if err != nil {
				return nil, err
			}
			raw[serversKey] = serversJSON
			output, err := json.MarshalIndent(raw, "", "  ")
			if err != nil {
				return nil, err
			}
			return append(output, '\n'), nil
		}
	}

	// No original data or parse failed: build from scratch.
	wrapper := map[string]interface{}{serversKey: cfg.Servers}
	output, err := json.MarshalIndent(wrapper, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(output, '\n'), nil
}

// WrapMCPServer wraps a single MCP server entry through pipelock mcp proxy.
// Works for any IDE config format that uses command/args (stdio) or url (HTTP).
//
// NOTE: This function references VSTypeStdio, IsVscodeHTTPType, BuildEnvFlags,
// InterfaceSliceToStrings, and PipelockMeta which remain in the parent cli
// package (vscode.go). These cross-package references will be resolved in the
// wiring step when shared types are extracted to cliutil or a shared package.
func WrapMCPServer(server map[string]interface{}, exe, configFile string, sandbox bool, workspace string) (map[string]interface{}, *PipelockMeta, error) {
	serverType, _ := server[MCPFieldType].(string)
	typeOmitted := serverType == ""
	if typeOmitted {
		serverType = VSTypeStdio
	}

	result := make(map[string]interface{})
	for k, v := range server {
		switch k {
		case MCPFieldCommand, MCPFieldArgs, MCPFieldURL, MCPFieldHeaders, MCPFieldType:
			// Replaced below.
		default:
			result[k] = v
		}
	}

	meta := &PipelockMeta{OriginalType: serverType, TypeOmitted: typeOmitted}
	envFlags := BuildEnvFlags(server)

	if serverType == VSTypeStdio {
		originalCmd, _ := server[MCPFieldCommand].(string)
		if originalCmd == "" {
			return nil, nil, fmt.Errorf("stdio server missing command")
		}
		originalArgs := InterfaceSliceToStrings(server[MCPFieldArgs])

		meta.OriginalCommand = originalCmd
		meta.OriginalArgs = originalArgs

		args := []string{"mcp", "proxy"}
		if configFile != "" {
			args = append(args, "--config", configFile)
		}
		if sandbox {
			args = append(args, "--sandbox")
			if workspace != "" {
				args = append(args, "--workspace", workspace)
			}
		}
		args = append(args, envFlags...)
		args = append(args, "--")
		args = append(args, originalCmd)
		args = append(args, originalArgs...)

		result[MCPFieldType] = VSTypeStdio
		result[MCPFieldCommand] = exe
		result[MCPFieldArgs] = args
	} else if IsVscodeHTTPType(serverType) {
		originalURL, _ := server[MCPFieldURL].(string)
		if originalURL == "" {
			return nil, nil, fmt.Errorf("%s server missing url", serverType)
		}

		if sandbox {
			_, _ = fmt.Fprintf(os.Stderr, "warning: --sandbox skipped for %s server (no subprocess to sandbox)\n", serverType)
		}

		meta.OriginalURL = originalURL
		if headers, ok := server[MCPFieldHeaders].(map[string]interface{}); ok && len(headers) > 0 {
			// mcp proxy --upstream does not yet support header passthrough.
			// Reject rather than silently generating a broken wrapper.
			return nil, nil, fmt.Errorf(
				"%s server has headers that cannot be passed through pipelock's MCP proxy; "+
					"use env var passthrough (--env) with a server that reads auth from environment instead",
				serverType)
		}

		args := []string{"mcp", "proxy"}
		if configFile != "" {
			args = append(args, "--config", configFile)
		}
		args = append(args, envFlags...)
		args = append(args, "--upstream", originalURL)

		result[MCPFieldType] = VSTypeStdio
		result[MCPFieldCommand] = exe
		result[MCPFieldArgs] = args
	} else {
		return nil, nil, fmt.Errorf("unsupported server type %q", serverType)
	}

	return result, meta, nil
}

// UnwrapMCPServer restores a server from its pipelock metadata.
func UnwrapMCPServer(server map[string]interface{}) (map[string]interface{}, error) {
	metaRaw, ok := server[MCPFieldPipelock]
	if !ok {
		return server, nil
	}

	metaJSON, err := json.Marshal(metaRaw)
	if err != nil {
		return nil, fmt.Errorf("reading _pipelock metadata: %w", err)
	}
	var meta PipelockMeta
	if err := json.Unmarshal(metaJSON, &meta); err != nil {
		return nil, fmt.Errorf("parsing _pipelock metadata: %w", err)
	}

	result := make(map[string]interface{})
	for k, v := range server {
		switch k {
		case MCPFieldCommand, MCPFieldArgs, MCPFieldURL, MCPFieldHeaders, MCPFieldType, MCPFieldPipelock:
			// Replaced/removed below.
		default:
			result[k] = v
		}
	}

	switch meta.OriginalType {
	case VSTypeStdio:
		if meta.OriginalCommand == "" {
			return nil, fmt.Errorf("invalid _pipelock metadata: missing original_command")
		}
	case "":
		return nil, fmt.Errorf("invalid _pipelock metadata: missing original_type")
	default:
		if meta.OriginalURL == "" {
			return nil, fmt.Errorf("invalid _pipelock metadata: missing original_url for %s server", meta.OriginalType)
		}
	}

	if !meta.TypeOmitted {
		result[MCPFieldType] = meta.OriginalType
	}

	switch meta.OriginalType {
	case VSTypeStdio:
		result[MCPFieldCommand] = meta.OriginalCommand
		if len(meta.OriginalArgs) > 0 {
			result[MCPFieldArgs] = meta.OriginalArgs
		}
	default:
		result[MCPFieldURL] = meta.OriginalURL
		if len(meta.OriginalHeaders) > 0 {
			headers := make(map[string]interface{}, len(meta.OriginalHeaders))
			for k, v := range meta.OriginalHeaders {
				headers[k] = v
			}
			result[MCPFieldHeaders] = headers
		}
	}

	return result, nil
}

// IsWrapped returns true if a server entry has pipelock metadata.
func IsWrapped(server map[string]interface{}) bool {
	_, ok := server[MCPFieldPipelock]
	return ok
}

// Note: atomicWriteFile is defined in generate_mcporter.go and shared
// across CLI commands. Use atomicWriteFile(path, data, doBackup).

// --- Types and helpers referenced from vscode.go ---
// These are duplicated here temporarily. In the wiring step, they will
// be extracted to a shared package to avoid duplication.

// PipelockMeta stores original server config for unwrapping on remove.
type PipelockMeta struct {
	OriginalType    string            `json:"original_type"`
	TypeOmitted     bool              `json:"type_omitted,omitempty"`
	OriginalCommand string            `json:"original_command,omitempty"`
	OriginalArgs    []string          `json:"original_args,omitempty"`
	OriginalURL     string            `json:"original_url,omitempty"`
	OriginalHeaders map[string]string `json:"original_headers,omitempty"`
}

// VSTypeStdio is the MCP server type for subprocess-based servers.
const VSTypeStdio = "stdio"

// IsVscodeHTTPType returns true for server types that use URL-based upstream
// transport (sse, http).
func IsVscodeHTTPType(t string) bool { return t != VSTypeStdio && t != "" }

// BuildEnvFlags extracts env var keys from a server's "env" block and returns
// --env KEY flags for passthrough to pipelock mcp proxy.
func BuildEnvFlags(server map[string]interface{}) []string {
	envBlock, ok := server["env"].(map[string]interface{})
	if !ok || len(envBlock) == 0 {
		return nil
	}
	var flags []string
	for key := range envBlock {
		flags = append(flags, "--env", key)
	}
	return flags
}

// InterfaceSliceToStrings converts []interface{} (from JSON unmarshal) to []string.
func InterfaceSliceToStrings(v interface{}) []string {
	items, ok := v.([]interface{})
	if !ok {
		return nil
	}
	result := make([]string, 0, len(items))
	for _, item := range items {
		if s, ok := item.(string); ok {
			result = append(result, s)
		}
	}
	return result
}
