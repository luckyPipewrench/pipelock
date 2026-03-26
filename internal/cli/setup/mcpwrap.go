// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// MCP server JSON field keys used across wrap/unwrap operations.
const (
	mcpFieldCommand  = "command"
	mcpFieldArgs     = "args"
	mcpFieldURL      = "url"
	mcpFieldHeaders  = "headers"
	mcpFieldType     = "type"
	mcpFieldPipelock = "_pipelock"
)

// mcpConfig is a generic MCP config file with a server map under a
// configurable key. Unknown top-level fields are preserved.
type mcpConfig struct {
	Servers map[string]map[string]interface{}
}

// readMCPConfig reads and parses an MCP config file. Returns an empty config
// if the file doesn't exist.
func readMCPConfig(path, serversKey string) (*mcpConfig, []byte, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		if os.IsNotExist(err) {
			return &mcpConfig{Servers: make(map[string]map[string]interface{})}, nil, nil
		}
		return nil, nil, fmt.Errorf("reading %s: %w", path, err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	cfg := &mcpConfig{Servers: make(map[string]map[string]interface{})}
	if serversRaw, ok := raw[serversKey]; ok {
		if err := json.Unmarshal(serversRaw, &cfg.Servers); err != nil {
			return nil, nil, fmt.Errorf("parsing %s servers: %w", path, err)
		}
	}

	return cfg, data, nil
}

// marshalMCPConfig marshals the config while preserving unknown top-level
// fields from the original file data.
func marshalMCPConfig(originalData []byte, cfg *mcpConfig, serversKey string) ([]byte, error) {
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

// wrapMCPServer wraps a single MCP server entry through pipelock mcp proxy.
// Works for any IDE config format that uses command/args (stdio) or url (HTTP).
func wrapMCPServer(server map[string]interface{}, exe, configFile string, sandbox bool, workspace string) (map[string]interface{}, *pipelockMeta, error) {
	serverType, _ := server[mcpFieldType].(string)
	typeOmitted := serverType == ""
	if typeOmitted {
		serverType = vsTypeStdio
	}

	result := make(map[string]interface{})
	for k, v := range server {
		switch k {
		case mcpFieldCommand, mcpFieldArgs, mcpFieldURL, mcpFieldHeaders, mcpFieldType:
			// Replaced below.
		default:
			result[k] = v
		}
	}

	meta := &pipelockMeta{OriginalType: serverType, TypeOmitted: typeOmitted}
	envFlags := buildEnvFlags(server)

	if serverType == vsTypeStdio {
		originalCmd, _ := server[mcpFieldCommand].(string)
		if originalCmd == "" {
			return nil, nil, fmt.Errorf("stdio server missing command")
		}
		originalArgs := interfaceSliceToStrings(server[mcpFieldArgs])

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

		result[mcpFieldType] = vsTypeStdio
		result[mcpFieldCommand] = exe
		result[mcpFieldArgs] = args
	} else if isVscodeHTTPType(serverType) {
		originalURL, _ := server[mcpFieldURL].(string)
		if originalURL == "" {
			return nil, nil, fmt.Errorf("%s server missing url", serverType)
		}

		if sandbox {
			_, _ = fmt.Fprintf(os.Stderr, "warning: --sandbox skipped for %s server (no subprocess to sandbox)\n", serverType)
		}

		meta.OriginalURL = originalURL
		if headers, ok := server[mcpFieldHeaders].(map[string]interface{}); ok && len(headers) > 0 {
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

		result[mcpFieldType] = vsTypeStdio
		result[mcpFieldCommand] = exe
		result[mcpFieldArgs] = args
	} else {
		return nil, nil, fmt.Errorf("unsupported server type %q", serverType)
	}

	return result, meta, nil
}

// unwrapMCPServer restores a server from its pipelock metadata.
func unwrapMCPServer(server map[string]interface{}) (map[string]interface{}, error) {
	metaRaw, ok := server[mcpFieldPipelock]
	if !ok {
		return server, nil
	}

	metaJSON, err := json.Marshal(metaRaw)
	if err != nil {
		return nil, fmt.Errorf("reading _pipelock metadata: %w", err)
	}
	var meta pipelockMeta
	if err := json.Unmarshal(metaJSON, &meta); err != nil {
		return nil, fmt.Errorf("parsing _pipelock metadata: %w", err)
	}

	result := make(map[string]interface{})
	for k, v := range server {
		switch k {
		case mcpFieldCommand, mcpFieldArgs, mcpFieldURL, mcpFieldHeaders, mcpFieldType, mcpFieldPipelock:
			// Replaced/removed below.
		default:
			result[k] = v
		}
	}

	switch meta.OriginalType {
	case vsTypeStdio:
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
		result[mcpFieldType] = meta.OriginalType
	}

	switch meta.OriginalType {
	case vsTypeStdio:
		result[mcpFieldCommand] = meta.OriginalCommand
		if len(meta.OriginalArgs) > 0 {
			result[mcpFieldArgs] = meta.OriginalArgs
		}
	default:
		result[mcpFieldURL] = meta.OriginalURL
		if len(meta.OriginalHeaders) > 0 {
			headers := make(map[string]interface{}, len(meta.OriginalHeaders))
			for k, v := range meta.OriginalHeaders {
				headers[k] = v
			}
			result[mcpFieldHeaders] = headers
		}
	}

	return result, nil
}

// isWrapped returns true if a server entry has pipelock metadata.
func isWrapped(server map[string]interface{}) bool {
	_, ok := server[mcpFieldPipelock]
	return ok
}
