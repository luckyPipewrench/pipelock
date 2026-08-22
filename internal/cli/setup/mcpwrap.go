// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// MCP server JSON field keys used across wrap/unwrap operations.
const (
	mcpFieldCommand  = "command"
	mcpFieldArgs     = "args"
	mcpSubcommand    = "mcp"
	proxySubcommand  = "proxy"
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

// isWrapped reports whether a server entry is actually mediated by the pipelock
// MCP proxy.
//
// It deliberately does NOT decide this from the presence of the _pipelock
// marker. That marker is a value this tool writes, so an attacker-authored
// project config can carry one beside a raw command; treating it as proof made
// the installer report "already wrapped", skip the entry, and leave its traffic
// unmediated, which is the outcome wrapping exists to prevent.
//
// The invocation is the evidence instead, and the shape of that evidence is
// already established for the Codex integration by isCodexWrapped: the command
// must look like a pipelock binary AND its arguments must begin "mcp proxy".
// Arguments alone are not proof, because an attacker can put those arguments in
// front of their own binary.
//
// The marker is also not REQUIRED here, on purpose. An entry whose invocation
// already goes through the proxy must keep reporting as wrapped even if its
// marker was removed, because re-wrapping it would nest one proxy inside
// another.
func isWrapped(server map[string]interface{}) bool {
	return invokesMCPProxy(server)
}

// invokesMCPProxy reports whether a server entry's own invocation runs the
// pipelock MCP proxy. Two config shapes exist and both are handled: a command
// string with a separate args array, and OpenCode's single command array where
// the binary is element zero.
func invokesMCPProxy(server map[string]interface{}) bool {
	if command, ok := server[mcpFieldCommand].(string); ok {
		return looksLikeWrapperBinary(command) &&
			argsBeginMCPProxy(commandArgStrings(server[mcpFieldArgs]))
	}
	if command := commandArgStrings(server[mcpFieldCommand]); len(command) > 0 {
		return looksLikeWrapperBinary(command[0]) && argsBeginMCPProxy(command[1:])
	}
	return false
}

// argsBeginMCPProxy reports whether an argument list starts the MCP proxy
// subcommand.
func argsBeginMCPProxy(args []string) bool {
	return len(args) >= 2 && args[0] == mcpSubcommand && args[1] == proxySubcommand
}

// commandArgStrings reads an argument list that may be either shape. A config
// decoded from JSON yields []interface{}, while an entry produced in-process by
// wrapMCPServer holds []string. Reading only the first shape made a freshly
// wrapped entry look unwrapped to any in-process caller, which would double-wrap
// it on the next pass.
func commandArgStrings(v interface{}) []string {
	switch typed := v.(type) {
	case []string:
		return typed
	default:
		return interfaceSliceToStrings(v)
	}
}

// looksLikeWrapperBinary reports whether a command is a pipelock binary that
// could be mediating this entry. It accepts the pipelock basename, matching
// isCodexWrapped so a rebuild at a different path does not cause double
// wrapping, and it also accepts the currently running executable by path.
//
// The second case matters because the wrapper writes os.Executable() into the
// config, and that binary is not always named "pipelock": it is the test binary
// under test, and it can be a renamed build in the field. An entry invoking THIS
// executable with the proxy subcommand is mediated by definition, so accepting it
// adds no trust that basename matching did not already grant.
func looksLikeWrapperBinary(command string) bool {
	if command == "" {
		return false
	}
	if looksLikePipelockBinary(command) {
		return true
	}
	self, err := os.Executable()
	if err != nil {
		return false
	}
	if resolved, linkErr := filepath.EvalSymlinks(self); linkErr == nil {
		self = resolved
	}
	if command == self {
		return true
	}
	resolvedCommand, err := filepath.EvalSymlinks(command)
	return err == nil && resolvedCommand == self
}

// warnUnmediatedMarker tells the operator that an entry claimed pipelock coverage
// it does not have. The entry is still wrapped by the caller, so it ends up
// mediated; the warning exists so a false claim is visible rather than silently
// corrected. Shared by every installer so the wording cannot drift.
func warnUnmediatedMarker(w io.Writer, name string, server map[string]interface{}) {
	if !hasUnmediatedPipelockMarker(server) {
		return
	}
	_, _ = fmt.Fprintf(w,
		"warning: server %q carries pipelock metadata but does not run through the proxy; wrapping it\n", name)
}

// hasUnmediatedPipelockMarker reports an entry that claims to be wrapped but is
// not: a _pipelock marker beside an invocation that does not go through the
// proxy. The installer wraps such an entry rather than skipping it, so the
// server ends up mediated, and warns so the operator sees that the claim was
// false rather than having it silently corrected.
func hasUnmediatedPipelockMarker(server map[string]interface{}) bool {
	if _, ok := server[mcpFieldPipelock]; !ok {
		return false
	}
	return !invokesMCPProxy(server)
}
