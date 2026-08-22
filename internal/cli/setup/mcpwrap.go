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

// wrapperState is how an MCP server entry relates to this pipelock binary. A
// single boolean cannot serve both callers: install asks whether THIS executable
// will mediate the traffic, and remove asks whether some pipelock wrapper can be
// migrated away. Answering both with one predicate is what allowed a forged entry
// to be skipped, or would strand an older wrapper permanently.
type wrapperState int

const (
	// stateNotWrapper is an entry that does not invoke the MCP proxy at all.
	stateNotWrapper wrapperState = iota
	// stateSelf invokes the proxy with the binary running right now, so its
	// traffic is mediated by this executable. Only this state may be skipped.
	stateSelf
	// stateForeignWrapper is shaped like a proxy invocation run by some other
	// binary. That may be a pipelock built at a different path, or an
	// attacker-authored config naming its own binary "pipelock". The installer
	// cannot tell those apart and must not skip either.
	stateForeignWrapper
)

// classifyWrapper decides which state an entry is in from its own invocation.
//
// The binary is compared by FILE IDENTITY, not by name. A basename check was the
// original form and is a fail-open: any project config can name an
// attacker-controlled binary "pipelock", add leading "mcp proxy" arguments, and be
// skipped by the installer, leaving that binary running with nothing in front of
// it. Reproduced before this changed, for both a relative ./tools/pipelock and a
// bare PATH-resolved pipelock.
func classifyWrapper(server map[string]interface{}) wrapperState {
	binary, args := serverInvocation(server)
	if binary == "" || !argsBeginMCPProxy(args) {
		return stateNotWrapper
	}
	if isThisExecutable(binary) {
		return stateSelf
	}
	return stateForeignWrapper
}

// isWrappedBySelf reports whether an entry is already mediated by this binary. It
// is the ONLY condition under which an installer may skip an entry, because it is
// the only one that establishes the traffic is actually mediated.
//
// The _pipelock marker is deliberately not consulted. It is a value this tool
// writes, so treating its presence as proof let a forged config be skipped. The
// marker is also not REQUIRED: an entry already invoking this binary through the
// proxy stays skipped with its marker removed, rather than being wrapped twice.
func isWrappedBySelf(server map[string]interface{}) bool {
	return classifyWrapper(server) == stateSelf
}

// isRestorableWrapper reports whether an entry looks like a pipelock wrapper that
// remove should unwrap. It deliberately accepts a FOREIGN wrapper as well as this
// binary, because requiring identity here would strand every entry wrapped by an
// earlier pipelock installed at a different path: an operator who upgrades could
// never remove them.
//
// That looseness is safe for choosing WHICH entries to restore and is not safe for
// everything the restore then does. In particular a metadata-supplied deletion
// target must never be honoured; see the header-sidecar note in the VS Code
// removal path.
func isRestorableWrapper(server map[string]interface{}) bool {
	return classifyWrapper(server) != stateNotWrapper
}

// isThisExecutable reports whether a command names the binary running right now,
// compared by file identity rather than by name. A bare command that does not
// resolve to a file is refused, which is correct: the installer cannot prove what
// a PATH lookup will find when the editor launches.
//
// This establishes filesystem identity and nothing more. It does not prove binary
// provenance or contents, and it cannot prevent the file changing between this
// check and the editor's launch.
func isThisExecutable(command string) bool {
	if command == "" {
		return false
	}
	self, err := os.Executable()
	if err != nil {
		return false
	}
	selfInfo, err := os.Stat(self)
	if err != nil {
		return false
	}
	commandInfo, err := os.Stat(command)
	if err != nil {
		return false
	}
	return os.SameFile(selfInfo, commandInfo)
}

// serverInvocation reads the binary and its arguments out of either config shape:
// a command string with a separate args array, or OpenCode's single command array
// where the binary is element zero.
func serverInvocation(server map[string]interface{}) (binary string, args []string) {
	if command, ok := server[mcpFieldCommand].(string); ok {
		return command, commandArgStrings(server[mcpFieldArgs])
	}
	if command := commandArgStrings(server[mcpFieldCommand]); len(command) > 0 {
		return command[0], command[1:]
	}
	return "", nil
}

// argsBeginMCPProxy reports whether an argument list starts the MCP proxy
// subcommand.
func argsBeginMCPProxy(args []string) bool {
	return len(args) >= 2 && args[0] == mcpSubcommand && args[1] == proxySubcommand
}

// warnForeignWrapper tells the operator that an entry claimed mediation this
// binary cannot confirm. The caller wraps it regardless, so the result IS
// mediated; the warning exists so a false claim is visible rather than silently
// corrected, and so an operator who upgraded pipelock knows why an entry is being
// wrapped again.
func warnForeignWrapper(w io.Writer, name string, server map[string]interface{}) {
	switch classifyWrapper(server) {
	case stateForeignWrapper:
		binary, _ := serverInvocation(server)
		_, _ = fmt.Fprintf(w,
			"warning: server %q runs %q with proxy arguments but that is not this pipelock binary; wrapping it, and remove-then-install for a single clean wrap\n",
			name, binary)
	case stateNotWrapper:
		if _, marked := server[mcpFieldPipelock]; marked {
			_, _ = fmt.Fprintf(w,
				"warning: server %q carries pipelock metadata but does not run through the proxy; wrapping it\n", name)
		}
	case stateSelf:
	}
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

// warnUnmediatedMarker tells the operator that an entry claimed pipelock coverage
// it does not have. The entry is still wrapped by the caller, so it ends up
// mediated; the warning exists so a false claim is visible rather than silently
// corrected. Shared by every installer so the wording cannot drift.

// hasUnmediatedPipelockMarker reports an entry that claims to be wrapped but is
// not: a _pipelock marker beside an invocation that does not go through the
// proxy. The installer wraps such an entry rather than skipping it, so the
// server ends up mediated, and warns so the operator sees that the claim was
// false rather than having it silently corrected.
