// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

// OpenCode is MCP-native and stores servers under the top-level "mcp" key in
// JSON/JSONC config files. Local servers use a single command array. Remote
// servers use url plus optional headers. Install rewrites both shapes into
// local command-array entries that launch `pipelock mcp proxy`.

const (
	opencodeConfigFilename      = "opencode.json"
	opencodeConfigJSONCFilename = "opencode.jsonc"
	opencodeConfigDirname       = "opencode"
	opencodeConfigEnv           = "OPENCODE_CONFIG"
	opencodeServersKey          = "mcp"
	opencodeSchemaKey           = "$schema"
	opencodeSchemaURL           = "https://opencode.ai/config.json"
	opencodeTypeLocal           = "local"
	opencodeTypeRemote          = "remote"
	opencodeFieldEnvironment    = "environment"
	opencodeFieldOAuth          = "oauth"
)

type opencodeConfig struct {
	Servers map[string]map[string]interface{} `json:"mcp"`
}

// OpenCodeCmd returns the `pipelock opencode` command tree.
func OpenCodeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "opencode",
		Short: "OpenCode integration",
		Long: `Commands for integrating pipelock with OpenCode's MCP support.

OpenCode is MCP-native rather than hook-based, so install rewrites its
opencode.json MCP entries so every server runs through pipelock's MCP proxy.
All tool calls, responses, and descriptions are scanned bidirectionally.

The install subcommand rewrites local and remote MCP servers to route through
pipelock. The remove subcommand restores the original config from the
_pipelock metadata field. Both commands are idempotent.`,
	}

	cmd.AddCommand(
		opencodeInstallCmd(),
		opencodeRemoveCmd(),
	)

	return cmd
}

func opencodeInstallCmd() *cobra.Command {
	var (
		path       string
		dryRun     bool
		configFile string
	)

	cmd := &cobra.Command{
		Use:   "install",
		Short: "Wrap OpenCode MCP servers through pipelock",
		Long: `Rewrites OpenCode's opencode.json to route MCP servers through
pipelock's MCP proxy. Local servers are wrapped in place. Remote servers are
converted to local command-array wrappers with --upstream and any headers are
stored in a private --header-file sidecar.

By default writes to OPENCODE_CONFIG when set, otherwise
~/.config/opencode/opencode.json. Use --path to point at a different file.
Already-wrapped servers are skipped (idempotent). A .bak backup is created
before modification. Non-server fields are preserved.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runOpenCodeInstall(cmd, path, dryRun, configFile)
		},
	}

	cmd.Flags().StringVar(&path, "path", "", "path to opencode.json (default OPENCODE_CONFIG or ~/.config/opencode/opencode.json)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show what would be written without modifying files")
	cmd.Flags().StringVarP(&configFile, "config", "c", "", "path to pipelock config file for --config passthrough")

	return cmd
}

func opencodeRemoveCmd() *cobra.Command {
	var (
		path   string
		dryRun bool
	)

	cmd := &cobra.Command{
		Use:   "remove",
		Short: "Remove pipelock wrapping from OpenCode MCP servers",
		Long: `Restores OpenCode's opencode.json by unwrapping servers that were
wrapped by pipelock install. Original server configurations are restored from
the _pipelock metadata field. Non-wrapped servers are left unchanged.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runOpenCodeRemove(cmd, path, dryRun)
		},
	}

	cmd.Flags().StringVar(&path, "path", "", "path to opencode.json (default OPENCODE_CONFIG or ~/.config/opencode/opencode.json)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show what would be written without modifying files")

	return cmd
}

func opencodeConfigPath(override string) (string, error) {
	if override != "" {
		return override, nil
	}
	if envPath := os.Getenv(opencodeConfigEnv); envPath != "" {
		return envPath, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("finding home directory: %w", err)
	}
	dir := filepath.Join(home, ".config", opencodeConfigDirname)
	jsonPath := filepath.Join(dir, opencodeConfigFilename)
	jsoncPath := filepath.Join(dir, opencodeConfigJSONCFilename)
	if _, err := os.Stat(jsonPath); err == nil || !errors.Is(err, os.ErrNotExist) {
		return jsonPath, nil
	}
	if _, err := os.Stat(jsoncPath); err == nil {
		return jsoncPath, nil
	}
	return jsonPath, nil
}

func runOpenCodeInstall(cmd *cobra.Command, override string, dryRun bool, configFile string) error {
	targetPath, err := opencodeConfigPath(override)
	if err != nil {
		return err
	}

	exe, err := resolvePipelockBinary()
	if err != nil {
		return err
	}

	configFile = discoverConfigForWrap(cmd, configFile)

	existingData, readErr := os.ReadFile(filepath.Clean(targetPath))
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return fmt.Errorf("reading existing %s: %w", targetPath, readErr)
	}

	mcpCfg := &opencodeConfig{Servers: make(map[string]map[string]interface{})}
	if readErr == nil && len(existingData) > 0 {
		if err := unmarshalOpenCodeConfig(existingData, mcpCfg); err != nil {
			return fmt.Errorf("parsing %s: %w", targetPath, err)
		}
		if mcpCfg.Servers == nil {
			mcpCfg.Servers = make(map[string]map[string]interface{})
		}
	}

	wrapped := 0
	skipped := 0
	var sidecarOps []sidecarOp
	for name, server := range mcpCfg.Servers {
		if isVscodeWrapped(server) {
			skipped++
			continue
		}

		newServer, meta, plan, err := wrapOpenCodeServer(server, exe, configFile, targetPath, name)
		if err != nil {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warning: skipping server %q: %v\n", name, err)
			continue
		}

		metaJSON, err := json.Marshal(meta)
		if err != nil {
			return fmt.Errorf("marshaling metadata for %q: %w", name, err)
		}
		var metaMap interface{}
		if err := json.Unmarshal(metaJSON, &metaMap); err != nil {
			return fmt.Errorf("unmarshaling metadata for %q: %w", name, err)
		}
		newServer[mcpFieldPipelock] = metaMap

		mcpCfg.Servers[name] = newServer
		if plan != nil {
			sidecarOps = append(sidecarOps, *plan)
		}
		wrapped++
	}

	output, err := marshalOpenCodeConfig(existingData, mcpCfg)
	if err != nil {
		return fmt.Errorf("marshaling %s: %w", targetPath, err)
	}

	if dryRun {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Would write to %s (%d wrapped, %d already wrapped):\n%s", targetPath, wrapped, skipped, output)
		return nil
	}

	targetDir := filepath.Dir(targetPath)
	if err := os.MkdirAll(targetDir, 0o750); err != nil {
		return fmt.Errorf("creating directory %s: %w", targetDir, err)
	}

	if readErr == nil {
		if err := os.WriteFile(targetPath+".bak", existingData, 0o600); err != nil {
			return fmt.Errorf("creating backup: %w", err)
		}
	}

	if err := applySidecarOps(sidecarOps); err != nil {
		return fmt.Errorf("writing header sidecar: %w", err)
	}
	if err := vscodeAtomicWrite(targetPath, output, targetDir); err != nil {
		rollbackSidecarWrites(sidecarOps)
		return err
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Wrapped %d server(s) in %s (%d already wrapped)\n", wrapped, targetPath, skipped)
	if wrapped > 0 {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Restart OpenCode to activate pipelock scanning.\n")
	}
	return nil
}

func runOpenCodeRemove(cmd *cobra.Command, override string, dryRun bool) error {
	targetPath, err := opencodeConfigPath(override)
	if err != nil {
		return err
	}

	existingData, err := os.ReadFile(filepath.Clean(targetPath))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "No %s found at %s\n", opencodeConfigFilename, targetPath)
			return nil
		}
		return fmt.Errorf("reading %s: %w", targetPath, err)
	}

	mcpCfg := &opencodeConfig{Servers: make(map[string]map[string]interface{})}
	if err := unmarshalOpenCodeConfig(existingData, mcpCfg); err != nil {
		return fmt.Errorf("parsing %s: %w", targetPath, err)
	}

	unwrapped := 0
	var sidecarOps []sidecarOp
	for name, server := range mcpCfg.Servers {
		if !isVscodeWrapped(server) {
			continue
		}

		restored, plan, err := unwrapOpenCodeServer(server)
		if err != nil {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warning: could not unwrap %q: %v\n", name, err)
			continue
		}

		mcpCfg.Servers[name] = restored
		if plan != nil {
			sidecarOps = append(sidecarOps, *plan)
		}
		unwrapped++
	}

	if unwrapped == 0 && len(sidecarOps) == 0 {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "No OpenCode servers were unwrapped in %s\n", targetPath)
		return nil
	}

	output, err := marshalOpenCodeConfig(existingData, mcpCfg)
	if err != nil {
		return fmt.Errorf("marshaling %s: %w", targetPath, err)
	}

	if dryRun {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Would write to %s (%d unwrapped):\n%s", targetPath, unwrapped, output)
		return nil
	}

	if err := os.WriteFile(targetPath+".bak", existingData, 0o600); err != nil {
		return fmt.Errorf("creating backup: %w", err)
	}

	targetDir := filepath.Dir(targetPath)
	if err := vscodeAtomicWrite(targetPath, output, targetDir); err != nil {
		return err
	}

	cleanupOpenCodeSidecars(cmd, targetPath, sidecarOps)

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Unwrapped %d server(s) in %s\n", unwrapped, targetPath)
	if unwrapped > 0 {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Restart OpenCode to apply changes.\n")
	}
	return nil
}

func wrapOpenCodeServer(server map[string]interface{}, exe, configFile, targetConfigPath, serverName string) (map[string]interface{}, *pipelockMeta, *sidecarOp, error) {
	_, hasCommand := server[mcpFieldCommand]
	_, hasURL := server[mcpFieldURL]
	if hasCommand && hasURL {
		return nil, nil, nil, fmt.Errorf("server has both command and url")
	}

	serverType, _ := server[mcpFieldType].(string)
	if serverType == "" {
		switch {
		case hasCommand:
			serverType = opencodeTypeLocal
		case hasURL:
			serverType = opencodeTypeRemote
		default:
			return nil, nil, nil, fmt.Errorf("server has neither command nor url")
		}
	}

	result := make(map[string]interface{})
	for k, v := range server {
		switch k {
		case mcpFieldCommand, mcpFieldURL, mcpFieldHeaders, mcpFieldType:
			// Replaced below.
		default:
			result[k] = v
		}
	}

	meta := &pipelockMeta{OriginalType: serverType}
	envFlags, err := buildOpenCodeEnvFlags(server)
	if err != nil {
		return nil, nil, nil, err
	}

	switch serverType {
	case opencodeTypeLocal:
		command, err := openCodeCommandToStrings(server[mcpFieldCommand])
		if err != nil {
			return nil, nil, nil, err
		}
		if len(command) == 0 || command[0] == "" {
			return nil, nil, nil, fmt.Errorf("local server missing command")
		}
		meta.OriginalCommand = command[0]
		meta.OriginalArgs = append([]string(nil), command[1:]...)
		meta.ArgsPresent = len(command) > 1

		wrappedCommand := []string{exe, "mcp", "proxy"}
		if configFile != "" {
			wrappedCommand = append(wrappedCommand, "--config", configFile)
		}
		wrappedCommand = append(wrappedCommand, envFlags...)
		wrappedCommand = append(wrappedCommand, "--", command[0])
		wrappedCommand = append(wrappedCommand, command[1:]...)

		result[mcpFieldType] = opencodeTypeLocal
		result[mcpFieldCommand] = wrappedCommand
		return result, meta, nil, nil

	case opencodeTypeRemote:
		originalURL, _ := server[mcpFieldURL].(string)
		if originalURL == "" {
			return nil, nil, nil, fmt.Errorf("remote server missing url")
		}
		if unsupportedOpenCodeRemoteAuth(server) {
			return nil, nil, nil, fmt.Errorf("remote server has oauth settings that cannot be preserved by a local --upstream wrapper")
		}

		meta.OriginalURL = originalURL
		headerLines, err := extractHeaderLines(server)
		if err != nil {
			return nil, nil, nil, err
		}
		if headers, ok := server[mcpFieldHeaders].(map[string]interface{}); ok {
			meta.OriginalHeaders = make(map[string]string, len(headers))
			for k, v := range headers {
				value, ok := v.(string)
				if !ok {
					return nil, nil, nil, fmt.Errorf("header %q has non-string value of type %T; only string header values are supported", k, v)
				}
				meta.OriginalHeaders[k] = value
			}
		}

		var (
			sidecarFlags []string
			plan         *sidecarOp
		)
		if len(headerLines) > 0 {
			path, err := headerSidecarPath(targetConfigPath, serverName)
			if err != nil {
				return nil, nil, nil, err
			}
			body := []byte(strings.Join(headerLines, "\n") + "\n")
			plan = &sidecarOp{kind: sidecarOpWrite, path: path, body: body}
			meta.HeaderSidecarPath = path
			sidecarFlags = []string{mcpFlagHeaderFile, path}
		}

		wrappedCommand := []string{exe, "mcp", "proxy"}
		if configFile != "" {
			wrappedCommand = append(wrappedCommand, "--config", configFile)
		}
		wrappedCommand = append(wrappedCommand, envFlags...)
		wrappedCommand = append(wrappedCommand, sidecarFlags...)
		wrappedCommand = append(wrappedCommand, "--upstream", originalURL)

		result[mcpFieldType] = opencodeTypeLocal
		result[mcpFieldCommand] = wrappedCommand
		return result, meta, plan, nil

	default:
		return nil, nil, nil, fmt.Errorf("unsupported server type %q", serverType)
	}
}

func unwrapOpenCodeServer(server map[string]interface{}) (map[string]interface{}, *sidecarOp, error) {
	metaRaw, ok := server[mcpFieldPipelock]
	if !ok {
		return server, nil, nil
	}

	metaJSON, err := json.Marshal(metaRaw)
	if err != nil {
		return nil, nil, fmt.Errorf("reading _pipelock metadata: %w", err)
	}
	var meta pipelockMeta
	if err := json.Unmarshal(metaJSON, &meta); err != nil {
		return nil, nil, fmt.Errorf("parsing _pipelock metadata: %w", err)
	}

	var plan *sidecarOp
	if meta.HeaderSidecarPath != "" {
		path, err := validatedHeaderSidecarDeletePath(meta.HeaderSidecarPath)
		if err != nil {
			return nil, nil, err
		}
		plan = &sidecarOp{kind: sidecarOpDelete, path: path}
	}

	result := make(map[string]interface{})
	for k, v := range server {
		switch k {
		case mcpFieldCommand, mcpFieldURL, mcpFieldHeaders, mcpFieldType, mcpFieldPipelock:
			// Replaced/removed below.
		default:
			result[k] = v
		}
	}

	switch meta.OriginalType {
	case opencodeTypeLocal:
		if meta.OriginalCommand == "" {
			return nil, nil, fmt.Errorf("invalid _pipelock metadata: missing original_command")
		}
		command := []string{meta.OriginalCommand}
		command = append(command, meta.OriginalArgs...)
		result[mcpFieldType] = opencodeTypeLocal
		result[mcpFieldCommand] = command
	case opencodeTypeRemote:
		if meta.OriginalURL == "" {
			return nil, nil, fmt.Errorf("invalid _pipelock metadata: missing original_url")
		}
		result[mcpFieldType] = opencodeTypeRemote
		result[mcpFieldURL] = meta.OriginalURL
		if len(meta.OriginalHeaders) > 0 {
			headers := make(map[string]interface{}, len(meta.OriginalHeaders))
			for k, v := range meta.OriginalHeaders {
				headers[k] = v
			}
			result[mcpFieldHeaders] = headers
		}
	case "":
		return nil, nil, fmt.Errorf("invalid _pipelock metadata: missing original_type")
	default:
		return nil, nil, fmt.Errorf("invalid _pipelock metadata: unsupported original_type %q", meta.OriginalType)
	}

	return result, plan, nil
}

func cleanupOpenCodeSidecars(cmd *cobra.Command, targetPath string, ops []sidecarOp) {
	for _, op := range ops {
		if op.kind != sidecarOpDelete || op.path == "" {
			continue
		}
		if err := os.Remove(filepath.Clean(op.path)); err != nil && !errors.Is(err, os.ErrNotExist) {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warning: restored %s but could not clean up header sidecar %s: %v\n", targetPath, op.path, err)
		}
	}
}

func openCodeCommandToStrings(v interface{}) ([]string, error) {
	raw, ok := v.([]interface{})
	if !ok {
		return nil, fmt.Errorf("local server command must be an array")
	}
	out := make([]string, 0, len(raw))
	for i, item := range raw {
		s, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("local server command[%d] has non-string value of type %T", i, item)
		}
		out = append(out, s)
	}
	return out, nil
}

func buildOpenCodeEnvFlags(server map[string]interface{}) ([]string, error) {
	env, ok := server[opencodeFieldEnvironment].(map[string]interface{})
	if !ok || len(env) == 0 {
		return nil, nil
	}
	flags := make([]string, 0, len(env)*2)
	keys := make([]string, 0, len(env))
	for key := range env {
		if key == "" || strings.HasPrefix(key, "-") {
			return nil, fmt.Errorf("unsafe environment key %q cannot be passed through safely", key)
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		flags = append(flags, codexFlagEnv, key)
	}
	return flags, nil
}

func unsupportedOpenCodeRemoteAuth(server map[string]interface{}) bool {
	raw, ok := server[opencodeFieldOAuth]
	if !ok || raw == nil {
		return false
	}
	switch v := raw.(type) {
	case bool:
		return v
	case map[string]interface{}:
		return len(v) > 0
	default:
		return true
	}
}

func unmarshalOpenCodeConfig(data []byte, cfg *opencodeConfig) error {
	cleaned, err := stripJSONC(data)
	if err != nil {
		return err
	}
	return json.Unmarshal(cleaned, cfg)
}

func marshalOpenCodeConfig(originalData []byte, cfg *opencodeConfig) ([]byte, error) {
	if len(originalData) > 0 {
		cleaned, err := stripJSONC(originalData)
		if err == nil {
			var raw map[string]json.RawMessage
			if err := json.Unmarshal(cleaned, &raw); err == nil && raw != nil {
				serversJSON, err := json.Marshal(cfg.Servers)
				if err != nil {
					return nil, err
				}
				raw[opencodeServersKey] = serversJSON
				output, err := json.MarshalIndent(raw, "", "  ")
				if err != nil {
					return nil, err
				}
				return append(output, '\n'), nil
			}
		}
	}

	wrapper := map[string]interface{}{
		opencodeSchemaKey:  opencodeSchemaURL,
		opencodeServersKey: cfg.Servers,
	}
	output, err := json.MarshalIndent(wrapper, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(output, '\n'), nil
}

func stripJSONC(data []byte) ([]byte, error) {
	var out bytes.Buffer
	inString := false
	escaped := false
	for i := 0; i < len(data); i++ {
		c := data[i]
		if inString {
			out.WriteByte(c)
			if escaped {
				escaped = false
				continue
			}
			switch c {
			case '\\':
				escaped = true
			case '"':
				inString = false
			}
			continue
		}

		if c == '"' {
			inString = true
			out.WriteByte(c)
			continue
		}
		if c == '/' && i+1 < len(data) {
			switch data[i+1] {
			case '/':
				i += 2
				for i < len(data) && data[i] != '\n' && data[i] != '\r' {
					i++
				}
				if i < len(data) {
					out.WriteByte(data[i])
				}
				continue
			case '*':
				i += 2
				closed := false
				for i+1 < len(data) {
					if data[i] == '*' && data[i+1] == '/' {
						i++
						closed = true
						break
					}
					if data[i] == '\n' || data[i] == '\r' {
						out.WriteByte(data[i])
					} else {
						out.WriteByte(' ')
					}
					i++
				}
				if !closed {
					return nil, fmt.Errorf("unterminated block comment in JSONC config")
				}
				continue
			}
		}
		if c == ',' && jsonCNextSignificant(data, i+1) {
			continue
		}
		out.WriteByte(c)
	}
	if inString {
		return nil, fmt.Errorf("unterminated string in JSONC config")
	}
	return out.Bytes(), nil
}

func jsonCNextSignificant(data []byte, start int) bool {
	for i := start; i < len(data); i++ {
		switch data[i] {
		case ' ', '\t', '\n', '\r':
			continue
		case '/', '*':
			if data[i] == '/' && i+1 < len(data) {
				switch data[i+1] {
				case '/':
					i += 2
					for i < len(data) && data[i] != '\n' && data[i] != '\r' {
						i++
					}
					if i < len(data) {
						i--
					}
					continue
				case '*':
					i += 2
					for i+1 < len(data) {
						if data[i] == '*' && data[i+1] == '/' {
							i++
							break
						}
						i++
					}
					continue
				}
			}
			return false
		case ']', '}':
			return true
		default:
			return false
		}
	}
	return false
}
