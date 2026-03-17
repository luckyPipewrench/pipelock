// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/spf13/cobra"
)

// vscodeMCPConfig represents the VS Code .vscode/mcp.json file structure.
// Top-level key is "servers" (not "mcpServers" like Cursor).
// Inputs and other unknown fields are preserved via rawFields.
type vscodeMCPConfig struct {
	Inputs  json.RawMessage                   `json:"inputs,omitempty"`
	Servers map[string]map[string]interface{} `json:"servers"`
}

// pipelockMeta stores original server config for unwrapping on remove.
type pipelockMeta struct {
	OriginalType    string            `json:"original_type"`
	TypeOmitted     bool              `json:"type_omitted,omitempty"`
	OriginalCommand string            `json:"original_command,omitempty"`
	OriginalArgs    []string          `json:"original_args,omitempty"`
	OriginalURL     string            `json:"original_url,omitempty"`
	OriginalHeaders map[string]string `json:"original_headers,omitempty"`
}

func vscodeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vscode",
		Short: "VS Code integration",
		Long: `Commands for integrating pipelock with VS Code's MCP server support.

Unlike Cursor and Claude Code which use hooks, VS Code integration wraps
MCP servers through pipelock's MCP proxy. All tool calls, responses, and
descriptions are scanned bidirectionally.

The install subcommand rewrites .vscode/mcp.json to route MCP servers
through pipelock. The remove subcommand restores the original config.`,
	}

	cmd.AddCommand(
		vscodeInstallCmd(),
		vscodeRemoveCmd(),
	)

	return cmd
}

func vscodeInstallCmd() *cobra.Command {
	var (
		global     bool
		project    bool
		dryRun     bool
		configFile string
	)

	cmd := &cobra.Command{
		Use:   "install",
		Short: "Wrap VS Code MCP servers through pipelock",
		Long: `Rewrites .vscode/mcp.json to route all MCP servers through pipelock's
MCP proxy. Stdio servers get their command wrapped. HTTP/SSE servers are
converted to stdio with --upstream.

By default writes to .vscode/mcp.json in the current directory (project-level).
Use --global to write to the VS Code user-level mcp.json.

If mcp.json already exists, servers are wrapped in place. Already-wrapped
servers are skipped (idempotent). A .bak backup is created before modification.
Non-server fields (inputs, sandbox) are preserved.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runVscodeInstall(cmd, global, project, dryRun, configFile)
		},
	}

	cmd.Flags().BoolVar(&global, "global", false, "install to VS Code user-level mcp.json")
	cmd.Flags().BoolVar(&project, "project", false, "install to .vscode/mcp.json in current directory (default)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show what would be written without modifying files")
	cmd.Flags().StringVarP(&configFile, "config", "c", "", "path to pipelock config file for --config passthrough")

	return cmd
}

func vscodeRemoveCmd() *cobra.Command {
	var (
		global  bool
		project bool
		dryRun  bool
	)

	cmd := &cobra.Command{
		Use:   "remove",
		Short: "Remove pipelock wrapping from VS Code MCP servers",
		Long: `Restores .vscode/mcp.json by unwrapping servers that were wrapped by
pipelock install. Original server configurations are restored from the
_pipelock metadata field. Non-wrapped servers are left unchanged.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runVscodeRemove(cmd, global, project, dryRun)
		},
	}

	cmd.Flags().BoolVar(&global, "global", false, "remove from VS Code user-level mcp.json")
	cmd.Flags().BoolVar(&project, "project", false, "remove from .vscode/mcp.json in current directory (default)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show what would be written without modifying files")

	return cmd
}

// vscodeConfigPath returns the target mcp.json path based on flags.
func vscodeConfigPath(global bool) (string, error) {
	if global {
		return vscodeUserConfigPath()
	}
	return filepath.Join(".", ".vscode", "mcp.json"), nil
}

// vscodeUserConfigPath returns the VS Code user-level mcp.json path.
func vscodeUserConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("finding home directory: %w", err)
	}

	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "Code", "User", "mcp.json"), nil
	case "windows":
		appData := os.Getenv("APPDATA")
		if appData == "" {
			appData = filepath.Join(home, "AppData", "Roaming")
		}
		return filepath.Join(appData, "Code", "User", "mcp.json"), nil
	default: // linux, freebsd, etc.
		configDir := os.Getenv("XDG_CONFIG_HOME")
		if configDir == "" {
			configDir = filepath.Join(home, ".config")
		}
		return filepath.Join(configDir, "Code", "User", "mcp.json"), nil
	}
}

func runVscodeInstall(cmd *cobra.Command, global, project, dryRun bool, configFile string) error {
	if global && project {
		return fmt.Errorf("--global and --project are mutually exclusive")
	}

	// Default to project when no scope flag is set.
	targetPath, err := vscodeConfigPath(global)
	if err != nil {
		return err
	}

	// Find pipelock binary path.
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("finding pipelock binary: %w", err)
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return fmt.Errorf("resolving pipelock binary path: %w", err)
	}

	// Load existing mcp.json if present.
	existingData, readErr := os.ReadFile(filepath.Clean(targetPath))
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return fmt.Errorf("reading existing %s: %w", targetPath, readErr)
	}

	mcpCfg := &vscodeMCPConfig{
		Servers: make(map[string]map[string]interface{}),
	}
	if readErr == nil && len(existingData) > 0 {
		if err := json.Unmarshal(existingData, mcpCfg); err != nil {
			return fmt.Errorf("parsing %s: %w", targetPath, err)
		}
		if mcpCfg.Servers == nil {
			mcpCfg.Servers = make(map[string]map[string]interface{})
		}
	}

	// Wrap each server through pipelock.
	wrapped := 0
	skipped := 0
	for name, server := range mcpCfg.Servers {
		if isVscodeWrapped(server) {
			skipped++
			continue
		}

		newServer, meta, err := wrapVscodeServer(server, exe, configFile)
		if err != nil {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warning: skipping server %q: %v\n", name, err)
			continue
		}

		// Store metadata for unwrapping.
		metaJSON, err := json.Marshal(meta)
		if err != nil {
			return fmt.Errorf("marshaling metadata for %q: %w", name, err)
		}
		var metaMap interface{}
		_ = json.Unmarshal(metaJSON, &metaMap)
		newServer["_pipelock"] = metaMap

		mcpCfg.Servers[name] = newServer
		wrapped++
	}

	// Marshal result, preserving unknown top-level fields.
	output, err := marshalVscodeConfig(existingData, mcpCfg)
	if err != nil {
		return fmt.Errorf("marshaling mcp.json: %w", err)
	}

	if dryRun {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Would write to %s (%d wrapped, %d already wrapped):\n%s", targetPath, wrapped, skipped, output)
		return nil
	}

	// Create directory if needed.
	targetDir := filepath.Dir(targetPath)
	if err := os.MkdirAll(targetDir, 0o750); err != nil {
		return fmt.Errorf("creating directory %s: %w", targetDir, err)
	}

	// Backup existing file.
	if readErr == nil {
		if err := os.WriteFile(targetPath+".bak", existingData, 0o600); err != nil {
			return fmt.Errorf("creating backup: %w", err)
		}
	}

	// Atomic write.
	if err := vscodeAtomicWrite(targetPath, output, targetDir); err != nil {
		return err
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Wrapped %d server(s) in %s (%d already wrapped)\n", wrapped, targetPath, skipped)
	if wrapped > 0 {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Restart VS Code to activate pipelock scanning.\n")
	}
	return nil
}

func runVscodeRemove(cmd *cobra.Command, global, project, dryRun bool) error {
	if global && project {
		return fmt.Errorf("--global and --project are mutually exclusive")
	}

	targetPath, err := vscodeConfigPath(global)
	if err != nil {
		return err
	}

	existingData, err := os.ReadFile(filepath.Clean(targetPath))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "No mcp.json found at %s\n", targetPath)
			return nil
		}
		return fmt.Errorf("reading %s: %w", targetPath, err)
	}

	mcpCfg := &vscodeMCPConfig{
		Servers: make(map[string]map[string]interface{}),
	}
	if err := json.Unmarshal(existingData, mcpCfg); err != nil {
		return fmt.Errorf("parsing %s: %w", targetPath, err)
	}

	unwrapped := 0
	for name, server := range mcpCfg.Servers {
		if !isVscodeWrapped(server) {
			continue
		}

		restored, err := unwrapVscodeServer(server)
		if err != nil {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warning: could not unwrap %q: %v\n", name, err)
			continue
		}

		mcpCfg.Servers[name] = restored
		unwrapped++
	}

	output, err := marshalVscodeConfig(existingData, mcpCfg)
	if err != nil {
		return fmt.Errorf("marshaling mcp.json: %w", err)
	}

	if dryRun {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Would write to %s (%d unwrapped):\n%s", targetPath, unwrapped, output)
		return nil
	}

	// Backup.
	if err := os.WriteFile(targetPath+".bak", existingData, 0o600); err != nil {
		return fmt.Errorf("creating backup: %w", err)
	}

	targetDir := filepath.Dir(targetPath)
	if err := vscodeAtomicWrite(targetPath, output, targetDir); err != nil {
		return err
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Unwrapped %d server(s) in %s\n", unwrapped, targetPath)
	if unwrapped > 0 {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Restart VS Code to apply changes.\n")
	}
	return nil
}

// VS Code MCP server type constants.
const (
	vscodeTypeStdio = "stdio"
	vscodeTypeHTTP  = "http"
	vscodeTypeSSE   = "sse"
)

// isVscodeWrapped returns true if a server entry has pipelock metadata.
func isVscodeWrapped(server map[string]interface{}) bool {
	_, ok := server["_pipelock"]
	return ok
}

// wrapVscodeServer wraps a single VS Code MCP server through pipelock mcp proxy.
func wrapVscodeServer(server map[string]interface{}, exe, configFile string) (map[string]interface{}, *pipelockMeta, error) {
	serverType, _ := server["type"].(string)
	typeOmitted := serverType == ""
	if typeOmitted {
		serverType = vscodeTypeStdio // VS Code defaults to stdio when type is omitted.
	}

	// VS Code mcp.json separates command and args, so use the raw path.
	// Unlike Cursor hooks (shell command string), no shell quoting needed.
	result := make(map[string]interface{})

	// Copy all fields except command/args/url/headers/type (we replace those).
	for k, v := range server {
		switch k {
		case "command", "args", "url", "headers", "type":
			// Replaced below.
		default:
			result[k] = v
		}
	}

	meta := &pipelockMeta{OriginalType: serverType, TypeOmitted: typeOmitted}

	switch serverType {
	case vscodeTypeStdio:
		originalCmd, _ := server["command"].(string)
		if originalCmd == "" {
			return nil, nil, fmt.Errorf("stdio server missing command")
		}
		originalArgs := interfaceSliceToStrings(server["args"])

		meta.OriginalCommand = originalCmd
		meta.OriginalArgs = originalArgs

		args := []string{"mcp", "proxy"}
		if configFile != "" {
			args = append(args, "--config", configFile)
		}
		args = append(args, "--")
		args = append(args, originalCmd)
		args = append(args, originalArgs...)

		result["type"] = vscodeTypeStdio
		result["command"] = exe
		result["args"] = args

	case vscodeTypeHTTP, vscodeTypeSSE:
		originalURL, _ := server["url"].(string)
		if originalURL == "" {
			return nil, nil, fmt.Errorf("%s server missing url", serverType)
		}

		meta.OriginalURL = originalURL
		if headers, ok := server["headers"].(map[string]interface{}); ok {
			meta.OriginalHeaders = make(map[string]string, len(headers))
			for k, v := range headers {
				meta.OriginalHeaders[k] = fmt.Sprint(v)
			}
		}

		args := []string{"mcp", "proxy"}
		if configFile != "" {
			args = append(args, "--config", configFile)
		}
		args = append(args, "--upstream", originalURL)

		result["type"] = vscodeTypeStdio
		result["command"] = exe
		result["args"] = args

	default:
		return nil, nil, fmt.Errorf("unsupported server type %q", serverType)
	}

	return result, meta, nil
}

// unwrapVscodeServer restores a server from its pipelock metadata.
func unwrapVscodeServer(server map[string]interface{}) (map[string]interface{}, error) {
	metaRaw, ok := server["_pipelock"]
	if !ok {
		return server, nil
	}

	// Marshal and unmarshal to get a typed struct.
	metaJSON, err := json.Marshal(metaRaw)
	if err != nil {
		return nil, fmt.Errorf("reading _pipelock metadata: %w", err)
	}
	var meta pipelockMeta
	if err := json.Unmarshal(metaJSON, &meta); err != nil {
		return nil, fmt.Errorf("parsing _pipelock metadata: %w", err)
	}

	result := make(map[string]interface{})

	// Copy fields that aren't replaced by restore.
	for k, v := range server {
		switch k {
		case "command", "args", "url", "headers", "type", "_pipelock":
			// Replaced/removed below.
		default:
			result[k] = v
		}
	}

	// Only set type if the original config had it explicitly.
	if !meta.TypeOmitted {
		result["type"] = meta.OriginalType
	}

	switch meta.OriginalType {
	case vscodeTypeStdio:
		result["command"] = meta.OriginalCommand
		if len(meta.OriginalArgs) > 0 {
			result["args"] = meta.OriginalArgs
		}
	case vscodeTypeHTTP, vscodeTypeSSE:
		result["url"] = meta.OriginalURL
		if len(meta.OriginalHeaders) > 0 {
			headers := make(map[string]interface{}, len(meta.OriginalHeaders))
			for k, v := range meta.OriginalHeaders {
				headers[k] = v
			}
			result["headers"] = headers
		}
	}

	return result, nil
}

// interfaceSliceToStrings converts []interface{} (from JSON unmarshal) to []string.
func interfaceSliceToStrings(v interface{}) []string {
	slice, ok := v.([]interface{})
	if !ok {
		return nil
	}
	result := make([]string, 0, len(slice))
	for _, item := range slice {
		if s, ok := item.(string); ok {
			result = append(result, s)
		}
	}
	return result
}

// marshalVscodeConfig marshals the mcp config while preserving unknown
// top-level fields from the original file data.
func marshalVscodeConfig(originalData []byte, cfg *vscodeMCPConfig) ([]byte, error) {
	// If we have original data, preserve unknown top-level fields.
	if len(originalData) > 0 {
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(originalData, &raw); err == nil {
			// Update servers.
			serversJSON, err := json.Marshal(cfg.Servers)
			if err != nil {
				return nil, err
			}
			raw["servers"] = serversJSON

			// Update inputs if present in our config.
			if cfg.Inputs != nil {
				raw["inputs"] = cfg.Inputs
			}

			output, err := json.MarshalIndent(raw, "", "  ")
			if err != nil {
				return nil, err
			}
			return append(output, '\n'), nil
		}
	}

	// No original data or parse failed: marshal from scratch.
	output, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(output, '\n'), nil
}

// vscodeAtomicWrite writes data to targetPath via temp file + rename.
func vscodeAtomicWrite(targetPath string, data []byte, tmpDir string) error {
	tmpFile, err := os.CreateTemp(tmpDir, "mcp-*.json.tmp")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpPath := tmpFile.Name()

	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("writing temp file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("closing temp file: %w", err)
	}

	if err := os.Chmod(tmpPath, 0o600); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("setting permissions: %w", err)
	}

	if err := os.Rename(tmpPath, targetPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("renaming to %s: %w", targetPath, err)
	}

	return nil
}
