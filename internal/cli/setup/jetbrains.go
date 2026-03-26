// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

func JetbrainsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "jetbrains",
		Short: "JetBrains IDE integration",
		Long: `Commands for integrating pipelock with JetBrains IDE MCP server support.

Wraps Junie MCP server configurations through pipelock's MCP proxy for
bidirectional scanning of all tool calls, responses, and descriptions.

The install subcommand rewrites mcp.json to route MCP servers through
pipelock. The remove subcommand restores the original config.

Supports both project-level (.junie/mcp/mcp.json) and user-level
(~/.junie/mcp/mcp.json) configurations.`,
	}

	cmd.AddCommand(
		jetbrainsInstallCmd(),
		jetbrainsRemoveCmd(),
	)

	return cmd
}

func jetbrainsInstallCmd() *cobra.Command {
	var (
		global     bool
		project    bool
		dryRun     bool
		configFile string
		sandbox    bool
		workspace  string
	)

	cmd := &cobra.Command{
		Use:   "install",
		Short: "Wrap JetBrains MCP servers through pipelock",
		Long: `Rewrites Junie mcp.json to route all MCP servers through pipelock's
MCP proxy. Stdio servers get their command wrapped. HTTP/SSE servers without
custom headers are converted to stdio with --upstream. HTTP/SSE servers with
headers (e.g. Authorization) are skipped with a warning since header
passthrough is not yet supported.

By default writes to ~/.junie/mcp/mcp.json (user-level, visible to pipelock discover).
Use --project to write to .junie/mcp/mcp.json in the current directory instead.

If mcp.json already exists, servers are wrapped in place. Already-wrapped
servers are skipped (idempotent). A .bak backup is created before modification.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runJetbrainsInstall(cmd, global, project, dryRun, configFile, sandbox, workspace)
		},
	}

	cmd.Flags().BoolVar(&global, "global", false, "install to user-level ~/.junie/mcp/mcp.json (default)")
	cmd.Flags().BoolVar(&project, "project", false, "install to .junie/mcp/mcp.json in current directory")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show what would be written without modifying files")
	cmd.Flags().StringVarP(&configFile, "config", "c", "", "path to pipelock config file for --config passthrough")
	cmd.Flags().BoolVar(&sandbox, "sandbox", false, "enable sandbox mode for wrapped MCP servers")
	cmd.Flags().StringVar(&workspace, "workspace", "", "workspace path for sandbox mode")

	return cmd
}

func jetbrainsRemoveCmd() *cobra.Command {
	var (
		global  bool
		project bool
		dryRun  bool
	)

	cmd := &cobra.Command{
		Use:   "remove",
		Short: "Remove pipelock wrapping from JetBrains MCP servers",
		Long: `Restores Junie mcp.json by unwrapping servers that were wrapped by
pipelock install. Original server configurations are restored from the
_pipelock metadata field. Non-wrapped servers are left unchanged.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runJetbrainsRemove(cmd, global, project, dryRun)
		},
	}

	cmd.Flags().BoolVar(&global, "global", false, "remove from user-level ~/.junie/mcp/mcp.json (default)")
	cmd.Flags().BoolVar(&project, "project", false, "remove from .junie/mcp/mcp.json in current directory")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show what would be written without modifying files")

	return cmd
}

// junieServersKey is the JSON key for MCP servers in Junie config files.
const junieServersKey = "mcpServers"

// junieConfigPath returns the target mcp.json path based on scope flags.
func junieConfigPath(global bool) (string, error) {
	if global {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("finding home directory: %w", err)
		}
		return filepath.Join(home, ".junie", "mcp", "mcp.json"), nil
	}
	return filepath.Join(".", ".junie", "mcp", "mcp.json"), nil
}

func runJetbrainsInstall(cmd *cobra.Command, global, project, dryRun bool, configFile string, sandbox bool, workspace string) error {
	if global && project {
		return fmt.Errorf("--global and --project are mutually exclusive")
	}

	// Default to global (user-level) when neither flag is set.
	// This ensures the default install target is visible to pipelock discover.
	useGlobal := global || !project
	targetPath, err := junieConfigPath(useGlobal)
	if err != nil {
		return err
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("finding pipelock binary: %w", err)
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return fmt.Errorf("resolving pipelock binary path: %w", err)
	}

	cfg, originalData, err := readMCPConfig(targetPath, junieServersKey)
	if err != nil {
		return err
	}

	wrapped := 0
	skipped := 0
	for name, server := range cfg.Servers {
		if isWrapped(server) {
			skipped++
			continue
		}

		newServer, meta, err := wrapMCPServer(server, exe, configFile, sandbox, workspace)
		if err != nil {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warning: skipping server %q: %v\n", name, err)
			continue
		}

		metaJSON, err := json.Marshal(meta)
		if err != nil {
			return fmt.Errorf("marshaling metadata for %q: %w", name, err)
		}
		var metaMap interface{}
		_ = json.Unmarshal(metaJSON, &metaMap)
		newServer["_pipelock"] = metaMap

		cfg.Servers[name] = newServer
		wrapped++
	}

	output, err := marshalMCPConfig(originalData, cfg, junieServersKey)
	if err != nil {
		return fmt.Errorf("marshaling mcp.json: %w", err)
	}

	if dryRun {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Would write to %s (%d wrapped, %d already wrapped):\n%s", targetPath, wrapped, skipped, output)
		return nil
	}

	targetDir := filepath.Dir(targetPath)
	if err := os.MkdirAll(targetDir, 0o750); err != nil {
		return fmt.Errorf("creating directory %s: %w", targetDir, err)
	}

	if originalData != nil {
		// File exists — use atomic write with backup.
		if err := atomicWriteFile(targetPath, output, true); err != nil {
			return err
		}
	} else {
		// New file — write directly.
		if err := os.WriteFile(targetPath, output, 0o600); err != nil {
			return fmt.Errorf("writing %s: %w", targetPath, err)
		}
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Wrapped %d server(s) in %s (%d already wrapped)\n", wrapped, targetPath, skipped)
	if wrapped > 0 {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Restart your JetBrains IDE to activate pipelock scanning.\n")
	}
	return nil
}

func runJetbrainsRemove(cmd *cobra.Command, global, project, dryRun bool) error {
	if global && project {
		return fmt.Errorf("--global and --project are mutually exclusive")
	}

	useGlobal := global || !project
	targetPath, err := junieConfigPath(useGlobal)
	if err != nil {
		return err
	}

	cfg, originalData, err := readMCPConfig(targetPath, junieServersKey)
	if err != nil {
		return err
	}
	if originalData == nil {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "No mcp.json found at %s\n", targetPath)
		return nil
	}

	unwrapped := 0
	for name, server := range cfg.Servers {
		if !isWrapped(server) {
			continue
		}

		restored, err := unwrapMCPServer(server)
		if err != nil {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warning: could not unwrap %q: %v\n", name, err)
			continue
		}

		cfg.Servers[name] = restored
		unwrapped++
	}

	output, err := marshalMCPConfig(originalData, cfg, junieServersKey)
	if err != nil {
		return fmt.Errorf("marshaling mcp.json: %w", err)
	}

	if dryRun {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Would write to %s (%d unwrapped):\n%s", targetPath, unwrapped, output)
		return nil
	}

	if err := atomicWriteFile(targetPath, output, true); err != nil {
		return err
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Unwrapped %d server(s) in %s\n", unwrapped, targetPath)
	if unwrapped > 0 {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Restart your JetBrains IDE to apply changes.\n")
	}
	return nil
}
