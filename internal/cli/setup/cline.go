// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

// Cline integration wraps the MCP servers declared in Cline's mcp.json file
// so that every tool call, response, and description is scanned bidirectionally
// by pipelock. Cline is MCP-native rather than hook-based, so the install
// rewrites the config file in place. Unlike VS Code's mcp.json (which uses a
// "servers" top-level key and a per-server "type" field), Cline uses
// "mcpServers" and infers the transport from the presence of "command" or
// "url". The wrap stores the original entry in a _pipelock metadata field so
// remove can restore the config byte-for-byte for any unwrapped fields.

const (
	clineConfigFilename = "mcp.json"
	clineConfigDirname  = ".cline"
	clineServersKey     = "mcpServers"
	clineHTTPProbeType  = "http"
)

// clineMCPConfig represents Cline's mcp.json file. Unknown top-level fields
// are preserved through the raw-map roundtrip in marshalClineConfig.
type clineMCPConfig struct {
	Servers map[string]map[string]interface{} `json:"mcpServers"`
}

// ClineCmd returns the `pipelock cline` command tree.
func ClineCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cline",
		Short: "Cline integration",
		Long: `Commands for integrating pipelock with Cline's MCP server support.

Cline is MCP-native rather than hook-based, so install rewrites the
mcp.json file so that every server runs through pipelock's MCP proxy.
All tool calls, responses, and descriptions are scanned bidirectionally.

The install subcommand rewrites mcp.json to route MCP servers through
pipelock. The remove subcommand restores the original config from the
_pipelock metadata field. Both commands are idempotent.`,
	}

	cmd.AddCommand(
		clineInstallCmd(),
		clineRemoveCmd(),
	)

	return cmd
}

func clineInstallCmd() *cobra.Command {
	var (
		path       string
		dryRun     bool
		configFile string
	)

	cmd := &cobra.Command{
		Use:   "install",
		Short: "Wrap Cline MCP servers through pipelock",
		Long: `Rewrites Cline's mcp.json to route all MCP servers through pipelock's
MCP proxy. Stdio servers (entries with "command") get their command
wrapped. Remote servers (entries with "url") are converted to stdio with
--upstream and a synthetic "type" hint that is removed on unwrap.

By default writes to ~/.cline/mcp.json. Use --path to point at a different
file, for example the VS Code extension's settings file under the user's
globalStorage directory.

If mcp.json already exists, servers are wrapped in place. Already-wrapped
servers are skipped (idempotent). A .bak backup is created before
modification. Non-server fields are preserved.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runClineInstall(cmd, path, dryRun, configFile)
		},
	}

	cmd.Flags().StringVar(&path, "path", "", "path to mcp.json (default ~/.cline/mcp.json)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show what would be written without modifying files")
	cmd.Flags().StringVarP(&configFile, "config", "c", "", "path to pipelock config file for --config passthrough")

	return cmd
}

func clineRemoveCmd() *cobra.Command {
	var (
		path   string
		dryRun bool
	)

	cmd := &cobra.Command{
		Use:   "remove",
		Short: "Remove pipelock wrapping from Cline MCP servers",
		Long: `Restores Cline's mcp.json by unwrapping servers that were wrapped by
pipelock install. Original server configurations are restored from the
_pipelock metadata field. Non-wrapped servers are left unchanged.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runClineRemove(cmd, path, dryRun)
		},
	}

	cmd.Flags().StringVar(&path, "path", "", "path to mcp.json (default ~/.cline/mcp.json)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show what would be written without modifying files")

	return cmd
}

// clineConfigPath returns the target mcp.json path, defaulting to
// ~/.cline/mcp.json when the operator did not supply an override.
func clineConfigPath(override string) (string, error) {
	if override != "" {
		return override, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("finding home directory: %w", err)
	}
	return filepath.Join(home, clineConfigDirname, clineConfigFilename), nil
}

func runClineInstall(cmd *cobra.Command, override string, dryRun bool, configFile string) error {
	targetPath, err := clineConfigPath(override)
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

	configFile = discoverConfigForWrap(cmd, configFile)

	existingData, readErr := os.ReadFile(filepath.Clean(targetPath))
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return fmt.Errorf("reading existing %s: %w", targetPath, readErr)
	}

	mcpCfg := &clineMCPConfig{Servers: make(map[string]map[string]interface{})}
	if readErr == nil && len(existingData) > 0 {
		if err := json.Unmarshal(existingData, mcpCfg); err != nil {
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

		newServer, meta, plan, err := wrapClineServer(server, exe, configFile, targetPath, name)
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

	output, err := marshalClineConfig(existingData, mcpCfg)
	if err != nil {
		return fmt.Errorf("marshaling %s: %w", clineConfigFilename, err)
	}

	if dryRun {
		// Dry-run is read-only: do not write the canonical config AND do not
		// write any sidecar.
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

	// Sidecars are written FIRST so a sidecar failure leaves the operator's
	// config untouched. applySidecarOps internally rolls back any partial
	// writes if one of the writes fails partway through the plan.
	if err := applySidecarOps(sidecarOps); err != nil {
		return fmt.Errorf("writing header sidecar: %w", err)
	}

	// Atomic write of the canonical config. If this fails, the sidecars
	// we just wrote would orphan to a config file that has no reference
	// to them, so we clean them up before returning the error.
	if err := vscodeAtomicWrite(targetPath, output, targetDir); err != nil {
		rollbackSidecarWrites(sidecarOps)
		return err
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Wrapped %d server(s) in %s (%d already wrapped)\n", wrapped, targetPath, skipped)
	if wrapped > 0 {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Restart Cline to activate pipelock scanning.\n")
	}
	return nil
}

func runClineRemove(cmd *cobra.Command, override string, dryRun bool) error {
	targetPath, err := clineConfigPath(override)
	if err != nil {
		return err
	}

	existingData, err := os.ReadFile(filepath.Clean(targetPath))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "No %s found at %s\n", clineConfigFilename, targetPath)
			return nil
		}
		return fmt.Errorf("reading %s: %w", targetPath, err)
	}

	mcpCfg := &clineMCPConfig{Servers: make(map[string]map[string]interface{})}
	if err := json.Unmarshal(existingData, mcpCfg); err != nil {
		return fmt.Errorf("parsing %s: %w", targetPath, err)
	}

	unwrapped := 0
	var sidecarOps []sidecarOp
	for name, server := range mcpCfg.Servers {
		if !isVscodeWrapped(server) {
			continue
		}

		restored, plan, err := unwrapVscodeServer(server)
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

	output, err := marshalClineConfig(existingData, mcpCfg)
	if err != nil {
		return fmt.Errorf("marshaling %s: %w", clineConfigFilename, err)
	}

	if dryRun {
		// Dry-run is read-only: do not delete the sidecars referenced by the
		// still-wrapped on-disk config.
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

	// Sidecars are deleted only after the restored config is committed to
	// disk. Earlier failures leave the wrapped config and its sidecars in
	// place so the operator can retry.
	_ = applySidecarOps(sidecarOps)

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Unwrapped %d server(s) in %s\n", unwrapped, targetPath)
	if unwrapped > 0 {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Restart Cline to apply changes.\n")
	}
	return nil
}

// wrapClineServer wraps a single Cline MCP server entry through pipelock mcp
// proxy. Cline omits the "type" field, so we infer the transport from the
// presence of "url" before delegating to wrapVscodeServer, then mark
// TypeOmitted=true on the returned metadata so remove restores a Cline-shaped
// entry rather than a VS Code-shaped one. Like wrapVscodeServer, this is pure
// with respect to the filesystem: the returned sidecarOp (if non-nil) is the
// caller's responsibility to apply only after the canonical config write
// succeeds.
func wrapClineServer(server map[string]interface{}, exe, configFile, targetConfigPath, serverName string) (map[string]interface{}, *pipelockMeta, *sidecarOp, error) {
	_, hasCommand := server[mcpFieldCommand]
	_, hasURL := server[mcpFieldURL]
	if hasCommand && hasURL {
		return nil, nil, nil, fmt.Errorf("server has both command and url")
	}

	if _, hasType := server[mcpFieldType]; hasType {
		// Operator explicitly set a type. Treat exactly like the VS Code path,
		// preserving the type on unwrap.
		return wrapVscodeServer(server, exe, configFile, targetConfigPath, serverName)
	}

	if hasCommand {
		// Stdio server with no type field: wrapVscodeServer's default branch
		// (typeOmitted -> stdio) already produces the right output and the
		// right TypeOmitted=true metadata. No extra work needed.
		return wrapVscodeServer(server, exe, configFile, targetConfigPath, serverName)
	}

	if hasURL {
		// Remote server with no type field. Pre-mutate to satisfy wrap's
		// dispatch, then force TypeOmitted=true on the returned metadata so
		// remove does not write a type field back into the Cline entry.
		probe := make(map[string]interface{}, len(server)+1)
		for k, v := range server {
			probe[k] = v
		}
		probe[mcpFieldType] = clineHTTPProbeType

		result, meta, plan, err := wrapVscodeServer(probe, exe, configFile, targetConfigPath, serverName)
		if err != nil {
			return nil, nil, nil, err
		}
		meta.TypeOmitted = true
		return result, meta, plan, nil
	}

	return nil, nil, nil, fmt.Errorf("server has neither command nor url")
}

// marshalClineConfig marshals the Cline mcp.json while preserving unknown
// top-level fields from the original file data.
func marshalClineConfig(originalData []byte, cfg *clineMCPConfig) ([]byte, error) {
	if len(originalData) > 0 {
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(originalData, &raw); err == nil {
			serversJSON, err := json.Marshal(cfg.Servers)
			if err != nil {
				return nil, err
			}
			raw[clineServersKey] = serversJSON
			output, err := json.MarshalIndent(raw, "", "  ")
			if err != nil {
				return nil, err
			}
			return append(output, '\n'), nil
		}
	}

	output, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(output, '\n'), nil
}
