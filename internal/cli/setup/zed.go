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

// Zed integration wraps the MCP servers declared in Zed's settings.json
// `context_servers` block so that every tool call, response, and description
// is scanned bidirectionally by pipelock. Zed's MCP config shape is identical
// to Cline's (no `type` field; transport inferred from `command` vs `url`),
// so the install path delegates to wrapClineServer. What is unique is that
// Zed supports two settings.json locations simultaneously: a user-level file
// (~/.config/zed/settings.json, honoring $XDG_CONFIG_HOME) and a project-level
// file (<project>/.zed/settings.json). The installer scans both by default so
// an operator's project MCP servers and global MCP servers are wrapped in one
// command. Use --path to operate on a single explicit file (parity with the
// other installers).

const (
	zedConfigFilename   = "settings.json"
	zedUserConfigSubdir = "zed"
	zedProjectConfigDir = ".zed"
	zedServersKey       = "context_servers"
	zedDefaultConfigDir = ".config" // joined under HOME when XDG_CONFIG_HOME is unset
)

// ZedCmd returns the `pipelock zed` command tree.
func ZedCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "zed",
		Short: "Zed integration",
		Long: `Commands for integrating pipelock with Zed's MCP context_servers support.

Zed is MCP-native, so install rewrites the settings.json file so that every
context server runs through pipelock's MCP proxy. All tool calls, responses,
and descriptions are scanned bidirectionally.

By default install scans both the user-level settings.json
($XDG_CONFIG_HOME/zed/settings.json or ~/.config/zed/settings.json) and the
project-level .zed/settings.json in the current directory, wrapping every
existing file. Use --path to target a single explicit file.

The install subcommand rewrites settings.json to route MCP servers through
pipelock. The remove subcommand restores the original config from the
_pipelock metadata field. Both commands are idempotent.`,
	}

	cmd.AddCommand(
		zedInstallCmd(),
		zedRemoveCmd(),
	)

	return cmd
}

func zedInstallCmd() *cobra.Command {
	var (
		path       string
		dryRun     bool
		configFile string
	)

	cmd := &cobra.Command{
		Use:   "install",
		Short: "Wrap Zed context_servers through pipelock",
		Long: `Rewrites Zed's settings.json to route all context_servers through
pipelock's MCP proxy. Stdio servers (entries with "command") get their
command wrapped. Remote servers (entries with "url") are converted to
stdio with --upstream. Header values, if present, land in a 0o600
header sidecar file referenced via --header-file so secrets never
appear in /proc/<pid>/cmdline.

Default discovery scans both:
  - $XDG_CONFIG_HOME/zed/settings.json (or ~/.config/zed/settings.json)
  - <cwd>/.zed/settings.json

Each file that exists is wrapped independently with its own .bak backup.
If neither exists, install prints a friendly hint and exits 0. Use --path
to target a single specific file, in which case the file is created if
it does not exist (matching the behavior of pipelock cline install).

Already-wrapped servers are skipped (idempotent). Non-server top-level
fields in settings.json are preserved byte-for-byte.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runZedInstall(cmd, path, dryRun, configFile)
		},
	}

	cmd.Flags().StringVar(&path, "path", "", "single settings.json to operate on (default: scan user + project)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show what would be written without modifying files")
	cmd.Flags().StringVarP(&configFile, "config", "c", "", "path to pipelock config file for --config passthrough")

	return cmd
}

func zedRemoveCmd() *cobra.Command {
	var (
		path   string
		dryRun bool
	)

	cmd := &cobra.Command{
		Use:   "remove",
		Short: "Remove pipelock wrapping from Zed context_servers",
		Long: `Restores Zed's settings.json by unwrapping context_servers that were
wrapped by pipelock install. Original server configurations are restored
from the _pipelock metadata field. Non-wrapped servers are left unchanged.

Default discovery is the same as install. Use --path to target a single
specific file.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runZedRemove(cmd, path, dryRun)
		},
	}

	cmd.Flags().StringVar(&path, "path", "", "single settings.json to operate on (default: scan user + project)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show what would be written without modifying files")

	return cmd
}

// zedUserConfigPath returns the user-level settings.json location, honoring
// $XDG_CONFIG_HOME when set. Zed uses the same path on Linux and macOS per
// Zed's official docs (https://zed.dev/docs/configuring-zed): the legacy
// macOS path under ~/Library/Application Support is not the current default.
func zedUserConfigPath() (string, error) {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, zedUserConfigSubdir, zedConfigFilename), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("finding home directory: %w", err)
	}
	return filepath.Join(home, zedDefaultConfigDir, zedUserConfigSubdir, zedConfigFilename), nil
}

// zedProjectConfigPath returns <cwd>/.zed/settings.json. The path is always
// returned (even when the file does not exist); callers decide whether to
// act on it. Returning an error here would mean "I cannot derive the path,"
// which is different from "the path is derivable but the file is absent".
func zedProjectConfigPath() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("finding current directory: %w", err)
	}
	return filepath.Join(cwd, zedProjectConfigDir, zedConfigFilename), nil
}

// zedDiscoveryResult describes the outcome of resolving install/remove
// targets. existingPaths is the subset of candidatePaths that exist on disk
// and is what install/remove actually operate on in default-discovery mode.
type zedDiscoveryResult struct {
	candidatePaths []string
	existingPaths  []string
}

// resolveZedTargets returns the paths the command should operate on. When
// override is set, only that path is returned (and is treated as required,
// even if missing — install creates it, remove no-ops on it). When override
// is empty, both default paths are probed; only the ones that exist are
// returned in existingPaths, but candidatePaths always carries both so the
// "no settings.json found" message can name what was looked for.
func resolveZedTargets(override string) (zedDiscoveryResult, error) {
	if override != "" {
		clean := filepath.Clean(override)
		return zedDiscoveryResult{
			candidatePaths: []string{clean},
			existingPaths:  []string{clean},
		}, nil
	}

	user, err := zedUserConfigPath()
	if err != nil {
		return zedDiscoveryResult{}, err
	}
	project, err := zedProjectConfigPath()
	if err != nil {
		return zedDiscoveryResult{}, err
	}

	// Order: project first so that when both exist the more-specific scope
	// is processed (and shown in output) before the broader scope.
	candidates := []string{project, user}
	existing := make([]string, 0, len(candidates))
	for _, p := range candidates {
		info, statErr := os.Stat(p)
		if statErr != nil {
			if errors.Is(statErr, os.ErrNotExist) {
				continue
			}
			return zedDiscoveryResult{}, fmt.Errorf("checking Zed settings path %s: %w", p, statErr)
		}
		if info.IsDir() {
			continue
		}
		existing = append(existing, p)
	}

	return zedDiscoveryResult{
		candidatePaths: candidates,
		existingPaths:  existing,
	}, nil
}

func runZedInstall(cmd *cobra.Command, override string, dryRun bool, configFile string) error {
	targets, err := resolveZedTargets(override)
	if err != nil {
		return err
	}
	paths := targets.existingPaths
	if override == "" && len(paths) == 0 {
		// Default discovery with neither file present: name what was looked
		// for so the operator can decide whether to point --path at a custom
		// location or to bootstrap one of the defaults.
		_, _ = fmt.Fprintf(cmd.OutOrStdout(),
			"No Zed settings.json found at any default location:\n  %s\n  %s\nRun `pipelock zed install --path <file>` to create one explicitly.\n",
			targets.candidatePaths[0], targets.candidatePaths[1])
		return nil
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

	for _, targetPath := range paths {
		if err := installZedPath(cmd, targetPath, exe, configFile, dryRun); err != nil {
			return err
		}
	}
	return nil
}

func installZedPath(cmd *cobra.Command, targetPath, exe, configFile string, dryRun bool) error {
	cfg, existingData, parseErr := readZedConfig(targetPath)
	if parseErr != nil {
		return parseErr
	}

	wrapped := 0
	skipped := 0
	var sidecarOps []sidecarOp
	for name, server := range cfg.Servers {
		if isWrapped(server) {
			skipped++
			continue
		}

		newServer, meta, plan, wrapErr := wrapClineServer(server, exe, configFile, targetPath, name)
		if wrapErr != nil {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warning: skipping server %q in %s: %v\n", name, targetPath, wrapErr)
			continue
		}

		metaJSON, err := json.Marshal(meta)
		if err != nil {
			return fmt.Errorf("marshaling metadata for %q in %s: %w", name, targetPath, err)
		}
		var metaMap interface{}
		if err := json.Unmarshal(metaJSON, &metaMap); err != nil {
			return fmt.Errorf("unmarshaling metadata for %q in %s: %w", name, targetPath, err)
		}
		newServer[mcpFieldPipelock] = metaMap

		cfg.Servers[name] = newServer
		if plan != nil {
			sidecarOps = append(sidecarOps, *plan)
		}
		wrapped++
	}

	output, err := marshalMCPConfig(existingData, cfg, zedServersKey)
	if err != nil {
		return fmt.Errorf("marshaling %s: %w", targetPath, err)
	}

	if dryRun {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(),
			"Would write to %s (%d wrapped, %d already wrapped):\n%s",
			targetPath, wrapped, skipped, output)
		return nil
	}

	targetDir := filepath.Dir(targetPath)
	if err := os.MkdirAll(targetDir, 0o750); err != nil {
		return fmt.Errorf("creating directory %s: %w", targetDir, err)
	}

	if len(existingData) > 0 {
		if err := os.WriteFile(targetPath+".bak", existingData, 0o600); err != nil {
			return fmt.Errorf("creating backup: %w", err)
		}
	}

	// Sidecars first so a sidecar failure leaves the operator's config
	// untouched; applySidecarOps rolls back partial writes internally.
	if err := applySidecarOps(sidecarOps); err != nil {
		return fmt.Errorf("writing header sidecar: %w", err)
	}

	if err := vscodeAtomicWrite(targetPath, output, targetDir); err != nil {
		rollbackSidecarWrites(sidecarOps)
		return err
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(),
		"Wrapped %d server(s) in %s (%d already wrapped)\n",
		wrapped, targetPath, skipped)
	if wrapped > 0 {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Restart Zed to activate pipelock scanning.\n")
	}
	return nil
}

func runZedRemove(cmd *cobra.Command, override string, dryRun bool) error {
	targets, err := resolveZedTargets(override)
	if err != nil {
		return err
	}
	paths := targets.existingPaths
	if override == "" && len(paths) == 0 {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(),
			"No Zed settings.json found at any default location:\n  %s\n  %s\n",
			targets.candidatePaths[0], targets.candidatePaths[1])
		return nil
	}

	for _, targetPath := range paths {
		if err := removeZedPath(cmd, targetPath, dryRun); err != nil {
			return err
		}
	}
	return nil
}

func removeZedPath(cmd *cobra.Command, targetPath string, dryRun bool) error {
	cfg, existingData, parseErr := readZedConfig(targetPath)
	if parseErr != nil {
		return parseErr
	}
	if len(existingData) == 0 {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "No %s found at %s\n", zedConfigFilename, targetPath)
		return nil
	}

	unwrapped := 0
	var sidecarOps []sidecarOp
	for name, server := range cfg.Servers {
		if !isWrapped(server) {
			continue
		}

		restored, plan, unwrapErr := unwrapVscodeServer(server)
		if unwrapErr != nil {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warning: could not unwrap %q in %s: %v\n", name, targetPath, unwrapErr)
			continue
		}

		cfg.Servers[name] = restored
		if plan != nil {
			sidecarOps = append(sidecarOps, *plan)
		}
		unwrapped++
	}

	output, err := marshalMCPConfig(existingData, cfg, zedServersKey)
	if err != nil {
		return fmt.Errorf("marshaling %s: %w", targetPath, err)
	}

	if dryRun {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(),
			"Would write to %s (%d unwrapped):\n%s",
			targetPath, unwrapped, output)
		return nil
	}

	if err := os.WriteFile(targetPath+".bak", existingData, 0o600); err != nil {
		return fmt.Errorf("creating backup: %w", err)
	}

	targetDir := filepath.Dir(targetPath)
	if err := vscodeAtomicWrite(targetPath, output, targetDir); err != nil {
		return err
	}

	// Sidecars are deleted only after the restored config commits, so a
	// partial failure leaves the wrapped config + carriers consistent.
	_ = applySidecarOps(sidecarOps)

	_, _ = fmt.Fprintf(cmd.OutOrStdout(),
		"Unwrapped %d server(s) in %s\n", unwrapped, targetPath)
	if unwrapped > 0 {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Restart Zed to apply changes.\n")
	}
	return nil
}

// readZedConfig reads and parses a Zed settings.json. A missing file produces
// an empty config rather than an error so the install path can create new
// files when --path points at one that does not yet exist (consistent with
// cline install).
func readZedConfig(path string) (*mcpConfig, []byte, error) {
	return readMCPConfig(path, zedServersKey)
}
