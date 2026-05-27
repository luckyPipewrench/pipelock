// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package hermes

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/mcpwrap"
)

// rollbackOptions captures `pipelock hermes rollback` flags.
type rollbackOptions struct {
	PluginRoot    string
	HermesConfig  string
	HomeDir       string
	RestoreBackup string
	KeepPlugin    bool
}

func (o *rollbackOptions) resolvePaths() error {
	if o.PluginRoot != "" && o.HermesConfig != "" {
		return nil
	}
	home := o.HomeDir
	if home == "" {
		detected, err := userHomeDir()
		if err != nil {
			return fmt.Errorf("hermes rollback: %w", err)
		}
		home = detected
	}
	if o.PluginRoot == "" {
		o.PluginRoot = ResolveDefaultPluginRoot(home)
	}
	if o.HermesConfig == "" {
		o.HermesConfig = ResolveDefaultHermesConfig(home)
	}
	return nil
}

func rollbackCmd() *cobra.Command {
	opts := &rollbackOptions{}

	cmd := &cobra.Command{
		Use:   "rollback",
		Short: "Remove pipelock's Hermes integration",
		Long: `Undo 'pipelock hermes install'.

By default the rollback is surgical: it removes only pipelock-managed state —
the proxy env names from terminal.env_passthrough and docker_forward_env, and
the pipelock plugin directory. Any other Hermes config the operator added
after install is left untouched.

--restore-backup PATH instead overwrites ~/.hermes/config.yaml with the named
.bak file produced by a prior install. Use this only for explicit recovery; it
discards config changes made after that backup.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runRollback(cmd, opts)
		},
	}

	cmd.Flags().StringVar(&opts.PluginRoot, "plugin-root", "",
		"override the plugin install directory (default ~/.hermes/plugins/pipelock)")
	cmd.Flags().StringVar(&opts.HermesConfig, "hermes-config", "",
		"override the Hermes config path (default ~/.hermes/config.yaml)")
	cmd.Flags().StringVar(&opts.RestoreBackup, "restore-backup", "",
		"overwrite config.yaml with this .bak file instead of surgical removal")
	cmd.Flags().BoolVar(&opts.KeepPlugin, "keep-plugin", false,
		"leave the extracted plugin directory in place")

	return cmd
}

func runRollback(cmd *cobra.Command, opts *rollbackOptions) error {
	if err := opts.resolvePaths(); err != nil {
		return err
	}
	out := cmd.OutOrStdout()

	if opts.RestoreBackup != "" {
		return restoreFromBackup(cmd, opts)
	}

	// Surgical removal: unwrap any pipelock-wrapped mcp_servers (mcp-only
	// artifacts) and strip pipelock proxy env names (full-mode artifacts) from
	// config.yaml. Both are handled regardless of which mode installed them, so
	// the operator need not remember.
	cfg, err := loadHermesConfig(opts.HermesConfig)
	if err != nil {
		return err
	}
	unwrapped, sidecarOps := unwrapHermesMCPServers(cmd, cfg)
	removed := cfg.removeTerminalEnv()
	disabled, err := cfg.disablePlugin()
	if err != nil {
		return err
	}
	if len(removed) > 0 || unwrapped > 0 || disabled {
		if _, err := cfg.save(true); err != nil {
			return err
		}
		// Delete header sidecars only after the restored config is committed,
		// so a save failure leaves the wrapped config and its sidecars intact
		// for a retry rather than orphaning a config that points at gone files.
		// Surface any deletion failure: a sidecar holds credential headers, so a
		// silent failure would leave a secret on disk while reporting success.
		if len(sidecarOps) > 0 {
			if err := mcpwrap.ApplySidecarOps(sidecarOps); err != nil {
				_, _ = fmt.Fprintf(out, "pipelock: warning: could not delete one or more header sidecar files; "+
					"remove them manually under ~/.config/pipelock/wrap-headers: %v\n", err)
			}
		}
	}
	if len(removed) > 0 {
		_, _ = fmt.Fprintf(out, "pipelock: removed %d proxy env name(s) from terminal passthrough\n", len(removed))
	} else {
		_, _ = fmt.Fprintln(out, "pipelock: no pipelock proxy env names found in config")
	}
	if disabled {
		_, _ = fmt.Fprintf(out, "pipelock: removed plugin %q from %s.%s\n", pluginRegistryName, pluginsKey, enabledKey)
	}
	if unwrapped > 0 {
		_, _ = fmt.Fprintf(out, "pipelock: unwrapped %d mcp server(s) in %s\n", unwrapped, opts.HermesConfig)
	}

	if opts.KeepPlugin {
		_, _ = fmt.Fprintf(out, "pipelock: left plugin directory in place at %s\n", opts.PluginRoot)
		return nil
	}
	if pluginInstalled(opts.PluginRoot) || fileExists(filepath.Join(opts.PluginRoot, configSidecarName)) {
		if err := removePluginTree(opts.PluginRoot); err != nil {
			return err
		}
		_, _ = fmt.Fprintf(out, "pipelock: removed managed plugin files under %s\n", opts.PluginRoot)
	} else {
		_, _ = fmt.Fprintf(out, "pipelock: no plugin directory at %s\n", opts.PluginRoot)
	}
	return nil
}

// unwrapHermesMCPServers restores every pipelock-wrapped mcp_servers entry,
// mutating cfg in place. Per-entry unwrap failures are warned and skipped (the
// entry is left wrapped) so one corrupt _pipelock block does not block the rest
// of the rollback. Returns the count unwrapped and the sidecar delete ops,
// which the caller MUST apply only after the restored config is committed.
func unwrapHermesMCPServers(cmd *cobra.Command, cfg *hermesConfig) (int, []mcpwrap.SidecarOp) {
	servers := cfg.mcpServers()
	if len(servers) == 0 {
		return 0, nil
	}
	unwrapped := 0
	var ops []mcpwrap.SidecarOp
	for _, name := range sortedKeys(servers) {
		server, ok := servers[name].(map[string]interface{})
		if !ok || !mcpwrap.IsWrapped(server) {
			continue
		}
		restored, op, err := mcpwrap.UnwrapServer(server)
		if err != nil {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warning: could not unwrap mcp server %q: %v\n", name, err)
			continue
		}
		servers[name] = restored
		if op != nil {
			ops = append(ops, *op)
		}
		unwrapped++
	}
	return unwrapped, ops
}

// restoreFromBackup overwrites config.yaml with the named backup file.
func restoreFromBackup(cmd *cobra.Command, opts *rollbackOptions) error {
	clean := filepath.Clean(opts.RestoreBackup)
	data, err := os.ReadFile(clean)
	if err != nil {
		return fmt.Errorf("hermes rollback: read backup %s: %w", clean, err)
	}
	// Rotate the current config aside before overwriting so the restore is
	// itself reversible.
	if _, err := rotateExisting(opts.HermesConfig); err != nil {
		return err
	}
	if err := writeFileAtomic(opts.HermesConfig, data); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "pipelock: restored %s from %s\n", opts.HermesConfig, clean)
	return nil
}
