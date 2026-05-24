// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package hermes

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
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

	// Surgical removal: strip pipelock proxy env names from config.yaml.
	cfg, err := loadHermesConfig(opts.HermesConfig)
	if err != nil {
		return err
	}
	removed := cfg.removeTerminalEnv()
	if len(removed) > 0 {
		if _, err := cfg.save(true); err != nil {
			return err
		}
		_, _ = fmt.Fprintf(out, "pipelock: removed %d proxy env name(s) from terminal passthrough\n", len(removed))
	} else {
		_, _ = fmt.Fprintln(out, "pipelock: no pipelock proxy env names found in config")
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
