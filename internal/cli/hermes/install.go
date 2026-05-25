// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package hermes

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"
)

// Install mode constants.
const (
	// ModeFull installs the Python plugin (which self-registers all five
	// hooks) and injects pipelock's proxy env names into the terminal
	// backend. It does NOT also wire shell hooks: the plugin already covers
	// every event, so adding shell hooks would double-scan each call.
	ModeFull = "full"
	// ModeMCPOnly rewrites mcp_servers through `pipelock mcp proxy` and skips
	// the plugin. Labeled partial coverage: it sees MCP traffic only, not the
	// terminal/file/browser/gateway surfaces the plugin covers.
	ModeMCPOnly = "mcp-only"
)

// installOptions captures the parsed flags for `pipelock hermes install`.
type installOptions struct {
	// Mode is one of ModeFull or ModeMCPOnly. Defaults to ModeFull.
	Mode string

	// PluginRoot is the directory the embedded plugin tree is extracted into.
	// Empty means "resolve from HOME at run time".
	PluginRoot string

	// HermesConfig is the path to ~/.hermes/config.yaml. Empty means resolve
	// from HOME at run time.
	HermesConfig string

	// PipelockConfig is the pipelock config path the hook should use; written
	// to the plugin's config sidecar. Empty means the hook uses built-in
	// defaults.
	PipelockConfig string

	// HomeDir overrides the value used to resolve PluginRoot/HermesConfig when
	// those are empty. Defaults to os.UserHomeDir().
	HomeDir string
}

// validate rejects an unacceptable flag set.
func (o *installOptions) validate() error {
	switch o.Mode {
	case ModeFull, ModeMCPOnly:
		return nil
	case "":
		return errors.New("hermes install: --mode is required (full|mcp-only)")
	default:
		return fmt.Errorf("hermes install: --mode must be one of full|mcp-only, got %q", o.Mode)
	}
}

// resolvePaths fills PluginRoot and HermesConfig from HomeDir/HOME when unset.
func (o *installOptions) resolvePaths() error {
	if o.PluginRoot == "" || o.HermesConfig == "" {
		home := o.HomeDir
		if home == "" {
			detected, err := userHomeDir()
			if err != nil {
				return fmt.Errorf("hermes install: %w", err)
			}
			home = detected
		}
		if o.PluginRoot == "" {
			o.PluginRoot = ResolveDefaultPluginRoot(home)
		}
		if o.HermesConfig == "" {
			o.HermesConfig = ResolveDefaultHermesConfig(home)
		}
	}
	if o.PipelockConfig != "" {
		clean := filepath.Clean(o.PipelockConfig)
		abs, err := filepath.Abs(clean)
		if err != nil {
			return fmt.Errorf("hermes install: resolve --pipelock-config: %w", err)
		}
		o.PipelockConfig = abs
	}
	return nil
}

func installCmd() *cobra.Command {
	opts := &installOptions{Mode: ModeFull}

	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install pipelock's Hermes integration",
		Long: `Wire pipelock into the Hermes Agent at ~/.hermes.

  --mode full (default)
      Extract the Python plugin into ~/.hermes/plugins/pipelock/ (it
      self-registers pre_tool_call, transform_tool_result,
      pre_gateway_dispatch, and session-lifecycle hooks) and inject
      pipelock's proxy env names into the terminal backend's
      env_passthrough so sandboxed tool execution can route through
      pipelock. The plugin is the single integration path; shell hooks
      are intentionally NOT wired to avoid double-scanning every event.

  --mode mcp-only
      Not yet available. Will rewrite ~/.hermes/config.yaml mcp_servers
      through 'pipelock mcp proxy' with auth-header preservation in a
      follow-up release. Use --mode full today.

The install is idempotent: config.yaml is backed up to a .bak file and
re-runs do not duplicate entries.

Coverage note: terminal proxy passthrough is cooperative. pipelock sees
sandbox traffic only when the proxy env VALUES are also set in Hermes'
environment and the backend honors them. This is not binary-enforced
network isolation.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runInstall(cmd, opts)
		},
	}

	cmd.Flags().StringVar(&opts.Mode, "mode", ModeFull,
		"install mode: full (plugin + terminal env). mcp-only is not yet available")
	cmd.Flags().StringVar(&opts.PluginRoot, "plugin-root", "",
		"override the plugin install directory (default ~/.hermes/plugins/pipelock)")
	cmd.Flags().StringVar(&opts.HermesConfig, "hermes-config", "",
		"override the Hermes config path (default ~/.hermes/config.yaml)")
	cmd.Flags().StringVar(&opts.PipelockConfig, "pipelock-config", "",
		"pipelock config the hook should use (recorded in the plugin sidecar)")

	return cmd
}

// runInstall is the post-flag-parse entry point, split out for testing.
func runInstall(cmd *cobra.Command, opts *installOptions) error {
	if err := opts.validate(); err != nil {
		return err
	}
	if err := opts.resolvePaths(); err != nil {
		return err
	}
	if opts.Mode == ModeMCPOnly {
		// mcp-only rewrites mcp_servers through `pipelock mcp proxy` and must
		// preserve MCP auth headers via the private header-sidecar pattern.
		// Doing that correctly means extracting the shared sidecar logic from
		// the setup package rather than re-implementing a header-dropping
		// wrapper; that extraction ships in a follow-up. Fail honestly here
		// rather than half-installing.
		return errors.New("hermes install: --mode mcp-only is not yet available; " +
			"use --mode full (plugin path). MCP-server wrapping with auth-header " +
			"preservation lands in a follow-up release")
	}
	return installFull(cmd, opts)
}

// installFull performs the plugin-only install: extract the plugin, record the
// config sidecar, and inject proxy env names into the terminal backend.
func installFull(cmd *cobra.Command, opts *installOptions) error {
	out := cmd.OutOrStdout()

	cfg, err := loadHermesConfig(opts.HermesConfig)
	if err != nil {
		return err
	}
	addedEnv := cfg.injectTerminalEnv()
	backend := cfg.backend()
	var backupPath string
	if len(addedEnv) > 0 {
		var saveErr error
		backupPath, saveErr = cfg.save(true)
		if saveErr != nil {
			return saveErr
		}
	}

	result, err := Install(PluginTarget{Root: opts.PluginRoot})
	if err != nil {
		return err
	}
	if err := writeConfigSidecar(result.Root, opts.PipelockConfig); err != nil {
		return err
	}

	_, _ = fmt.Fprintf(out, "pipelock: hermes plugin installed at %s\n", result.Root)
	_, _ = fmt.Fprintf(out, "pipelock: %d plugin files written\n", result.FilesWritten)
	for _, backup := range result.BackupsCreated {
		_, _ = fmt.Fprintf(out, "pipelock: rotated existing plugin file to %s\n", backup)
	}
	if opts.PipelockConfig != "" {
		_, _ = fmt.Fprintf(out, "pipelock: hook will use config %s\n", opts.PipelockConfig)
	}
	_, _ = fmt.Fprintf(out, "pipelock: terminal backend %q\n", backend)
	if len(addedEnv) > 0 {
		_, _ = fmt.Fprintf(out, "pipelock: added %d proxy env name(s) to terminal passthrough\n", len(addedEnv))
	} else {
		_, _ = fmt.Fprintln(out, "pipelock: proxy env names already present in terminal passthrough")
	}
	if backupPath != "" {
		_, _ = fmt.Fprintf(out, "pipelock: backed up %s to %s\n", opts.HermesConfig, backupPath)
	}
	_, _ = fmt.Fprintln(out, "pipelock: coverage = full Hermes hooks + configured terminal proxy passthrough")
	_, _ = fmt.Fprintln(out, "pipelock: set the proxy env VALUES (HTTPS_PROXY, NODE_EXTRA_CA_CERTS, ...) in Hermes' environment for terminal traffic to route through pipelock")
	return nil
}
