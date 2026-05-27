// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package hermes

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/mcpwrap"
)

// Install mode constants.
const (
	// ModeFull installs the Python plugin (which self-registers all five
	// hooks), enables it in config.yaml plugins.enabled, and injects pipelock's
	// proxy env names into the terminal backend. It does NOT also wire shell
	// hooks: the plugin already covers every event, so adding shell hooks would
	// double-scan each call.
	//
	// The full install-load-enable-block path is proven end-to-end against a
	// live Hermes by `make hermes-e2e` (TestHermesLiveE2E). This is the default:
	// an agent firewall should default to maximum coverage, and the plugin hooks
	// (tool args, results, gateway) protect immediately on install. Terminal
	// egress is the one cooperative arm (see the install help).
	ModeFull = "full"
	// ModeMCPOnly rewrites mcp_servers through `pipelock mcp proxy` (preserving
	// auth headers via a 0o600 header sidecar) and skips the plugin. This is the
	// lighter opt-in: no Python plugin, no terminal env changes. Labeled partial
	// coverage: it sees MCP traffic only, not the terminal/file/browser/gateway
	// surfaces the plugin covers.
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

  --mode full (default, plugin-visible tool surfaces)
      Extract the Python plugin into ~/.hermes/plugins/pipelock/ (it
      self-registers pre_tool_call, transform_tool_result,
      pre_gateway_dispatch, and session-lifecycle hooks), enable it in
      config.yaml plugins.enabled, and inject pipelock's proxy env names into
      the terminal backend's env_passthrough so sandboxed tool execution can
      route through pipelock. The plugin is the single integration path; shell
      hooks are intentionally NOT wired to avoid double-scanning every event.

      This is the default because the plugin sees what a network proxy cannot:
      a terminal command's arguments before it runs, a file write's contents,
      and a tool result before the model reads it. The plugin load-enable-block
      path is proven end-to-end against a live Hermes by 'make hermes-e2e'. The
      one cooperative caveat is terminal egress (below): pipelock only sees
      terminal network traffic if the proxy env VALUES are also set in Hermes'
      environment and the backend honors them.

  --mode mcp-only (lighter opt-in)
      Rewrite ~/.hermes/config.yaml mcp_servers so each MCP server runs
      through 'pipelock mcp proxy'. Stdio servers (command/args) get their
      command wrapped; remote servers (url) are converted to a stdio proxy
      with --upstream. Auth headers on remote servers are preserved in a
      0600 header sidecar referenced via --header-file, so credential values
      never appear in process argv. This is partial coverage (MCP traffic
      only), not the terminal/file/browser/gateway surfaces the plugin covers.
      No Python plugin, no terminal env changes.

The install is idempotent: config.yaml is backed up to a .bak file and
re-runs do not re-wrap already-wrapped servers or duplicate entries.

Coverage note: terminal proxy passthrough is cooperative. pipelock sees
sandbox traffic only when the proxy env VALUES are also set in Hermes'
environment and the backend honors them. This is not binary-enforced
network isolation.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runInstall(cmd, opts)
		},
	}

	cmd.Flags().StringVar(&opts.Mode, "mode", ModeFull,
		"install mode: full (default: plugin + terminal env, plugin-visible tool surfaces) or mcp-only (lighter: wrap mcp_servers through pipelock)")
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
		return installMCPOnly(cmd, opts)
	}
	return installFull(cmd, opts)
}

// installMCPOnly rewrites ~/.hermes/config.yaml's mcp_servers entries to route
// each MCP server through `pipelock mcp proxy`, preserving auth headers via a
// 0o600 header sidecar. It does NOT install the plugin or inject terminal env:
// mcp-only is partial coverage by design (MCP traffic only). Idempotent —
// already-wrapped servers are skipped — and config.yaml is backed up before
// modification.
func installMCPOnly(cmd *cobra.Command, opts *installOptions) error {
	out := cmd.OutOrStdout()

	exe, err := resolvePipelockExe()
	if err != nil {
		return err
	}

	cfg, err := loadHermesConfig(opts.HermesConfig)
	if err != nil {
		return err
	}
	servers := cfg.mcpServers()
	if len(servers) == 0 {
		_, _ = fmt.Fprintf(out, "pipelock: no mcp_servers declared in %s; nothing to wrap\n", opts.HermesConfig)
		_, _ = fmt.Fprintln(out, "pipelock: coverage = none (mcp-only requires MCP servers to wrap; use --mode full for plugin coverage)")
		return nil
	}

	// If the full-mode plugin is already installed it scans MCP tool calls via
	// pre_tool_call, so also wrapping mcp_servers double-scans MCP traffic
	// (redundant receipts and latency, not a security hole). Warn rather than
	// block — the operator explicitly chose mcp-only.
	if pluginInstalled(opts.PluginRoot) {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(),
			"warning: the pipelock Hermes plugin is already installed at %s and already scans MCP tool calls; "+
				"wrapping mcp_servers as well will scan MCP traffic twice. Run 'pipelock hermes rollback' first if you want mcp-only coverage.\n",
			opts.PluginRoot)
	}

	configFile := mcpProxyConfigForWrap(cmd, opts.PipelockConfig)

	wrapped := 0
	skipped := 0
	failed := 0
	var sidecarOps []mcpwrap.SidecarOp
	for _, name := range sortedKeys(servers) {
		server, ok := servers[name].(map[string]interface{})
		if !ok {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warning: skipping mcp server %q: entry is not a mapping\n", name)
			failed++
			continue
		}
		if mcpwrap.IsWrapped(server) {
			skipped++
			continue
		}
		newServer, meta, plan, wrapErr := mcpwrap.WrapServer(server, exe, configFile, opts.HermesConfig, name)
		if wrapErr != nil {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warning: skipping mcp server %q: %v\n", name, wrapErr)
			failed++
			continue
		}
		metaValue, err := metaToInterface(meta)
		if err != nil {
			return fmt.Errorf("hermes install: encode metadata for %q: %w", name, err)
		}
		newServer[mcpwrap.FieldPipelock] = metaValue
		servers[name] = newServer
		if plan != nil {
			sidecarOps = append(sidecarOps, *plan)
		}
		wrapped++
	}

	if failed > 0 {
		return fmt.Errorf("hermes install: %d mcp server(s) could not be wrapped; fix the warnings above and rerun", failed)
	}
	if wrapped == 0 {
		_, _ = fmt.Fprintf(out, "pipelock: all %d mcp server(s) already wrapped in %s\n", skipped, opts.HermesConfig)
		return nil
	}

	// Sidecars first so a failed sidecar write leaves config.yaml untouched.
	// ApplySidecarOps rolls back its own partial writes on failure.
	if err := mcpwrap.ApplySidecarOps(sidecarOps); err != nil {
		return fmt.Errorf("hermes install: writing header sidecar: %w", err)
	}
	backupPath, err := cfg.save(true)
	if err != nil {
		// Config write failed after sidecars landed: drop the orphaned sidecars
		// so they do not point at a config that never referenced them.
		mcpwrap.RollbackSidecarWrites(sidecarOps)
		return err
	}

	_, _ = fmt.Fprintf(out, "pipelock: wrapped %d mcp server(s) through pipelock mcp proxy in %s\n", wrapped, opts.HermesConfig)
	if skipped > 0 {
		_, _ = fmt.Fprintf(out, "pipelock: %d server(s) already wrapped (left as-is)\n", skipped)
	}
	if len(sidecarOps) > 0 {
		_, _ = fmt.Fprintf(out, "pipelock: wrote %d auth-header sidecar file(s) at 0600 under ~/.config/pipelock/wrap-headers\n", len(sidecarOps))
	}
	if configFile != "" {
		_, _ = fmt.Fprintf(out, "pipelock: wrapped servers use config %s\n", configFile)
	}
	if backupPath != "" {
		_, _ = fmt.Fprintf(out, "pipelock: backed up %s to %s\n", opts.HermesConfig, backupPath)
	}
	_, _ = fmt.Fprintln(out, "pipelock: coverage = partial (MCP server traffic only; terminal/file/browser/gateway NOT scanned)")
	_, _ = fmt.Fprintln(out, "pipelock: use --mode full to also scan non-MCP tool events via the plugin")
	return nil
}

// mcpProxyConfigForWrap returns the config path embedded into wrapped MCP
// proxy invocations. Explicit --pipelock-config wins; otherwise mirror the
// setup installers and discover the standard pipelock config path so a
// successful-looking wrap does not silently spawn proxies with built-in
// defaults that disable MCP scanning features.
func mcpProxyConfigForWrap(cmd *cobra.Command, explicit string) string {
	if explicit != "" {
		return explicit
	}
	if discovered := cliutil.DiscoverConfigPath(); discovered != "" {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "pipelock: using config %s for wrapped MCP proxy\n", discovered)
		return discovered
	}
	_, _ = fmt.Fprintln(cmd.ErrOrStderr(),
		"warning: no pipelock config found at PIPELOCK_CONFIG, $XDG_CONFIG_HOME/pipelock/pipelock.yaml, ~/.config/pipelock/pipelock.yaml, or /etc/pipelock/pipelock.yaml. The wrapped MCP proxy will run with built-in defaults; MCP input scanning, tool scanning, tool policy, and the flight recorder are disabled in the defaults. Pass --pipelock-config explicitly or place a config at one of the standard locations to enable scanning.")
	return ""
}

// resolvePipelockExe resolves the absolute pipelock binary path to embed in the
// wrapped server command, following symlinks so the entry survives PATH shims.
func resolvePipelockExe() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("hermes install: finding pipelock binary: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return "", fmt.Errorf("hermes install: resolving pipelock binary path: %w", err)
	}
	return resolved, nil
}

// metaToInterface converts the typed wrap metadata into a generic value with
// JSON field names so it round-trips through YAML marshal/unmarshal and stays
// readable by mcpwrap.ParseMeta on unwrap (which decodes via JSON tags).
func metaToInterface(meta *mcpwrap.Meta) (interface{}, error) {
	data, err := json.Marshal(meta)
	if err != nil {
		return nil, err
	}
	var out interface{}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// installFull performs the plugin-only install: extract the plugin, record the
// config sidecar, and inject proxy env names into the terminal backend.
func installFull(cmd *cobra.Command, opts *installOptions) error {
	out := cmd.OutOrStdout()

	cfg, err := loadHermesConfig(opts.HermesConfig)
	if err != nil {
		return err
	}

	// Prepare config changes in memory first so malformed operator config is
	// rejected before we touch the plugin directory. The config is saved only
	// after the plugin files and sidecar have landed, so a filesystem failure
	// cannot leave plugins.enabled pointing at an absent plugin.
	addedEnv := cfg.injectTerminalEnv()
	backend := cfg.backend()
	// Enable the plugin in config.yaml. Standalone plugins are opt-in: Hermes
	// loads ours only when "pipelock" is in plugins.enabled. Without this the
	// installed plugin is discovered-but-disabled and never fires.
	enabledNow, err := cfg.enablePlugin()
	if err != nil {
		return err
	}

	result, err := Install(PluginTarget{Root: opts.PluginRoot})
	if err != nil {
		return err
	}
	if err := writeConfigSidecar(result.Root, opts.PipelockConfig); err != nil {
		return err
	}

	var backupPath string
	if len(addedEnv) > 0 || enabledNow {
		var saveErr error
		backupPath, saveErr = cfg.save(true)
		if saveErr != nil {
			return saveErr
		}
	}

	_, _ = fmt.Fprintf(out, "pipelock: hermes plugin installed at %s\n", result.Root)
	_, _ = fmt.Fprintf(out, "pipelock: %d plugin files written\n", result.FilesWritten)
	for _, backup := range result.BackupsCreated {
		_, _ = fmt.Fprintf(out, "pipelock: rotated existing plugin file to %s\n", backup)
	}
	if opts.PipelockConfig != "" {
		_, _ = fmt.Fprintf(out, "pipelock: hook will use config %s\n", opts.PipelockConfig)
	}
	if enabledNow {
		_, _ = fmt.Fprintf(out, "pipelock: enabled plugin %q in %s.%s\n", pluginRegistryName, pluginsKey, enabledKey)
	} else {
		_, _ = fmt.Fprintf(out, "pipelock: plugin %q already enabled in %s.%s\n", pluginRegistryName, pluginsKey, enabledKey)
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
	// The plugin path (tool args, tool results, gateway, sessions) is proven
	// end-to-end against a live Hermes by `make hermes-e2e`. Terminal egress is
	// the one cooperative arm: pipelock sees it only when the proxy env VALUES
	// are set in Hermes' environment and the backend honors them.
	_, _ = fmt.Fprintln(out, "pipelock: coverage = full Hermes plugin hooks + cooperative terminal proxy passthrough")
	_, _ = fmt.Fprintln(out, "pipelock: set the proxy env VALUES (HTTPS_PROXY, NODE_EXTRA_CA_CERTS, ...) in Hermes' environment for terminal traffic to route through pipelock")
	return nil
}
