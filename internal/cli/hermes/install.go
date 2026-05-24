// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package hermes

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
)

// Install mode constants. The current release only validates these values;
// the mode-specific behaviour (backend-aware env injection, MCP-only
// labelling, idempotent .bak rotation across full installs) lands in a
// follow-up.
const (
	ModeFull    = "full"
	ModeMCPOnly = "mcp-only"
)

// installOptions captures the parsed flags for `pipelock hermes install`. It
// exists separately from the cobra command so tests can exercise the run
// logic without re-parsing argv.
type installOptions struct {
	// Mode is one of ModeFull or ModeMCPOnly. Defaults to ModeFull.
	Mode string

	// PluginRoot is the directory the embedded plugin tree is extracted
	// into. Empty means "resolve from HOME at run time" — kept off the
	// struct default so tests can inject a tmpdir without colliding with
	// the operator's real ~/.hermes.
	PluginRoot string

	// HomeDir overrides the value used to resolve PluginRoot when
	// PluginRoot is empty. Defaults to os.UserHomeDir().
	HomeDir string
}

// validate returns an error when the parsed flag set is not yet acceptable to
// run. The current release enforces only the mode-flag whitelist; follow-ups
// will extend this with backend-detection requirements.
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

func installCmd() *cobra.Command {
	opts := &installOptions{Mode: ModeFull}

	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install pipelock's Hermes plugin and shell-hook wiring",
		Long: `Materialise pipelock's Hermes plugin tree under ~/.hermes/plugins/pipelock/
and (in later releases) wire the pipelock-hermes-hook binary into the active
Hermes configuration.

This release ships plugin extraction only. The --mode flag accepts values
that a later release will act on:

  full      — full plugin + shell-hook wiring (default; intended target)
  mcp-only  — MCP-server wrapping only, no plugin install

The current build always extracts the plugin tree regardless of mode; the
mode flag is captured so operators can pin the value across upgrades without
the install command erroring out once mode-specific install lands.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runInstall(cmd, opts)
		},
	}

	cmd.Flags().StringVar(&opts.Mode, "mode", ModeFull,
		"install mode: full (default, plugin + shell-hook) or mcp-only (MCP wrap only)")
	cmd.Flags().StringVar(&opts.PluginRoot, "plugin-root", "",
		"override the plugin install directory (default ~/.hermes/plugins/pipelock)")

	return cmd
}

// runInstall is the post-flag-parse entry point. It is split out so tests can
// drive the install behaviour directly without going through cobra.
func runInstall(cmd *cobra.Command, opts *installOptions) error {
	if err := opts.validate(); err != nil {
		return err
	}

	root := opts.PluginRoot
	if root == "" {
		home := opts.HomeDir
		if home == "" {
			detected, err := userHomeDir()
			if err != nil {
				return fmt.Errorf("hermes install: %w", err)
			}
			home = detected
		}
		root = ResolveDefaultPluginRoot(home)
	}

	result, err := Install(PluginTarget{Root: root})
	if err != nil {
		return err
	}

	out := cmd.OutOrStdout()
	_, _ = fmt.Fprintf(out, "pipelock: hermes plugin installed at %s\n", result.Root)
	_, _ = fmt.Fprintf(out, "pipelock: %d files written\n", result.FilesWritten)
	for _, backup := range result.BackupsCreated {
		_, _ = fmt.Fprintf(out, "pipelock: rotated existing file to %s\n", backup)
	}
	if opts.Mode == ModeMCPOnly {
		_, _ = fmt.Fprintln(out,
			"pipelock: --mode=mcp-only selected; plugin extracted for future use, "+
				"shell-hook wiring deferred to a follow-up release")
	}
	return nil
}
