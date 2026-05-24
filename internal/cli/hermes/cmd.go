// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package hermes implements the `pipelock hermes` subcommand tree, which
// manages pipelock's integration with the Hermes Agent (Nous Research) plugin
// system. The package owns plugin extraction, install/verify/rollback
// commands, and any future Hermes-specific glue.
//
// Subcommands:
//   - `pipelock hermes install` — extracts the embedded Python plugin tree
//     into ~/.hermes/plugins/pipelock/ and wires the integration.
//   - `pipelock hermes verify` — reports the installed coverage state.
//   - `pipelock hermes rollback` — surgically removes the integration.
//   - `pipelock hermes hook` — the subprocess entrypoint Hermes invokes per
//     hook event (stdin JSON in, decision JSON out).
//
// The hook lives as a subcommand of the main pipelock binary (not a separate
// binary) so it ships with every pipelock install, with no extra release
// artifact to provision.
package hermes

import "github.com/spf13/cobra"

// Cmd returns the `pipelock hermes` parent cobra command. Subcommands are
// attached here so the root CLI only needs to wire this single node into its
// AddCommand list.
func Cmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "hermes",
		Short: "Manage pipelock's Hermes Agent integration",
		Long: `Manage pipelock's Hermes Agent (github.com/NousResearch/hermes-agent)
integration: extracts the Python plugin into ~/.hermes/plugins/pipelock/ so
Hermes can call pipelock for pre_tool_call, transform_tool_result,
pre_gateway_dispatch, and session-lifecycle hooks.

The 'hook' subcommand is the per-event subprocess entrypoint; 'install',
'verify', and 'rollback' manage the integration.`,
	}
	cmd.AddCommand(installCmd())
	cmd.AddCommand(verifyCmd())
	cmd.AddCommand(rollbackCmd())
	cmd.AddCommand(hookCmd())
	return cmd
}
