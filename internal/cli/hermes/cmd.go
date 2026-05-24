// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package hermes implements the `pipelock hermes` subcommand tree, which
// manages pipelock's integration with the Hermes Agent (Nous Research) plugin
// system. The package owns plugin extraction, install/verify/rollback
// commands, and any future Hermes-specific glue.
//
// The MVP release ships:
//   - `pipelock hermes install` — extracts the embedded Python plugin tree
//     into ~/.hermes/plugins/pipelock/ (mode-flag scaffolding only; full
//     backend-aware install lands in a follow-up).
//
// The separate `pipelock-hermes-hook` binary (under cmd/) is the workhorse
// invoked by Hermes for each hook event; this package handles configuration
// of that integration rather than the runtime hot path itself.
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

The runtime hot path lives in the pipelock-hermes-hook binary; this command
group manages installation, verification, and rollback of that integration.`,
	}
	cmd.AddCommand(installCmd())
	return cmd
}
