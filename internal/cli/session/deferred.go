// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/proxy"
)

// deferredCmd is the `pipelock session deferred` command group: list held
// (deferred) MCP actions awaiting an operator decision, and approve or deny
// each by its defer id.
func deferredCmd(flags *rootFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "deferred",
		Short: "List, approve, and deny held (deferred) MCP actions",
		Long: `Operate the deferred (held-action) control surface on the running
pipelock MCP proxy. Actions that a tool policy deferred are held pending an
operator decision; these commands list them and approve or deny each by its
defer id.

These commands use the authenticated admin API and require
kill_switch.api_listen + kill_switch.api_token on the pipelock MCP proxy, so
the surface is isolated from the agent-facing port. Approving an action whose
rule does not permit approval resolves it CLOSED (blocked); the reported
decision is always the one actually applied.`,
	}
	cmd.AddCommand(
		deferredListCmd(flags),
		deferredApproveCmd(flags),
		deferredDenyCmd(flags),
	)
	return cmd
}

func deferredListCmd(flags *rootFlags) *cobra.Command {
	var jsonOutput bool
	cmd := &cobra.Command{
		Use:           "list",
		Short:         "List held (deferred) actions awaiting a decision",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.Flags().BoolVar(&jsonOutput, flagJSON, false, usageJSON)
	cmd.RunE = func(c *cobra.Command, _ []string) error {
		return runClientCmd(flags, c.Context(), c.OutOrStdout(), func(ctx context.Context, client *Client, out io.Writer) error {
			resp, err := client.DeferredList(ctx)
			if err != nil {
				return err
			}
			if jsonOutput {
				return writeJSON(out, resp)
			}
			return renderDeferredList(out, resp)
		})
	}
	return cmd
}

func deferredApproveCmd(flags *rootFlags) *cobra.Command {
	var jsonOutput bool
	cmd := &cobra.Command{
		Use:           "approve <defer-id>",
		Short:         "Approve a held action (opens it only if its rule permits)",
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.Flags().BoolVar(&jsonOutput, flagJSON, false, usageJSON)
	cmd.RunE = func(c *cobra.Command, args []string) error {
		id := args[0]
		return runClientCmd(flags, c.Context(), c.OutOrStdout(), func(ctx context.Context, client *Client, out io.Writer) error {
			resp, err := client.DeferredApprove(ctx, id)
			if err != nil {
				return err
			}
			if jsonOutput {
				return writeJSON(out, resp)
			}
			return renderDeferredResolve(out, resp)
		})
	}
	return cmd
}

func deferredDenyCmd(flags *rootFlags) *cobra.Command {
	var jsonOutput bool
	cmd := &cobra.Command{
		Use:           "deny <defer-id>",
		Short:         "Deny a held action (resolves it closed / blocked)",
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.Flags().BoolVar(&jsonOutput, flagJSON, false, usageJSON)
	cmd.RunE = func(c *cobra.Command, args []string) error {
		id := args[0]
		return runClientCmd(flags, c.Context(), c.OutOrStdout(), func(ctx context.Context, client *Client, out io.Writer) error {
			resp, err := client.DeferredDeny(ctx, id)
			if err != nil {
				return err
			}
			if jsonOutput {
				return writeJSON(out, resp)
			}
			return renderDeferredResolve(out, resp)
		})
	}
	return cmd
}

// renderDeferredResolve prints the terminal decision that was applied. It is
// deliberately the actual FinalDecision, so an approve that the rule forbids
// prints "approve <id> -> block", not a misleading success.
func renderDeferredResolve(w io.Writer, resp proxy.DeferredResolveResult) error {
	_, _ = fmt.Fprintf(w, "%s %s -> %s\n", resp.Action, resp.DeferID, resp.FinalDecision)
	return nil
}

func renderDeferredList(w io.Writer, resp proxy.DeferredListResponse) error {
	if resp.Count == 0 {
		_, _ = fmt.Fprintln(w, "no held actions")
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "DEFER_ID\tSURFACE\tMETHOD\tTARGET\tSESSION\tDEPTH\tREASON")
	for _, a := range resp.Held {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%d\t%s\n",
			a.DeferID, a.Surface, a.Method, a.Target, a.SessionID, a.CascadeDepth, a.Reason)
	}
	return tw.Flush()
}
