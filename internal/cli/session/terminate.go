// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

const (
	terminateUse   = "terminate <key>"
	terminateShort = "Force a full tear-down of a session (destructive)"
)

func terminateCmd() *cobra.Command {
	var jsonOutput bool
	cmd := &cobra.Command{
		Use:   terminateUse,
		Short: terminateShort,
		Long: `Force a full tear-down of a session: cancel in-flight long-lived
connections, reset all enforcement state, and clear CEE entropy/fragment
tracking. This is DESTRUCTIVE
— the affected agent loses its current adaptive history, any
in-flight streams are cut, and any task-scoped overrides are dropped.

Use this when release is insufficient: a session is actively being
exploited, or has accumulated so much bad state that starting fresh
is safer than releasing.

Invocation sessions (ephemeral MCP transport keys starting with
mcp-stdio-/mcp-http-/mcp-ws-) cannot be terminated via the admin API
— they are rejected with a 400 error.

Examples:
  pipelock session terminate "agent|10.0.0.1"
  pipelock session terminate "agent|10.0.0.1" --json`,
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	flags := addCommonFlags(cmd)
	cmd.Flags().BoolVar(&jsonOutput, flagJSON, false, usageJSON)

	cmd.RunE = func(c *cobra.Command, args []string) error {
		key := args[0]
		return runClientCmd(flags, c.Context(), c.OutOrStdout(), func(ctx context.Context, client *Client, out io.Writer) error {
			if !jsonOutput {
				// Keep stdout machine-readable in --json mode.
				_, _ = fmt.Fprintf(out, "WARNING: terminating session %s — in-flight connections will be cut.\n", key)
			}

			resp, err := client.Terminate(ctx, key)
			if err != nil {
				return err
			}
			if jsonOutput {
				return writeJSON(out, resp)
			}
			_, _ = fmt.Fprintf(out, "terminated %s: previous_tier=%s level=%s score=%.2f cee_cleared=%t\n",
				resp.Key, resp.PreviousTier, resp.PreviousLevel, resp.PreviousScore, resp.CEEStateCleared)
			return nil
		})
	}
	return cmd
}
