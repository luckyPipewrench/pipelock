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
	resetUse   = "reset <key>"
	resetShort = "Clear adaptive score and scoped airlock without tearing down connections"
)

func resetCmd(flags *rootFlags) *cobra.Command {
	var jsonOutput bool
	cmd := &cobra.Command{
		Use:   resetUse,
		Short: resetShort,
		Long: `Clear this identity session's adaptive threat score, escalation
level, destination-scoped airlock, and block_all flags. In-flight
connections are left running. Taint and task-boundary state are left
alone; use terminate when those must go too.

This is the operator command for "the session is at critical because
a blocked destination keeps retrying", not for changing airlock tier.
Release only moves session-wide airlock. If inspect shows airlock
none and a destination scope at hard, reset is the command that
matches the blocker.

Invocation sessions (mcp-stdio-/mcp-http-/mcp-ws-) cannot be reset
via the admin API — they are rejected with a 400 error.

Examples:
  pipelock session reset "agent|10.0.0.1"
  pipelock session reset "agent|10.0.0.1" --json`,
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.Flags().BoolVar(&jsonOutput, flagJSON, false, usageJSON)

	cmd.RunE = func(c *cobra.Command, args []string) error {
		key := args[0]
		return runClientCmd(flags, c.Context(), c.OutOrStdout(), func(ctx context.Context, client *Client, out io.Writer) error {
			resp, err := client.Reset(ctx, key)
			if err != nil {
				return err
			}
			if jsonOutput {
				return writeJSON(out, resp)
			}
			_, _ = fmt.Fprintf(out, "reset %s: reset=%t previous_level=%s previous_score=%.2f ip_cleared=%t cee_cleared=%t\n",
				resp.Key, resp.Reset, resp.PreviousLevel, resp.PreviousScore, resp.IPStateCleared, resp.CEEStateCleared)
			if !resp.Reset {
				_, _ = fmt.Fprintln(out, "no session matched that key; nothing was reset. check the key with `pipelock session list`.")
			}
			return nil
		})
	}
	return cmd
}
