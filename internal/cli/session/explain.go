// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"io"

	"github.com/spf13/cobra"
)

const (
	explainUse   = "explain <key>"
	explainShort = "Explain why a session is in its current airlock state"
)

func explainCmd(flags *rootFlags) *cobra.Command {
	var jsonOutput bool
	cmd := &cobra.Command{
		Use:   explainUse,
		Short: explainShort,
		Long: `Return a human-readable explanation of why a session is in its
current airlock tier: which trigger fired, when it fired, the threat
score at the moment of escalation, and the most recent piece of
evidence recorded for the session.

Sessions at the normal tier return a "not quarantined" explanation
with the most recent recorded event (if any).

Examples:
  pipelock session explain "agent|10.0.0.1"
  pipelock session explain "agent|10.0.0.1" --json`,
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.Flags().BoolVar(&jsonOutput, flagJSON, false, usageJSON)

	cmd.RunE = func(c *cobra.Command, args []string) error {
		key := args[0]
		return runClientCmd(flags, c.Context(), c.OutOrStdout(), func(ctx context.Context, client *Client, out io.Writer) error {
			exp, err := client.Explain(ctx, key)
			if err != nil {
				return err
			}
			if jsonOutput {
				return writeJSON(out, exp)
			}
			return renderExplanation(out, exp)
		})
	}
	return cmd
}
