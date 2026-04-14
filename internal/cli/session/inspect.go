// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"io"

	"github.com/spf13/cobra"
)

const (
	inspectUse   = "inspect <key>"
	inspectShort = "Show the full detail snapshot of a session"
)

func inspectCmd() *cobra.Command {
	var jsonOutput bool
	cmd := &cobra.Command{
		Use:   inspectUse,
		Short: inspectShort,
		Long: `Dump the full SessionDetail for the given key: airlock tier, entry
time, in-flight count, threat score, and recent events. Use --json for
the raw wire format.

Examples:
  pipelock session inspect "agent|10.0.0.1"
  pipelock session inspect "agent|10.0.0.1" --json`,
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	flags := addCommonFlags(cmd)
	cmd.Flags().BoolVar(&jsonOutput, flagJSON, false, usageJSON)

	cmd.RunE = func(c *cobra.Command, args []string) error {
		key := args[0]
		return runClientCmd(flags, c.Context(), c.OutOrStdout(), func(ctx context.Context, client *Client, out io.Writer) error {
			detail, err := client.Inspect(ctx, key)
			if err != nil {
				return err
			}
			if jsonOutput {
				return writeJSON(out, detail)
			}
			return renderDetail(out, detail)
		})
	}
	return cmd
}
