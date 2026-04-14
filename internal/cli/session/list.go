// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"errors"
	"io"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

const (
	listUse     = "list"
	listShort   = "List active sessions and their airlock tiers"
	listTierDoc = `filter sessions by airlock tier (none|soft|hard|drain|normal)`
)

func listCmd() *cobra.Command {
	var (
		tier       string
		jsonOutput bool
	)
	cmd := &cobra.Command{
		Use:   listUse,
		Short: listShort,
		Long: `List all active sessions and their current airlock tier.

Use --tier to filter by quarantine state. Use --json for machine output.

Examples:
  pipelock session list
  pipelock session list --tier hard
  pipelock session list --json`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	flags := addCommonFlags(cmd)
	cmd.Flags().StringVar(&tier, "tier", "", listTierDoc)
	cmd.Flags().BoolVar(&jsonOutput, flagJSON, false, usageJSON)

	cmd.RunE = func(c *cobra.Command, _ []string) error {
		if err := validateTierFilter(tier); err != nil {
			return cliutil.ExitCodeError(2, err)
		}
		return runClientCmd(flags, c.Context(), c.OutOrStdout(), func(ctx context.Context, client *Client, out io.Writer) error {
			resp, err := client.List(ctx, tier)
			if err != nil {
				return err
			}
			if jsonOutput {
				return writeJSON(out, resp)
			}
			return renderList(out, resp.Sessions)
		})
	}
	return cmd
}

// validateTierFilter rejects obviously-bogus tier filters before a round
// trip to the server. The server re-validates, but a local check gives
// operators a faster feedback loop and a clearer error.
func validateTierFilter(tier string) error {
	if tier == "" {
		return nil
	}
	switch tier {
	case config.AirlockTierNone,
		config.AirlockTierSoft,
		config.AirlockTierHard,
		config.AirlockTierDrain,
		airlockTierAliasNormal:
		return nil
	}
	return errors.New("invalid --tier: must be none|soft|hard|drain|normal")
}

// airlockTierAliasNormal mirrors the server-side alias: "normal" is
// accepted on the wire as a synonym for the "none" tier. Defined here
// so the CLI validates without importing the unexported proxy constant.
const airlockTierAliasNormal = "normal"
