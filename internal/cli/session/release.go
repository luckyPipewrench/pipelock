// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

const (
	releaseUse   = "release <key>"
	releaseShort = "Release an airlocked session to a lower tier"
	releaseToUse = `target tier: none (fully release) or soft (observe-only)`
)

func releaseCmd() *cobra.Command {
	var (
		toTier     string
		jsonOutput bool
	)
	cmd := &cobra.Command{
		Use:   releaseUse,
		Short: releaseShort,
		Long: `Move a quarantined session to a lower airlock tier. The default is
--to none, which fully releases the session. Use --to soft to move
the session to observe-only mode without fully clearing quarantine.

Under the hood, release wraps the /api/v1/sessions/{key}/airlock
endpoint with ForceSetTier semantics — downward transitions are
permitted for administrative recovery.

Examples:
  pipelock session release "agent|10.0.0.1"
  pipelock session release "agent|10.0.0.1" --to soft`,
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	flags := addCommonFlags(cmd)
	cmd.Flags().StringVar(&toTier, "to", "none", releaseToUse)
	cmd.Flags().BoolVar(&jsonOutput, flagJSON, false, usageJSON)

	cmd.RunE = func(c *cobra.Command, args []string) error {
		key := args[0]
		if err := validateReleaseTier(toTier); err != nil {
			return cliutil.ExitCodeError(2, err)
		}
		return runClientCmd(flags, c.Context(), c.OutOrStdout(), func(ctx context.Context, client *Client, out io.Writer) error {
			resp, err := client.Release(ctx, key, toTier)
			if err != nil {
				return err
			}
			if jsonOutput {
				return writeJSON(out, resp)
			}
			_, _ = fmt.Fprintf(out, "released %s: %s -> %s (changed=%t)\n",
				resp.Key, resp.PreviousTier, resp.NewTier, resp.Changed)
			return nil
		})
	}
	return cmd
}

// validateReleaseTier rejects any tier that is not a valid release
// target. Releasing to hard or drain does not make sense — use the
// airlock/task commands for upward transitions. "normal" is accepted
// as a synonym for "none" mirroring HandleAirlock.
func validateReleaseTier(tier string) error {
	switch tier {
	case config.AirlockTierNone, airlockTierAliasNormal, config.AirlockTierSoft:
		return nil
	}
	return errors.New("invalid --to: must be none|soft (use the airlock endpoint for upward transitions)")
}
