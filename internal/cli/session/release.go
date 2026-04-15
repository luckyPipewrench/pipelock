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

func releaseCmd(flags *rootFlags) *cobra.Command {
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
	cmd.Flags().StringVar(&toTier, "to", "none", releaseToUse)
	cmd.Flags().BoolVar(&jsonOutput, flagJSON, false, usageJSON)

	cmd.RunE = func(c *cobra.Command, args []string) error {
		key := args[0]
		if err := validateReleaseTier(toTier); err != nil {
			return cliutil.ExitCodeError(2, err)
		}
		return runClientCmd(flags, c.Context(), c.OutOrStdout(), func(ctx context.Context, client *Client, out io.Writer) error {
			// Release is contract-downward. Fetch the current tier first and
			// reject any move that would escalate the session. Without this
			// check, `release --to soft` on a normal-tier session would
			// ForceSetTier upward to soft, contradicting the command's
			// recover-semantics. The inspect/release pair is best-effort
			// (the tier could change between the two calls) but prevents
			// the common misuse case; server-side enforcement would require
			// a dedicated endpoint, out of scope here.
			detail, err := client.Inspect(ctx, key)
			if err != nil {
				return err
			}
			if err := ensureDownward(detail.AirlockTier, toTier); err != nil {
				return cliutil.ExitCodeError(2, err)
			}
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

// releaseTierRank maps each airlock tier to an ordinal for downward
// comparison. Higher rank = more restrictive. A release target must be
// less than or equal to the current rank. Empty tiers are normalized to
// none (rank 0), matching runtime behavior where an unset AirlockTier
// on a snapshot means the session is not quarantined.
func releaseTierRank(tier string) int {
	switch tier {
	case "", config.AirlockTierNone, airlockTierAliasNormal:
		return 0
	case config.AirlockTierSoft:
		return 1
	case config.AirlockTierHard:
		return 2
	case config.AirlockTierDrain:
		return 3
	default:
		// Unknown tiers are treated as maximum so a stale snapshot cannot
		// accidentally authorize a release we don't understand.
		return 99
	}
}

// ensureDownward returns an error if target would raise the session's
// tier. Same-rank moves are allowed (idempotent release).
func ensureDownward(current, target string) error {
	if releaseTierRank(target) > releaseTierRank(current) {
		cur := current
		if cur == "" {
			cur = config.AirlockTierNone
		}
		return fmt.Errorf("refusing to escalate session: current tier %q, target %q — release is downward-only; use the airlock command to escalate", cur, target)
	}
	return nil
}
