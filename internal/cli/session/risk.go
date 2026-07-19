// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/proxy"
)

func riskCmd(flags *rootFlags) *cobra.Command {
	var jsonOutput bool
	cmd := &cobra.Command{
		Use:           "risk [key]",
		Short:         "Show adaptive risk state for this client or a session key",
		Args:          cobra.MaximumNArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.Flags().BoolVar(&jsonOutput, flagJSON, false, usageJSON)
	cmd.RunE = func(c *cobra.Command, args []string) error {
		return runClientCmd(flags, c.Context(), c.OutOrStdout(), func(ctx context.Context, client *Client, out io.Writer) error {
			if len(args) == 0 {
				resp, err := client.AdaptiveWhoami(ctx)
				if err != nil {
					return err
				}
				if jsonOutput {
					return writeJSON(out, resp)
				}
				return renderWhoamiRisk(out, resp)
			}
			detail, err := client.Inspect(ctx, args[0])
			if err != nil {
				return err
			}
			if jsonOutput {
				return writeJSON(out, detail)
			}
			return renderSessionRisk(out, detail)
		})
	}
	return cmd
}

func renderWhoamiRisk(w io.Writer, r proxy.AdaptiveWhoami) error {
	_, _ = fmt.Fprintf(w, "session=%s level=%s score=%.2f airlock_tier=%s ttl_seconds=%d\n",
		r.SessionKey, r.EscalationLevel, r.ThreatScore, defaultIfEmpty(r.AirlockTier, "none"), r.LockdownTTLSeconds)
	return nil
}

func renderSessionRisk(w io.Writer, d proxy.SessionDetail) error {
	eta := "-"
	if !d.AutoRecoverAt.IsZero() {
		eta = d.AutoRecoverAt.UTC().Format(time.RFC3339)
	}
	hint := d.RecoverHint
	if hint == "" {
		hint = "-"
	}
	_, _ = fmt.Fprintf(w, "session=%s level=%s score=%.2f block_all=%t auto_recover_at=%s hint=%s\n",
		d.Key, d.EscalationLevel, d.ThreatScore, d.BlockAll, eta, strconv.Quote(hint))
	return nil
}
