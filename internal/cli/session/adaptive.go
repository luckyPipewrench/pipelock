// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/proxy"
)

// AdaptiveCmd is the top-level `pipelock adaptive` operator command.
func AdaptiveCmd() *cobra.Command {
	flags := &rootFlags{}
	cmd := &cobra.Command{
		Use:   "adaptive",
		Short: "Inspect and reset adaptive enforcement state",
		Long: `Inspect and reset adaptive enforcement state on the running
pipelock instance. These commands use the same authenticated admin API as
pipelock session and require the kill switch API token.`,
	}
	bindPersistentFlags(cmd, flags)
	cmd.AddCommand(
		adaptiveStatusCmd(flags),
		adaptiveFlushCmd(flags),
		adaptiveWhoamiCmd(flags),
	)
	return cmd
}

func adaptiveStatusCmd(flags *rootFlags) *cobra.Command {
	var jsonOutput bool
	cmd := &cobra.Command{
		Use:           "status",
		Short:         "Show adaptive escalation and anomaly state",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.Flags().BoolVar(&jsonOutput, flagJSON, false, usageJSON)
	cmd.RunE = func(c *cobra.Command, _ []string) error {
		return runClientCmd(flags, c.Context(), c.OutOrStdout(), func(ctx context.Context, client *Client, out io.Writer) error {
			resp, err := client.AdaptiveStatus(ctx)
			if err != nil {
				return err
			}
			if jsonOutput {
				return writeJSON(out, resp)
			}
			return renderAdaptiveStatus(out, resp)
		})
	}
	return cmd
}

func adaptiveFlushCmd(flags *rootFlags) *cobra.Command {
	var jsonOutput bool
	cmd := &cobra.Command{
		Use:           "flush",
		Short:         "Reset adaptive state without reloading config",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.Flags().BoolVar(&jsonOutput, flagJSON, false, usageJSON)
	cmd.RunE = func(c *cobra.Command, _ []string) error {
		return runClientCmd(flags, c.Context(), c.OutOrStdout(), func(ctx context.Context, client *Client, out io.Writer) error {
			resp, err := client.AdaptiveFlush(ctx)
			if err != nil {
				return err
			}
			if jsonOutput {
				return writeJSON(out, resp)
			}
			_, _ = fmt.Fprintf(out, "flushed adaptive state: identity_sessions=%d skipped_invocations=%d ip_domain_state_cleared=%t\n",
				resp.IdentitySessions, resp.SkippedInvocations, resp.IPDomainStateCleared)
			return nil
		})
	}
	return cmd
}

func adaptiveWhoamiCmd(flags *rootFlags) *cobra.Command {
	var jsonOutput bool
	cmd := &cobra.Command{
		Use:           "whoami",
		Short:         "Show adaptive classification for this client",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.Flags().BoolVar(&jsonOutput, flagJSON, false, usageJSON)
	cmd.RunE = func(c *cobra.Command, _ []string) error {
		return runClientCmd(flags, c.Context(), c.OutOrStdout(), func(ctx context.Context, client *Client, out io.Writer) error {
			resp, err := client.AdaptiveWhoami(ctx)
			if err != nil {
				return err
			}
			if jsonOutput {
				return writeJSON(out, resp)
			}
			_, _ = fmt.Fprintf(out, "client_ip=%s session=%s classification=%s tier=%s level=%s score=%.2f ttl_seconds=%d\n",
				resp.ClientIP, resp.SessionKey, resp.Classification, resp.AirlockTier, resp.EscalationLevel, resp.ThreatScore, resp.LockdownTTLSeconds)
			return nil
		})
	}
	return cmd
}

func renderAdaptiveStatus(w io.Writer, status proxy.AdaptiveStatus) error {
	_, _ = fmt.Fprintf(w, "adaptive status: sessions=%d max_level=%s ttl_seconds=%d\n",
		status.ActiveSessions, status.MaxEscalationLevel, status.LockdownTTLSeconds)
	_, _ = fmt.Fprintf(w, "levels: normal=%d elevated=%d high=%d critical=%d\n",
		status.SessionsByLevel["normal"], status.SessionsByLevel["elevated"], status.SessionsByLevel["high"], status.SessionsByLevel["critical"])
	_, _ = fmt.Fprintf(w, "airlock: none=%d soft=%d hard=%d drain=%d\n",
		status.AirlockTiers["none"], status.AirlockTiers["soft"], status.AirlockTiers["hard"], status.AirlockTiers["drain"])
	if len(status.TopAnomalies) == 0 {
		_, _ = fmt.Fprintln(w, "top_anomalies: none")
		return nil
	}
	_, _ = fmt.Fprintln(w, "top_anomalies:")
	for _, a := range status.TopAnomalies {
		_, _ = fmt.Fprintf(w, "  %s %d\n", a.Name, a.Count)
	}
	return nil
}
