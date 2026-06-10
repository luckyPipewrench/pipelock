// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/proxy"
)

// BaselineCmd is the top-level `pipelock baseline` operator command.
func BaselineCmd() *cobra.Command {
	flags := &rootFlags{}
	cmd := &cobra.Command{
		Use:   "baseline",
		Short: "Inspect, ratify, and relearn behavioral baselines",
		Long: `Inspect, ratify, and relearn behavioral-baseline profiles on the
running pipelock instance. These commands use the authenticated admin API and
require kill_switch.api_token. Configure kill_switch.api_listen so the admin
API is isolated from the agent-facing proxy port.`,
	}
	bindPersistentFlags(cmd, flags)
	cmd.AddCommand(
		baselineListCmd(flags),
		baselineShowCmd(flags),
		baselineRatifyCmd(flags),
		baselineForgetCmd(flags),
	)
	return cmd
}

func baselineListCmd(flags *rootFlags) *cobra.Command {
	var jsonOutput bool
	cmd := &cobra.Command{
		Use:           "list",
		Short:         "List behavioral-baseline profiles",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.Flags().BoolVar(&jsonOutput, flagJSON, false, usageJSON)
	cmd.RunE = func(c *cobra.Command, _ []string) error {
		return runClientCmd(flags, c.Context(), c.OutOrStdout(), func(ctx context.Context, client *Client, out io.Writer) error {
			resp, err := client.BaselineList(ctx)
			if err != nil {
				return err
			}
			if jsonOutput {
				return writeJSON(out, resp)
			}
			return renderBaselineList(out, resp)
		})
	}
	return cmd
}

func baselineShowCmd(flags *rootFlags) *cobra.Command {
	var jsonOutput bool
	cmd := &cobra.Command{
		Use:           "show <agent>",
		Short:         "Show a behavioral-baseline profile",
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.Flags().BoolVar(&jsonOutput, flagJSON, false, usageJSON)
	cmd.RunE = func(c *cobra.Command, args []string) error {
		agent := args[0]
		return runClientCmd(flags, c.Context(), c.OutOrStdout(), func(ctx context.Context, client *Client, out io.Writer) error {
			resp, err := client.BaselineShow(ctx, agent)
			if err != nil {
				return err
			}
			if jsonOutput {
				return writeJSON(out, resp)
			}
			return renderBaselineProfile(out, resp)
		})
	}
	return cmd
}

func baselineRatifyCmd(flags *rootFlags) *cobra.Command {
	var jsonOutput bool
	cmd := &cobra.Command{
		Use:           "ratify <agent>",
		Short:         "Lock a pending behavioral-baseline profile",
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.Flags().BoolVar(&jsonOutput, flagJSON, false, usageJSON)
	cmd.RunE = func(c *cobra.Command, args []string) error {
		agent := args[0]
		return runClientCmd(flags, c.Context(), c.OutOrStdout(), func(ctx context.Context, client *Client, out io.Writer) error {
			resp, err := client.BaselineRatify(ctx, agent)
			if err != nil {
				return err
			}
			if jsonOutput {
				return writeJSON(out, resp)
			}
			_, _ = fmt.Fprintf(out, "ratified baseline %s: %s -> %s\n", resp.AgentKey, resp.PreviousState, resp.NewState)
			return nil
		})
	}
	return cmd
}

func baselineForgetCmd(flags *rootFlags) *cobra.Command {
	var jsonOutput bool
	cmd := &cobra.Command{
		Use:           "forget <agent>",
		Short:         "Forget a behavioral-baseline profile so it can relearn",
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.Flags().BoolVar(&jsonOutput, flagJSON, false, usageJSON)
	cmd.RunE = func(c *cobra.Command, args []string) error {
		agent := args[0]
		return runClientCmd(flags, c.Context(), c.OutOrStdout(), func(ctx context.Context, client *Client, out io.Writer) error {
			resp, err := client.BaselineForget(ctx, agent)
			if err != nil {
				return err
			}
			if jsonOutput {
				return writeJSON(out, resp)
			}
			_, _ = fmt.Fprintf(out, "forgot baseline %s: %s -> %s\n", resp.AgentKey, resp.PreviousState, resp.NewState)
			return nil
		})
	}
	return cmd
}

func renderBaselineList(w io.Writer, resp proxy.BaselineListResponse) error {
	if len(resp.Profiles) == 0 {
		_, err := fmt.Fprintln(w, "No baseline profiles found.")
		return err
	}
	_, _ = fmt.Fprintf(w, "baseline profiles: count=%d pending_ratify=%d locked=%d\n", resp.Count, resp.PendingRatify, resp.Locked)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "AGENT\tSTATE\tSESSIONS\tOBSERVED\tTRIMMED\tRATIFIED\tLEARNED")
	for _, profile := range resp.Profiles {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%d\t%t\t%s\n",
			profile.AgentKey,
			profile.State,
			profile.SessionCount,
			baselineObservedSessions(profile),
			profile.TrimmedSessionCount,
			profile.Ratified,
			formatBaselineTime(profile.LearnedAt),
		)
	}
	return tw.Flush()
}

func renderBaselineProfile(w io.Writer, profile proxy.BaselineProfile) error {
	_, _ = fmt.Fprintf(w, "Baseline %s\n", profile.AgentKey)
	_, _ = fmt.Fprintf(w, "  state:             %s\n", profile.State)
	_, _ = fmt.Fprintf(w, "  ratified:          %t\n", profile.Ratified)
	if profile.RatifiedAt != nil && !profile.RatifiedAt.IsZero() {
		_, _ = fmt.Fprintf(w, "  ratified_at:       %s\n", profile.RatifiedAt.UTC().Format(time.RFC3339))
	} else {
		_, _ = fmt.Fprintln(w, "  ratified_at:       -")
	}
	_, _ = fmt.Fprintf(w, "  learned_at:        %s\n", formatBaselineTime(profile.LearnedAt))
	_, _ = fmt.Fprintf(w, "  retained_sessions: %d\n", profile.SessionCount)
	_, _ = fmt.Fprintf(w, "  observed_sessions: %s\n", baselineObservedSessions(profile))
	_, _ = fmt.Fprintf(w, "  trimmed_sessions:  %d\n", profile.TrimmedSessionCount)
	_, _ = fmt.Fprintln(w, "  metrics:")
	writeBaselineRange(w, "tool_calls_per_session", profile.Metrics.ToolCallsPerSession)
	writeBaselineRange(w, "unique_tools_per_session", profile.Metrics.UniqueToolsPerSession)
	writeBaselineRange(w, "domains_per_session", profile.Metrics.DomainsPerSession)
	writeBaselineRange(w, "bytes_per_session", profile.Metrics.BytesPerSession)
	writeBaselineRange(w, "session_duration_sec", profile.Metrics.SessionDurationSec)
	writeBaselineRange(w, "requests_per_session", profile.Metrics.RequestsPerSession)
	return nil
}

func writeBaselineRange(w io.Writer, name string, r proxy.BaselineRange) {
	_, _ = fmt.Fprintf(w, "    %-24s min=%.2f max=%.2f mean=%.2f stddev=%.2f\n", name, r.Min, r.Max, r.Mean, r.StdDev)
}

func baselineObservedSessions(profile proxy.BaselineProfile) string {
	if profile.ObservedSessionCount <= 0 {
		return "-"
	}
	return fmt.Sprintf("%d", profile.ObservedSessionCount)
}

func formatBaselineTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format(time.RFC3339)
}
