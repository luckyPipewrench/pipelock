//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/license"
)

type killStatusOptions struct {
	client  clientOptions
	orgID   string
	fleetID string
	jsonOut bool
}

func killStatusCmd() *cobra.Command {
	opts := killStatusOptions{}
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show active Conductor remote-kill messages",
		Long: `status queries the Conductor stream-status endpoint and reports any active
remote-kill messages in scope for the given org/fleet. This is a read-only
convenience over 'conductor stream status' that filters to just the kill state.

No new server endpoint is needed; the data is already in the stream-status
response.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := license.VerifyFleet("", "", opts.client.licenseCRLFile); err != nil {
				return err
			}
			return runKillStatus(cmd, opts)
		},
	}
	opts.client.bindFlags(cmd)
	cmd.Flags().StringVar(&opts.orgID, "org-id", "", "org id to query (required)")
	cmd.Flags().StringVar(&opts.fleetID, "fleet-id", "", "fleet id to scope the query")
	cmd.Flags().BoolVar(&opts.jsonOut, "json", false, "emit the raw JSON response instead of a table")
	return cmd
}

func runKillStatus(cmd *cobra.Command, opts killStatusOptions) error {
	if strings.TrimSpace(opts.orgID) == "" {
		return errors.New("--org-id is required")
	}
	client, err := newConductorClient(opts.client)
	if err != nil {
		return err
	}
	body, err := client.getStreamStatus(cmd.Context(), opts.orgID, opts.fleetID)
	if err != nil {
		return err
	}
	if opts.jsonOut {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), string(body))
		return nil
	}
	var parsed streamStatusResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return fmt.Errorf("decode stream status response: %w", err)
	}
	return writeKillStatusTable(cmd, parsed)
}

func writeKillStatusTable(cmd *cobra.Command, resp streamStatusResponse) error {
	out := cmd.OutOrStdout()
	if !resp.EmergencyControlsRead {
		_, _ = fmt.Fprintln(out, "emergency controls: NOT AVAILABLE (kill list may be incomplete)")
	}
	if len(resp.ActiveRemoteKills) == 0 {
		_, _ = fmt.Fprintln(out, "no active remote kills")
		return nil
	}
	_, _ = fmt.Fprintf(out, "%d active remote kill(s):\n", len(resp.ActiveRemoteKills))
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "MESSAGE_ID\tFLEET\tSTATE\tCOUNTER\tEXPIRES_AT\tREASON")
	for _, k := range resp.ActiveRemoteKills {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\t%s\n",
			k.MessageID, k.FleetID, k.State, k.Counter,
			k.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z"), k.Reason)
	}
	return tw.Flush()
}
