//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor/controlplane"
	"github.com/luckyPipewrench/pipelock/internal/license"
)

type streamStatusOptions struct {
	client  clientOptions
	orgID   string
	fleetID string
	jsonOut bool
}

// streamStatusResponse mirrors the control-plane stream-overview payload. It is
// metadata only: stream topology, the monotonicity gate (max-ever version), the
// bundle chain, and the active emergency controls in scope. There is NO
// per-follower applied version or drift here; the Conductor does not track
// per-follower applied bundle version, so this report never claims it.
type streamStatusResponse struct {
	OrgID             string                                     `json:"org_id"`
	FleetID           string                                     `json:"fleet_id"`
	Streams           []controlplane.StreamSummary               `json:"streams"`
	StreamCount       int                                        `json:"stream_count"`
	ActiveRemoteKills []controlplane.ActiveRemoteKill            `json:"active_remote_kills"`
	ActiveRollbacks   []controlplane.ActiveRollbackAuthorization `json:"active_rollback_authorizations"`
	// EmergencyControlsRead reports whether the configured EmergencyStore could
	// be enumerated. When false, the kill/rollback lists below may be
	// incomplete, so the table renderer must say so rather than letting an empty
	// list read as "no active emergency controls".
	EmergencyControlsRead bool `json:"emergency_controls_read"`
}

func streamCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "stream",
		Short: "Inspect Conductor publication stream state",
	}
	cmd.AddCommand(streamStatusCmd())
	cmd.AddCommand(streamInspectCmd())
	cmd.AddCommand(streamResetCmd())
	return cmd
}

func streamStatusCmd() *cobra.Command {
	opts := streamStatusOptions{}
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Summarize Conductor stream heads, max versions, and active emergency controls",
		Long: `Summarize the Conductor publication streams for an org/fleet.

Authorized for an auditor or admin bearer token scoped to the requested
org/fleet. The summary reports stream topology only: each stream's effective
head version and hash, the max-ever published version (the monotonicity gate),
whether an active rollback caps the head, and the active remote-kill and
rollback authorizations in scope. Per-follower applied bundle version and
last-contact time are NOT tracked by the Conductor and are not reported; use
'conductor fleet status' for the enrolled-follower roster.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := license.VerifyFleet("", "", opts.client.licenseCRLFile); err != nil {
				return err
			}
			return runStreamStatus(cmd, opts, false)
		},
	}
	bindStreamStatusFlags(cmd, &opts)
	return cmd
}

func streamInspectCmd() *cobra.Command {
	opts := streamStatusOptions{}
	cmd := &cobra.Command{
		Use:   "inspect",
		Short: "Print the full Conductor stream overview as JSON (bundle chains included)",
		Long: `Print the full Conductor stream overview JSON for an org/fleet.

Identical authorization and scope to 'conductor stream status', but always emits
the raw JSON response, including every stream's complete bundle chain
(id, version, hash, previous_bundle_hash, created_at, min_pipelock_version) and
the active emergency controls. Per-follower applied version and drift are not
included because the Conductor does not track them.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := license.VerifyFleet("", "", opts.client.licenseCRLFile); err != nil {
				return err
			}
			return runStreamStatus(cmd, opts, true)
		},
	}
	// inspect always emits JSON. Register the hidden --json flag BEFORE the
	// shared binder so the binder's Lookup("json") finds it and does not add a
	// duplicate; this keeps bindStreamStatusFlags the single source of truth for
	// the connection/scope flags.
	cmd.Flags().BoolVar(&opts.jsonOut, "json", true, "emit the raw JSON response (always true for inspect)")
	_ = cmd.Flags().MarkHidden("json")
	bindStreamStatusFlags(cmd, &opts)
	return cmd
}

func bindStreamStatusFlags(cmd *cobra.Command, opts *streamStatusOptions) {
	opts.client.bindFlags(cmd)
	cmd.Flags().StringVar(&opts.orgID, "org-id", "", "org id to query (required)")
	cmd.Flags().StringVar(&opts.fleetID, "fleet-id", "", "fleet id to scope the query")
	if cmd.Flags().Lookup("json") == nil {
		cmd.Flags().BoolVar(&opts.jsonOut, "json", false, "emit the raw JSON response instead of a table")
	}
}

func runStreamStatus(cmd *cobra.Command, opts streamStatusOptions, forceJSON bool) error {
	if strings.TrimSpace(opts.orgID) == "" {
		return errors.New("--org-id is required")
	}
	client, err := newConductorClient(opts.client)
	if err != nil {
		return err
	}
	body, err := fetchStreamStatus(cmd.Context(), client, opts)
	if err != nil {
		return err
	}
	if forceJSON || opts.jsonOut {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), string(body))
		return nil
	}
	var parsed streamStatusResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return fmt.Errorf("decode stream status response: %w", err)
	}
	return writeStreamStatusTables(cmd, parsed)
}

func fetchStreamStatus(ctx context.Context, client *conductorClient, opts streamStatusOptions) ([]byte, error) {
	return client.getStreamStatus(ctx, opts.orgID, opts.fleetID)
}

func writeStreamStatusTables(cmd *cobra.Command, resp streamStatusResponse) error {
	out := cmd.OutOrStdout()
	if resp.StreamCount == 0 {
		_, _ = fmt.Fprintln(out, "no publication streams match the query")
	} else {
		tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "ORG\tFLEET\tENVIRONMENT\tHEAD_VERSION\tMAX_VERSION\tROLLED_BACK\tHEAD_BUNDLE_ID\tHEAD_HASH\tCHAIN_LEN")
		for _, s := range resp.Streams {
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%d\t%t\t%s\t%s\t%d\n",
				s.OrgID, s.FleetID, s.Environment, s.HeadVersion, s.MaxVersion, s.RolledBack,
				s.HeadBundleID, shortHash(s.HeadBundleHash), len(s.BundleChain))
		}
		if err := tw.Flush(); err != nil {
			return fmt.Errorf("write stream table: %w", err)
		}
		_, _ = fmt.Fprintf(out, "%d stream(s)\n", resp.StreamCount)
	}
	// Fail loud when the emergency store could not be read: an empty kill /
	// rollback list must never be mistaken for "nothing active" if the read
	// itself failed. Operators rely on this line to know the lists are suspect.
	if !resp.EmergencyControlsRead {
		_, _ = fmt.Fprintln(out, "emergency controls: NOT AVAILABLE (kill/rollback list may be incomplete)")
	} else if len(resp.ActiveRemoteKills) == 0 && len(resp.ActiveRollbacks) == 0 {
		_, _ = fmt.Fprintln(out, "emergency controls: none active")
	}
	if len(resp.ActiveRemoteKills) > 0 {
		_, _ = fmt.Fprintf(out, "\n%d active remote kill(s):\n", len(resp.ActiveRemoteKills))
		tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "MESSAGE_ID\tFLEET\tSTATE\tCOUNTER\tEXPIRES_AT\tREASON")
		for _, k := range resp.ActiveRemoteKills {
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\t%s\n",
				k.MessageID, k.FleetID, k.State, k.Counter,
				k.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z"), k.Reason)
		}
		if err := tw.Flush(); err != nil {
			return fmt.Errorf("write remote kill table: %w", err)
		}
	}
	if len(resp.ActiveRollbacks) > 0 {
		_, _ = fmt.Fprintf(out, "\n%d active rollback authorization(s):\n", len(resp.ActiveRollbacks))
		tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "AUTHORIZATION_ID\tFLEET\tCURRENT_VERSION\tTARGET_VERSION\tEXPIRES_AT\tREASON")
		for _, rb := range resp.ActiveRollbacks {
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%d\t%d\t%s\t%s\n",
				rb.AuthorizationID, rb.FleetID, rb.CurrentVersion, rb.TargetVersion,
				rb.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z"), rb.Reason)
		}
		if err := tw.Flush(); err != nil {
			return fmt.Errorf("write rollback table: %w", err)
		}
	}
	return nil
}

// shortHash trims a 64-hex bundle hash to a readable prefix for the table view.
// The full hash is always available via 'conductor stream inspect' / --json.
func shortHash(hash string) string {
	const prefixLen = 12
	if len(hash) <= prefixLen {
		return hash
	}
	return hash[:prefixLen] + "…"
}
