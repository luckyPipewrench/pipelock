//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor/controlplane"
	"github.com/luckyPipewrench/pipelock/internal/license"
)

type fleetStatusOptions struct {
	client     clientOptions
	orgID      string
	fleetID    string
	instanceID string
	limit      int
	jsonOut    bool
}

type followersResponse struct {
	Followers []controlplane.FollowerSummary `json:"followers"`
	Count     int                            `json:"count"`
}

func fleetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fleet",
		Short: "Inspect Conductor fleet topology",
	}
	cmd.AddCommand(fleetStatusCmd())
	cmd.AddCommand(fleetReportCmd())
	return cmd
}

func fleetStatusCmd() *cobra.Command {
	opts := fleetStatusOptions{}
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show enrolled followers and their enrollment state",
		Long: `Show the followers enrolled with a Conductor for an org/fleet.

Authorized for an auditor or admin bearer token scoped to the requested
org/fleet. The roster is enrollment metadata only: identity, audit key id,
enrollment time, and active state. Applied bundle version and last-contact time
are NOT tracked by the Conductor enrollment store today and are not reported.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := license.VerifyFleetWithOptions(license.FleetVerifyInputs{CRLFile: opts.client.licenseCRLFile}); err != nil {
				return err
			}
			return runFleetStatus(cmd, opts, false)
		},
	}
	bindFleetStatusFlags(cmd, &opts)
	return cmd
}

// followersCmd is the top-level alias of `fleet status`. It reads the same
// enrolled-follower roster; the two share one endpoint and one implementation.
func followersCmd() *cobra.Command {
	opts := fleetStatusOptions{}
	cmd := &cobra.Command{
		Use:   "followers",
		Short: "List enrolled Conductor followers (alias of 'fleet status')",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := license.VerifyFleetWithOptions(license.FleetVerifyInputs{CRLFile: opts.client.licenseCRLFile}); err != nil {
				return err
			}
			return runFleetStatus(cmd, opts, false)
		},
	}
	bindFleetStatusFlags(cmd, &opts)
	return cmd
}

func bindFleetStatusFlags(cmd *cobra.Command, opts *fleetStatusOptions) {
	opts.client.bindFlags(cmd)
	cmd.Flags().StringVar(&opts.orgID, "org-id", "", "org id to query (required)")
	cmd.Flags().StringVar(&opts.fleetID, "fleet-id", "", "fleet id to scope the query")
	cmd.Flags().StringVar(&opts.instanceID, "instance-id", "", "follower instance id to scope the query")
	cmd.Flags().IntVar(&opts.limit, "limit", 0, "maximum number of followers to list (server clamps to its configured ceiling)")
	cmd.Flags().BoolVar(&opts.jsonOut, "json", false, "emit the raw JSON response instead of a table")
}

func runFleetStatus(cmd *cobra.Command, opts fleetStatusOptions, _ bool) error {
	if strings.TrimSpace(opts.orgID) == "" {
		return errors.New("--org-id is required")
	}
	if opts.limit < 0 {
		return errors.New("--limit must be non-negative")
	}
	client, err := newConductorClient(opts.client)
	if err != nil {
		return err
	}
	body, err := fetchFollowers(cmd.Context(), client, opts)
	if err != nil {
		return err
	}
	if opts.jsonOut {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), string(body))
		return nil
	}
	var parsed followersResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return fmt.Errorf("decode followers response: %w", err)
	}
	return writeFollowerTable(cmd, parsed)
}

func fetchFollowers(ctx context.Context, client *conductorClient, opts fleetStatusOptions) ([]byte, error) {
	params := map[string]string{
		"org_id":      opts.orgID,
		"fleet_id":    opts.fleetID,
		"instance_id": opts.instanceID,
	}
	if opts.limit > 0 {
		params["limit"] = strconv.Itoa(opts.limit)
	}
	return client.getJSON(ctx, controlplane.FollowersPath+encodeQuery(params))
}

func writeFollowerTable(cmd *cobra.Command, resp followersResponse) error {
	out := cmd.OutOrStdout()
	if resp.Count == 0 {
		_, _ = fmt.Fprintln(out, "no enrolled followers match the query")
		return nil
	}
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "ORG\tFLEET\tINSTANCE\tENVIRONMENT\tAUDIT_KEY_ID\tACTIVE\tENROLLED_AT")
	for _, f := range resp.Followers {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%t\t%s\n",
			f.OrgID, f.FleetID, f.InstanceID, f.Environment, f.AuditKeyID, f.Active,
			f.EnrolledAt.UTC().Format("2006-01-02T15:04:05Z"))
	}
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("write follower table: %w", err)
	}
	_, _ = fmt.Fprintf(out, "%d follower(s)\n", resp.Count)
	return nil
}
