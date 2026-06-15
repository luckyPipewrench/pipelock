//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor/controlplane"
	"github.com/luckyPipewrench/pipelock/internal/license"
)

type auditQueryOptions struct {
	client     clientOptions
	orgID      string
	fleetID    string
	instanceID string
	batchID    string
	limit      int
}

func auditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Inspect Conductor audit-batch metadata",
	}
	cmd.AddCommand(auditQueryCmd())
	return cmd
}

func auditQueryCmd() *cobra.Command {
	opts := auditQueryOptions{}
	cmd := &cobra.Command{
		Use:   "query",
		Short: "Query accepted audit-batch metadata from a Conductor",
		Long: `Query the metadata-only audit-batch records a Conductor has accepted.

Authorized for an auditor or admin bearer token whose org/fleet scope covers the
requested org/fleet. The response contains batch metadata (sequence ranges,
hashes, counts, timestamps) only; raw audit evidence stays behind the
Conductor's storage backend and is never returned by this endpoint.

Provide --batch-id together with --fleet-id and --instance-id to fetch a single
batch; omit it to list the most recent batches for the scope.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// License gate: audit query is an Enterprise fleet operator tool.
			// Fail closed before any network connection.
			if _, err := license.VerifyFleetWithOptions(license.FleetVerifyInputs{CRLFile: opts.client.licenseCRLFile}); err != nil {
				return err
			}
			return runAuditQuery(cmd, opts)
		},
	}
	opts.client.bindFlags(cmd)
	cmd.Flags().StringVar(&opts.orgID, "org-id", "", "org id to query (required)")
	cmd.Flags().StringVar(&opts.fleetID, "fleet-id", "", "fleet id to scope the query")
	cmd.Flags().StringVar(&opts.instanceID, "instance-id", "", "follower instance id to scope the query")
	cmd.Flags().StringVar(&opts.batchID, "batch-id", "", "fetch a single batch by id (requires --fleet-id and --instance-id)")
	cmd.Flags().IntVar(&opts.limit, "limit", 0, "maximum number of batches to list (server clamps to its configured ceiling)")
	return cmd
}

func runAuditQuery(cmd *cobra.Command, opts auditQueryOptions) error {
	if strings.TrimSpace(opts.orgID) == "" {
		return errors.New("--org-id is required")
	}
	if opts.batchID != "" && (strings.TrimSpace(opts.fleetID) == "" || strings.TrimSpace(opts.instanceID) == "") {
		return errors.New("--batch-id requires --fleet-id and --instance-id")
	}
	// Reject characters that would split the path or smuggle query parameters:
	// the batch id is concatenated into the URL path before the query string,
	// so a '/', '?', or '#' would corrupt the request. The server also rejects
	// a path-embedded '/', but failing locally gives a clearer error.
	if strings.ContainsAny(opts.batchID, "/?#") {
		return errors.New("--batch-id must not contain '/', '?', or '#'")
	}
	if opts.limit < 0 {
		return errors.New("--limit must be non-negative")
	}
	client, err := newConductorClient(opts.client)
	if err != nil {
		return err
	}
	if opts.batchID != "" {
		return runAuditBatchGet(cmd, client, opts)
	}
	return runAuditBatchList(cmd, client, opts)
}

func runAuditBatchList(cmd *cobra.Command, client *conductorClient, opts auditQueryOptions) error {
	params := map[string]string{
		"org_id":      opts.orgID,
		"fleet_id":    opts.fleetID,
		"instance_id": opts.instanceID,
	}
	if opts.limit > 0 {
		params["limit"] = strconv.Itoa(opts.limit)
	}
	path := controlplane.AuditBatchesPath + encodeQuery(params)
	body, err := client.getJSON(cmd.Context(), path)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), string(body))
	return nil
}

func runAuditBatchGet(cmd *cobra.Command, client *conductorClient, opts auditQueryOptions) error {
	params := map[string]string{
		"org_id":      opts.orgID,
		"fleet_id":    opts.fleetID,
		"instance_id": opts.instanceID,
	}
	path := controlplane.AuditBatchesPath + "/" + opts.batchID + encodeQuery(params)
	body, err := client.getJSON(cmd.Context(), path)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), string(body))
	return nil
}
