//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor/controlplane"
	"github.com/luckyPipewrench/pipelock/internal/license"
)

type streamResetOptions struct {
	client  clientOptions
	orgID   string
	fleetID string
	confirm bool
}

func streamResetCmd() *cobra.Command {
	opts := streamResetOptions{}
	cmd := &cobra.Command{
		Use:   "reset",
		Short: "Clear all active rollback authorizations from the Conductor emergency store",
		Long: `reset removes all currently active (non-expired) rollback authorizations for
the given org/fleet scope from the Conductor's emergency store. This is a
destructive admin-only operation: it unblocks forward publishes by removing ALL
active rollback state rather than clearing individual authorizations.

The --confirm flag is required as a safety guard; the command refuses to run
without it. Prefer 'conductor rollback clear --authorization-id <id>' to remove
a single rollback authorization.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := license.VerifyFleet("", "", opts.client.licenseCRLFile); err != nil {
				return err
			}
			return runStreamReset(cmd, opts)
		},
	}
	opts.client.bindFlags(cmd)
	cmd.Flags().StringVar(&opts.orgID, "org-id", "", "org id to scope the reset (required)")
	cmd.Flags().StringVar(&opts.fleetID, "fleet-id", "", "fleet id to scope the reset")
	cmd.Flags().BoolVar(&opts.confirm, "confirm", false, "explicit confirmation that you intend to clear all active rollback authorizations (required)")
	return cmd
}

func runStreamReset(cmd *cobra.Command, opts streamResetOptions) error {
	if !opts.confirm {
		return fmt.Errorf("--confirm is required: stream reset clears all active rollback authorizations; pass --confirm to proceed")
	}
	orgID := strings.TrimSpace(opts.orgID)
	if orgID == "" {
		return errors.New("--org-id is required")
	}
	// Fetch the stream status to discover active rollback authorizations.
	client, err := newConductorClient(opts.client)
	if err != nil {
		return err
	}
	body, err := client.getStreamStatus(cmd.Context(), orgID, opts.fleetID)
	if err != nil {
		return err
	}
	var status streamStatusResponse
	if err := json.Unmarshal(body, &status); err != nil {
		return fmt.Errorf("decode stream status: %w", err)
	}
	activeRollbacks, err := rollbackAuthorizationsForReset(status)
	if err != nil {
		return err
	}
	if len(activeRollbacks) == 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "no active rollback authorizations to clear")
		return nil
	}
	// Clear each active rollback authorization individually via the DELETE endpoint.
	cleared := 0
	for _, rb := range activeRollbacks {
		_, err := client.deleteRollbackAuthorization(cmd.Context(), rb.AuthorizationID)
		if err != nil {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warning: failed to clear %s: %v\n", rb.AuthorizationID, err)
			continue
		}
		cleared++
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "cleared rollback authorization %s (target_version=%d)\n",
			rb.AuthorizationID, rb.TargetVersion)
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "cleared %d of %d active rollback authorization(s)\n",
		cleared, len(activeRollbacks))
	return nil
}

func rollbackAuthorizationsForReset(status streamStatusResponse) ([]controlplane.ActiveRollbackAuthorization, error) {
	if !status.EmergencyControlsRead {
		return nil, errors.New("stream reset cannot confirm active rollback state: emergency controls were not readable")
	}
	return status.ActiveRollbacks, nil
}
