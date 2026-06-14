//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor/controlplane"
	"github.com/luckyPipewrench/pipelock/internal/license"
)

type rollbackClearOptions struct {
	client          clientOptions
	authorizationID string
	confirm         bool
}

func rollbackClearCmd() *cobra.Command {
	opts := rollbackClearOptions{}
	cmd := &cobra.Command{
		Use:   "clear",
		Short: "Clear an active Conductor rollback authorization",
		Long: `clear removes an active rollback authorization from the Conductor by its
authorization_id. This is an admin-only operation that lets the operator
unblock forward publishes without waiting for the rollback TTL to expire.

The --confirm flag is required as a safety guard; the command refuses to run
without it.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := license.VerifyFleet("", "", opts.client.licenseCRLFile); err != nil {
				return err
			}
			return runRollbackClear(cmd, opts)
		},
	}
	opts.client.bindFlags(cmd)
	cmd.Flags().StringVar(&opts.authorizationID, "authorization-id", "", "authorization_id of the rollback authorization to clear (required)")
	cmd.Flags().BoolVar(&opts.confirm, "confirm", false, "explicit confirmation that you intend to clear the rollback authorization (required)")
	return cmd
}

func runRollbackClear(cmd *cobra.Command, opts rollbackClearOptions) error {
	if !opts.confirm {
		return fmt.Errorf("--confirm is required: clearing a rollback authorization is a control-plane state mutation; pass --confirm to proceed")
	}
	authID := strings.TrimSpace(opts.authorizationID)
	if authID == "" {
		return fmt.Errorf("--authorization-id is required")
	}
	client, err := newConductorClient(opts.client)
	if err != nil {
		return err
	}
	body, err := client.deleteRollbackAuthorization(cmd.Context(), authID)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), string(body))
	return nil
}

// deleteRollbackAuthorization sends a DELETE to the Conductor's
// rollback-authorizations endpoint with the authorization_id in the JSON body.
func (c *conductorClient) deleteRollbackAuthorization(ctx context.Context, authorizationID string) ([]byte, error) {
	return c.deleteJSON(ctx, controlplane.RollbackAuthorizationsPath, map[string]string{
		"authorization_id": authorizationID,
	})
}
