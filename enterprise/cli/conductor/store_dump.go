//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/license"
)

type storeDumpOptions struct {
	client  clientOptions
	orgID   string
	fleetID string
}

func storeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "store",
		Short: "Inspect Conductor control-plane store state",
	}
	cmd.AddCommand(storeDumpCmd())
	return cmd
}

func storeDumpCmd() *cobra.Command {
	opts := storeDumpOptions{}
	cmd := &cobra.Command{
		Use:   "dump",
		Short: "Dump the Conductor stream overview as JSON for support and debugging",
		Long: `dump performs a read-only query of the Conductor stream-status
endpoint and prints its JSON response. This is a convenience for operators
gathering support artifacts. No state is modified.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := license.VerifyFleet("", "", opts.client.licenseCRLFile); err != nil {
				return err
			}
			return runStoreDump(cmd, opts)
		},
	}
	opts.client.bindFlags(cmd)
	cmd.Flags().StringVar(&opts.orgID, "org-id", "", "org id to query (required)")
	cmd.Flags().StringVar(&opts.fleetID, "fleet-id", "", "fleet id to scope the query")
	return cmd
}

func runStoreDump(cmd *cobra.Command, opts storeDumpOptions) error {
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
	// Pretty-print the raw JSON.
	var parsed json.RawMessage
	if err := json.Unmarshal(body, &parsed); err != nil {
		// If it's not valid JSON for some reason, print raw.
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), string(body))
		return nil
	}
	pretty, err := json.MarshalIndent(parsed, "", "  ")
	if err != nil {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), string(body))
		return nil
	}
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), string(pretty))
	return nil
}
