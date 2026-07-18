//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package entcli

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/enterprise/dashboard"
	"github.com/luckyPipewrench/pipelock/internal/license"
)

type legalHoldListOptions struct {
	storePath string
}

type legalHoldAddOptions struct {
	storePath string
	id        string
	scope     string
	reason    string
	created   string
}

type legalHoldReleaseOptions struct {
	storePath string
	id        string
	released  string
}

func legalHoldCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "legal-hold", Short: "Manage legal-hold metadata outside the dashboard HTTP authority"}
	cmd.AddCommand(legalHoldListCmd(), legalHoldAddCmd(), legalHoldReleaseCmd())
	return cmd
}

func legalHoldListCmd() *cobra.Command {
	opts := legalHoldListOptions{}
	cmd := &cobra.Command{
		Use: "list", Short: "List legal-hold metadata", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := license.VerifyAgentsWithOptions(license.FleetVerifyInputs{}); err != nil {
				return err
			}
			return runLegalHoldList(cmd, opts)
		},
	}
	cmd.Flags().StringVar(&opts.storePath, "store", "", "path to the legal-hold JSON store")
	_ = cmd.MarkFlagRequired("store")
	return cmd
}

func legalHoldAddCmd() *cobra.Command {
	opts := legalHoldAddOptions{}
	cmd := &cobra.Command{
		Use: "add", Short: "Create an active legal hold", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := license.VerifyAgentsWithOptions(license.FleetVerifyInputs{}); err != nil {
				return err
			}
			return runLegalHoldAdd(cmd, opts)
		},
	}
	cmd.Flags().StringVar(&opts.storePath, "store", "", "path to the legal-hold JSON store")
	cmd.Flags().StringVar(&opts.id, "id", "", "operator-assigned unique hold ID")
	cmd.Flags().StringVar(&opts.scope, "scope", "", "bounded evidence scope retained by the hold")
	cmd.Flags().StringVar(&opts.reason, "reason", "", "reason for the hold")
	cmd.Flags().StringVar(&opts.created, "created", "", "creation time in RFC3339 (default: now)")
	_ = cmd.MarkFlagRequired("store")
	_ = cmd.MarkFlagRequired("id")
	_ = cmd.MarkFlagRequired("scope")
	_ = cmd.MarkFlagRequired("reason")
	return cmd
}

func legalHoldReleaseCmd() *cobra.Command {
	opts := legalHoldReleaseOptions{}
	cmd := &cobra.Command{
		Use: "release", Short: "Release an active legal hold", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := license.VerifyAgentsWithOptions(license.FleetVerifyInputs{}); err != nil {
				return err
			}
			return runLegalHoldRelease(cmd, opts)
		},
	}
	cmd.Flags().StringVar(&opts.storePath, "store", "", "path to the legal-hold JSON store")
	cmd.Flags().StringVar(&opts.id, "id", "", "legal hold ID to release")
	cmd.Flags().StringVar(&opts.released, "released", "", "release time in RFC3339 (default: now)")
	_ = cmd.MarkFlagRequired("store")
	_ = cmd.MarkFlagRequired("id")
	return cmd
}

func runLegalHoldList(cmd *cobra.Command, opts legalHoldListOptions) error {
	store, err := dashboard.OpenLegalHoldStore(opts.storePath)
	if err != nil {
		return err
	}
	holds := store.List()
	if len(holds) == 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "no legal holds")
		return nil
	}
	for _, hold := range holds {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "id: %s\nscope: %s\nreason: %s\ncreated: %s\nreleased: %s\nstatus: %s\n\n",
			hold.ID, hold.Scope, hold.Reason, hold.CreatedDisplay(), hold.ReleasedDisplay(), hold.Status())
	}
	return nil
}

func runLegalHoldAdd(cmd *cobra.Command, opts legalHoldAddOptions) error {
	created, err := optionalRFC3339(opts.created, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("--created: %w", err)
	}
	store, err := dashboard.OpenLegalHoldStore(opts.storePath)
	if err != nil {
		return err
	}
	hold := dashboard.LegalHold{ID: opts.id, Scope: opts.scope, Reason: opts.reason, Created: created}
	if err := store.Add(hold); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "created legal hold %s\n", hold.ID)
	return nil
}

func runLegalHoldRelease(cmd *cobra.Command, opts legalHoldReleaseOptions) error {
	released, err := optionalRFC3339(opts.released, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("--released: %w", err)
	}
	store, err := dashboard.OpenLegalHoldStore(opts.storePath)
	if err != nil {
		return err
	}
	if err := store.Release(opts.id, released); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "released legal hold %s\n", opts.id)
	return nil
}

func optionalRFC3339(value string, fallback time.Time) (time.Time, error) {
	if value == "" {
		return fallback, nil
	}
	return time.Parse(time.RFC3339, value)
}
