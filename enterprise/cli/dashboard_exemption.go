//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package entcli

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/enterprise/dashboard"
	"github.com/luckyPipewrench/pipelock/internal/license"
)

const exemptionIDBytes = 8

func exemptionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "exemption",
		Short: "Manage exemption lifecycle records (Pro/Enterprise)",
	}
	cmd.AddCommand(
		exemptionListCmd(),
		exemptionAddCmd(),
		exemptionExpireCmd(),
		exemptionRenewCmd(),
		exemptionTouchCmd(),
		exemptionRemoveCmd(),
	)
	return cmd
}

func exemptionListCmd() *cobra.Command {
	var storePath string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all exemption lifecycle records",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := license.VerifyAgentsWithOptions(license.FleetVerifyInputs{}); err != nil {
				return err
			}
			store, err := dashboard.OpenExemptionStore(storePath)
			if err != nil {
				return err
			}
			now := time.Now()
			records := store.List()
			if len(records) == 0 {
				_, _ = fmt.Fprintln(cmd.OutOrStdout(), "no exemption records")
				return nil
			}
			for _, rec := range records {
				printRecord(cmd, rec, now)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&storePath, "store", "", "path to the exemption store JSON file")
	_ = cmd.MarkFlagRequired("store")
	return cmd
}

func exemptionAddCmd() *cobra.Command {
	var (
		storePath string
		scope     string
		owner     string
		reason    string
		expiryStr string
		createdBy string
	)
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add a new exemption lifecycle record",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := license.VerifyAgentsWithOptions(license.FleetVerifyInputs{}); err != nil {
				return err
			}
			expiry, err := time.Parse(time.RFC3339, expiryStr)
			if err != nil {
				return fmt.Errorf("--expiry: %w", err)
			}
			store, err := dashboard.OpenExemptionStore(storePath)
			if err != nil {
				return err
			}
			now := time.Now()
			id, err := generateExemptionID()
			if err != nil {
				return fmt.Errorf("generate id: %w", err)
			}
			rec := dashboard.ExemptionRecord{
				ID:        id,
				Scope:     scope,
				Owner:     owner,
				Reason:    reason,
				CreatedBy: createdBy,
				Created:   now,
				Expiry:    expiry,
			}
			if err := store.Add(rec, now); err != nil {
				return err
			}
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "created exemption record:")
			printRecord(cmd, rec, now)
			return nil
		},
	}
	cmd.Flags().StringVar(&storePath, "store", "", "path to the exemption store JSON file")
	cmd.Flags().StringVar(&scope, "scope", "", "scope identifier matching the config exemption entry")
	cmd.Flags().StringVar(&owner, "owner", "", "owner of this exemption")
	cmd.Flags().StringVar(&reason, "reason", "", "justification for the exemption")
	cmd.Flags().StringVar(&expiryStr, "expiry", "", "expiry time in RFC3339 format")
	cmd.Flags().StringVar(&createdBy, "by", "", "who created this record (optional)")
	_ = cmd.MarkFlagRequired("store")
	_ = cmd.MarkFlagRequired("scope")
	_ = cmd.MarkFlagRequired("owner")
	_ = cmd.MarkFlagRequired("reason")
	_ = cmd.MarkFlagRequired("expiry")
	return cmd
}

func exemptionExpireCmd() *cobra.Command {
	var (
		storePath string
		id        string
	)
	cmd := &cobra.Command{
		Use:   "expire",
		Short: "Expire an exemption record immediately",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := license.VerifyAgentsWithOptions(license.FleetVerifyInputs{}); err != nil {
				return err
			}
			store, err := dashboard.OpenExemptionStore(storePath)
			if err != nil {
				return err
			}
			if err := store.Expire(id, time.Now()); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "expired exemption record %s\n", id)
			return nil
		},
	}
	cmd.Flags().StringVar(&storePath, "store", "", "path to the exemption store JSON file")
	cmd.Flags().StringVar(&id, "id", "", "record ID to expire")
	_ = cmd.MarkFlagRequired("store")
	_ = cmd.MarkFlagRequired("id")
	return cmd
}

func exemptionRenewCmd() *cobra.Command {
	var (
		storePath string
		id        string
		expiryStr string
	)
	cmd := &cobra.Command{
		Use:   "renew",
		Short: "Renew an exemption record with a new expiry",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := license.VerifyAgentsWithOptions(license.FleetVerifyInputs{}); err != nil {
				return err
			}
			expiry, err := time.Parse(time.RFC3339, expiryStr)
			if err != nil {
				return fmt.Errorf("--expiry: %w", err)
			}
			store, err := dashboard.OpenExemptionStore(storePath)
			if err != nil {
				return err
			}
			if err := store.Renew(id, expiry); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "renewed exemption record %s, new expiry %s\n", id, expiry.Format(time.RFC3339))
			return nil
		},
	}
	cmd.Flags().StringVar(&storePath, "store", "", "path to the exemption store JSON file")
	cmd.Flags().StringVar(&id, "id", "", "record ID to renew")
	cmd.Flags().StringVar(&expiryStr, "expiry", "", "new expiry time in RFC3339 format")
	_ = cmd.MarkFlagRequired("store")
	_ = cmd.MarkFlagRequired("id")
	_ = cmd.MarkFlagRequired("expiry")
	return cmd
}

func exemptionTouchCmd() *cobra.Command {
	var (
		storePath string
		id        string
		whenStr   string
	)
	cmd := &cobra.Command{
		Use:   "touch",
		Short: "Update the last-matched timestamp for an exemption record",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := license.VerifyAgentsWithOptions(license.FleetVerifyInputs{}); err != nil {
				return err
			}
			store, err := dashboard.OpenExemptionStore(storePath)
			if err != nil {
				return err
			}
			when := time.Now()
			if whenStr != "" {
				when, err = time.Parse(time.RFC3339, whenStr)
				if err != nil {
					return fmt.Errorf("--when: %w", err)
				}
			}
			if err := store.Touch(id, when); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "touched exemption record %s at %s\n", id, when.Format(time.RFC3339))
			return nil
		},
	}
	cmd.Flags().StringVar(&storePath, "store", "", "path to the exemption store JSON file")
	cmd.Flags().StringVar(&id, "id", "", "record ID to touch")
	cmd.Flags().StringVar(&whenStr, "when", "", "timestamp in RFC3339 format (default: now)")
	_ = cmd.MarkFlagRequired("store")
	_ = cmd.MarkFlagRequired("id")
	return cmd
}

func exemptionRemoveCmd() *cobra.Command {
	var (
		storePath string
		id        string
	)
	cmd := &cobra.Command{
		Use:   "remove",
		Short: "Remove an exemption record from the store",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := license.VerifyAgentsWithOptions(license.FleetVerifyInputs{}); err != nil {
				return err
			}
			store, err := dashboard.OpenExemptionStore(storePath)
			if err != nil {
				return err
			}
			if err := store.Remove(id); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "removed exemption record %s\n", id)
			return nil
		},
	}
	cmd.Flags().StringVar(&storePath, "store", "", "path to the exemption store JSON file")
	cmd.Flags().StringVar(&id, "id", "", "record ID to remove")
	_ = cmd.MarkFlagRequired("store")
	_ = cmd.MarkFlagRequired("id")
	return cmd
}

func generateExemptionID() (string, error) {
	b := make([]byte, exemptionIDBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "exm_" + hex.EncodeToString(b), nil
}

func printRecord(cmd *cobra.Command, rec dashboard.ExemptionRecord, now time.Time) {
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  id:           %s\n", rec.ID)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  scope:        %s\n", rec.Scope)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  owner:        %s\n", rec.Owner)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  reason:       %s\n", rec.Reason)
	if rec.CreatedBy != "" {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  created_by:   %s\n", rec.CreatedBy)
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  created:      %s\n", rec.Created.Format(time.RFC3339))
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  expiry:       %s\n", rec.Expiry.Format(time.RFC3339))
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  status:       %s\n", rec.Status(now))
	if rec.LastMatched != nil {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  last_matched: %s\n", rec.LastMatched.Format(time.RFC3339))
	} else {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  last_matched: not observed\n")
	}
	_, _ = fmt.Fprintln(cmd.OutOrStdout())
}
