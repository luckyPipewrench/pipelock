//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package entcli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/enterprise/dashboard"
)

func dashboardBackupCmd() *cobra.Command {
	var stateDir, output, exemptionStore, deliveryInbox, legalHoldStore string
	cmd := &cobra.Command{
		Use:   "backup",
		Short: "Back up non-reconstructible dashboard state",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			result, err := dashboard.BackupStateWithOptions(dashboard.BackupOptions{
				StateDir:           stateDir,
				ArchivePath:        output,
				ExemptionStorePath: exemptionStore,
				DeliveryInboxPath:  deliveryInbox,
				LegalHoldStorePath: legalHoldStore,
			})
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "dashboard durable state backed up to %s (captured stores: %s)\n",
				output, formatDashboardStoreList(result.CapturedStores))
			if len(result.MissingStores) > 0 {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "dashboard durable state stores not present: %s\n", formatDashboardStoreList(result.MissingStores))
			}
			if strings.TrimSpace(legalHoldStore) == "" {
				_, _ = fmt.Fprintln(cmd.OutOrStdout(), "legal holds not captured: --legal-hold-store was not set")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&stateDir, "state-dir", "", "dashboard state directory containing durable JSON stores")
	cmd.Flags().StringVar(&output, "output", "", "output tar archive (created with mode 0600)")
	cmd.Flags().StringVar(&exemptionStore, "exemption-store", "", "optional exemption lifecycle store file; defaults to <state-dir>/exemptions.json")
	cmd.Flags().StringVar(&deliveryInbox, "delivery-inbox", "", "optional alert delivery inbox file; defaults to <state-dir>/delivery-inbox.json")
	cmd.Flags().StringVar(&legalHoldStore, "legal-hold-store", "", "optional legal-hold metadata store file to include")
	_ = cmd.MarkFlagRequired("state-dir")
	_ = cmd.MarkFlagRequired("output")
	return cmd
}

func dashboardRestoreCmd() *cobra.Command {
	var stateDir, input, exemptionStore, deliveryInbox, legalHoldStore string
	cmd := &cobra.Command{
		Use:   "restore",
		Short: "Validate and restore dashboard durable state (per-file atomic write, rollback on failure)",
		Long: `Validate a dashboard backup archive and restore the durable state files.

Each file is written atomically and a runtime failure rolls back every file to its
prior contents. This is per-file atomicity with best-effort whole-set rollback, not a
single cross-file transaction: a process crash between file writes can leave a mixed
generation on disk. Re-run restore to converge.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			result, err := dashboard.RestoreStateWithOptions(dashboard.RestoreOptions{
				StateDir:           stateDir,
				ArchivePath:        input,
				ExemptionStorePath: exemptionStore,
				DeliveryInboxPath:  deliveryInbox,
				LegalHoldStorePath: legalHoldStore,
			})
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "dashboard durable state restored from %s (restored stores: %s)\n",
				input, formatDashboardStoreList(result.RestoredStores))
			return nil
		},
	}
	cmd.Flags().StringVar(&stateDir, "state-dir", "", "dashboard state directory to restore")
	cmd.Flags().StringVar(&input, "input", "", "validated dashboard backup tar archive")
	cmd.Flags().StringVar(&exemptionStore, "exemption-store", "", "optional exemption lifecycle store file; defaults to <state-dir>/exemptions.json")
	cmd.Flags().StringVar(&deliveryInbox, "delivery-inbox", "", "optional alert delivery inbox file; defaults to <state-dir>/delivery-inbox.json")
	cmd.Flags().StringVar(&legalHoldStore, "legal-hold-store", "", "optional legal-hold metadata store file to restore")
	_ = cmd.MarkFlagRequired("state-dir")
	_ = cmd.MarkFlagRequired("input")
	return cmd
}

func formatDashboardStoreList(stores []string) string {
	if len(stores) == 0 {
		return "none"
	}
	return strings.Join(stores, ", ")
}

func dashboardRebuildReadModelCmd() *cobra.Command {
	var sourceDir, output string
	cmd := &cobra.Command{
		Use:   "rebuild-read-model",
		Short: "Rebuild a disposable dashboard index from recorder evidence",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := dashboard.RebuildReadModel(dashboard.RebuildOptions{SourceDir: sourceDir, Output: output}); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "dashboard read model rebuilt from %s into %s\n", sourceDir, output)
			return nil
		},
	}
	cmd.Flags().StringVar(&sourceDir, "receipt-dir", "", "source recorder evidence directory")
	cmd.Flags().StringVar(&output, "output", "", "disposable read-model index path")
	_ = cmd.MarkFlagRequired("receipt-dir")
	_ = cmd.MarkFlagRequired("output")
	return cmd
}
