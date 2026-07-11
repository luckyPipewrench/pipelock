//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package entcli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/enterprise/dashboard"
)

func dashboardBackupCmd() *cobra.Command {
	var stateDir, output string
	cmd := &cobra.Command{
		Use:   "backup",
		Short: "Back up non-reconstructible dashboard state",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := dashboard.BackupState(stateDir, output); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "dashboard durable state backed up to %s\n", output)
			return nil
		},
	}
	cmd.Flags().StringVar(&stateDir, "state-dir", "", "dashboard state directory containing durable JSON stores")
	cmd.Flags().StringVar(&output, "output", "", "output tar archive (created with mode 0600)")
	_ = cmd.MarkFlagRequired("state-dir")
	_ = cmd.MarkFlagRequired("output")
	return cmd
}

func dashboardRestoreCmd() *cobra.Command {
	var stateDir, input string
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
			if err := dashboard.RestoreState(stateDir, input); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "dashboard durable state restored from %s\n", input)
			return nil
		},
	}
	cmd.Flags().StringVar(&stateDir, "state-dir", "", "dashboard state directory to restore")
	cmd.Flags().StringVar(&input, "input", "", "validated dashboard backup tar archive")
	_ = cmd.MarkFlagRequired("state-dir")
	_ = cmd.MarkFlagRequired("input")
	return cmd
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
