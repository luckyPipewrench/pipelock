//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor/controlplane"
	"github.com/luckyPipewrench/pipelock/internal/license"
)

// policyBundlesSubdir is the subdirectory under --storage-dir that holds the
// policy-bundle store, matching what `conductor serve` passes to
// OpenFileBundleStore.
const policyBundlesSubdir = "policy-bundles"

type storeOfflineOptions struct {
	storageDir     string
	backupDir      string
	confirm        bool
	jsonOut        bool
	licenseCRLFile string
}

func (o *storeOfflineOptions) bindCommon(cmd *cobra.Command) {
	cmd.Flags().StringVar(&o.storageDir, "storage-dir", "", "Conductor storage directory (the same --storage-dir passed to 'conductor serve') (required)")
	cmd.Flags().BoolVar(&o.jsonOut, "json", false, "emit the report as JSON")
	cmd.Flags().StringVar(&o.licenseCRLFile, "license-crl-file", "", "signed license revocation list file; falls back to PIPELOCK_LICENSE_CRL_FILE")
}

func storeInspectOfflineCmd() *cobra.Command {
	opts := storeOfflineOptions{}
	cmd := &cobra.Command{
		Use:   "inspect-offline",
		Short: "Analyze the Conductor bundle store directly on disk, with no running server",
		Long: `inspect-offline reads the Conductor policy-bundle store directly from
--storage-dir without contacting (or requiring) a running Conductor. It reports
each stream's head and chain plus any provably-orphaned records that would brick
startup, and any record files that could not be parsed.

This is the recovery counterpart to 'conductor store dump', which needs a live
server over mTLS. When a store wedge crashes the server at startup, the live
commands cannot run; inspect-offline still can. It is strictly read-only.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := license.VerifyFleetWithOptions(license.FleetVerifyInputs{CRLFile: opts.licenseCRLFile}); err != nil {
				return err
			}
			return runStoreInspectOffline(cmd, opts)
		},
	}
	opts.bindCommon(cmd)
	return cmd
}

func storeRepairOfflineCmd() *cobra.Command {
	opts := storeOfflineOptions{}
	cmd := &cobra.Command{
		Use:   "repair",
		Short: "Remove provably-orphaned bundle records on disk to unbrick startup (offline)",
		Long: `repair removes provably-orphaned bundle records from the Conductor
policy-bundle store under --storage-dir, operating directly on disk with no
running server. An orphan is a record that is NOT reachable from its stream's
head, NOT covered by a durable rollback marker, and NOT a tolerated historical
fork sibling -- exactly the records that fail startup validation.

Safety posture (mirrors 'conductor stream reset'):

  - Without --confirm the command is a DRY RUN: it lists what it would remove and
    changes nothing.
  - With --confirm each removed record is first copied to a backup directory
    (default: <storage-dir>/policy-bundles/offline-repair-backup/<timestamp>).
  - It NEVER removes a record reachable from a head, a rollback-covered record, a
    tolerated fork sibling, an unreadable record, an off-chain record with a
    corrupt ancestry chain (flagged for manual review), the stream-head markers,
    or the audit store.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := license.VerifyFleetWithOptions(license.FleetVerifyInputs{CRLFile: opts.licenseCRLFile}); err != nil {
				return err
			}
			return runStoreRepairOffline(cmd, opts)
		},
	}
	opts.bindCommon(cmd)
	cmd.Flags().StringVar(&opts.backupDir, "backup-dir", "", "directory to back up removed records into (default: <storage-dir>/policy-bundles/offline-repair-backup/<timestamp>)")
	cmd.Flags().BoolVar(&opts.confirm, "confirm", false, "actually remove orphaned records; without it the command is a dry run")
	return cmd
}

func resolvePolicyBundlesDir(storageDir string) (string, error) {
	trimmed := strings.TrimSpace(storageDir)
	if trimmed == "" {
		return "", errors.New("--storage-dir is required")
	}
	abs, err := filepath.Abs(trimmed)
	if err != nil {
		return "", fmt.Errorf("resolve --storage-dir: %w", err)
	}
	return filepath.Join(abs, policyBundlesSubdir), nil
}

func runStoreInspectOffline(cmd *cobra.Command, opts storeOfflineOptions) error {
	dir, err := resolvePolicyBundlesDir(opts.storageDir)
	if err != nil {
		return err
	}
	report, err := controlplane.InspectOfflineStore(dir)
	if err != nil {
		return err
	}
	if opts.jsonOut {
		return writeJSON(cmd, report)
	}
	out := cmd.OutOrStdout()
	_, _ = fmt.Fprintf(out, "conductor bundle store: %s\n", report.BundlesDir)
	_, _ = fmt.Fprintf(out, "streams: %d\n", len(report.Streams))
	for _, s := range report.Streams {
		_, _ = fmt.Fprintf(out, "  stream %s\n", s.StreamKey)
		_, _ = fmt.Fprintf(out, "    head: %s v%d (%s)\n", s.HeadBundleID, s.HeadVersion, s.HeadBundleHash)
		_, _ = fmt.Fprintf(out, "    max version: %d, records: %d\n", s.MaxVersion, s.RecordCount)
		if s.RollbackMarker {
			_, _ = fmt.Fprintf(out, "    rollback marker: superseded_version=%d\n", s.SupersededVersion)
		}
	}
	if len(report.UnreadableRecords) > 0 {
		_, _ = fmt.Fprintf(out, "unreadable records (manual review, NOT auto-removed): %d\n", len(report.UnreadableRecords))
		for _, u := range report.UnreadableRecords {
			_, _ = fmt.Fprintf(out, "  %s: %s\n", u.FileName, u.Err)
		}
	}
	if len(report.Orphans) == 0 {
		_, _ = fmt.Fprintln(out, "orphaned records: none (store would load cleanly)")
		return nil
	}
	_, _ = fmt.Fprintf(out, "orphaned records: %d\n", len(report.Orphans))
	for _, o := range report.Orphans {
		_, _ = fmt.Fprintf(out, "  %s (%s v%d): %s\n", o.BundleHash, o.BundleID, o.Version, o.Reason)
	}
	_, _ = fmt.Fprintf(out, "run 'conductor store repair --storage-dir %s --confirm' to remove the removable orphans (backed up first)\n", opts.storageDir)
	return nil
}

func runStoreRepairOffline(cmd *cobra.Command, opts storeOfflineOptions) error {
	dir, err := resolvePolicyBundlesDir(opts.storageDir)
	if err != nil {
		return err
	}
	result, err := controlplane.RepairOfflineStore(dir, opts.backupDir, opts.confirm, time.Time{})
	if err != nil {
		return err
	}
	if opts.jsonOut {
		return writeJSON(cmd, result)
	}
	out := cmd.OutOrStdout()
	if result.DryRun {
		if len(result.Removed) == 0 {
			_, _ = fmt.Fprintln(out, "dry run: no removable orphaned records found; pass --confirm only when there are orphans to remove")
			return nil
		}
		_, _ = fmt.Fprintf(out, "dry run: would remove %d orphaned record(s); pass --confirm to proceed (each is backed up first):\n", len(result.Removed))
		for _, o := range result.Removed {
			_, _ = fmt.Fprintf(out, "  %s (%s v%d): %s\n", o.BundleHash, o.BundleID, o.Version, o.Reason)
		}
		return nil
	}
	if len(result.Removed) == 0 {
		_, _ = fmt.Fprintln(out, "no removable orphaned records found; nothing removed")
		return nil
	}
	_, _ = fmt.Fprintf(out, "removed %d orphaned record(s); backups written to %s\n", len(result.Removed), result.BackupDir)
	for _, o := range result.Removed {
		_, _ = fmt.Fprintf(out, "  removed %s (%s v%d)\n", o.BundleHash, o.BundleID, o.Version)
	}
	return nil
}

func writeJSON(cmd *cobra.Command, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal report: %w", err)
	}
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), string(data))
	return nil
}
