//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
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

const (
	conductorBackupSchema = "pipelock-conductor-storage-backup-v1"
	backupManifestFile    = "conductor-backup-manifest.json"
	backupStorageSubdir   = "storage"
)

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

func storeBackupCmd() *cobra.Command {
	opts := storeOfflineOptions{}
	cmd := &cobra.Command{
		Use:   "backup",
		Short: "Create an offline backup of Conductor control-plane storage",
		Long: `backup copies the Conductor storage directory into a manifest-wrapped
backup directory. Run it while the Conductor is stopped, or from a crash-
consistent volume snapshot mounted read-only, so policy bundles, stream heads,
enrollments, emergency controls, and audit evidence are captured together.

The backup includes the contents under --storage-dir. It does not collect
operator signing keys or TLS private keys that live outside that directory;
those must remain under the deployment's normal secret/KMS backup process.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := license.VerifyFleetWithOptions(license.FleetVerifyInputs{CRLFile: opts.licenseCRLFile}); err != nil {
				return err
			}
			return runStoreBackup(cmd, opts)
		},
	}
	opts.bindCommon(cmd)
	cmd.Flags().StringVar(&opts.backupDir, "backup-dir", "", "empty destination directory for the backup (required; must not be inside --storage-dir)")
	return cmd
}

func storeRestoreCmd() *cobra.Command {
	opts := storeOfflineOptions{}
	cmd := &cobra.Command{
		Use:   "restore",
		Short: "Restore Conductor control-plane storage from an offline backup",
		Long: `restore rebuilds --storage-dir from a backup created by
'conductor store backup'. Without --confirm it is a dry run. With --confirm,
any existing storage directory is moved aside to a sibling
.pre-restore-<timestamp> directory before the restored copy is installed. A
non-directory target at --storage-dir is rejected.

Run restore while the Conductor is stopped. Restore does not restore signing
or TLS private keys outside the storage directory; restore those through the
deployment's secret/KMS process before starting the Conductor.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := license.VerifyFleetWithOptions(license.FleetVerifyInputs{CRLFile: opts.licenseCRLFile}); err != nil {
				return err
			}
			return runStoreRestore(cmd, opts)
		},
	}
	opts.bindCommon(cmd)
	cmd.Flags().StringVar(&opts.backupDir, "backup-dir", "", "backup directory created by 'conductor store backup' (required)")
	cmd.Flags().BoolVar(&opts.confirm, "confirm", false, "actually restore storage; without it the command is a dry run")
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

type conductorBackupManifest struct {
	Schema           string    `json:"schema"`
	CreatedAt        time.Time `json:"created_at"`
	SourceStorageDir string    `json:"source_storage_dir"`
	Includes         []string  `json:"includes"`
}

func runStoreBackup(cmd *cobra.Command, opts storeOfflineOptions) error {
	storageDir, err := resolveStorageDir(opts.storageDir)
	if err != nil {
		return err
	}
	// The source must be an actual directory: backing up a regular file or a
	// symlink would produce an archive that restore later rejects, so fail
	// closed here with a clear message instead of deep in copyDir.
	if st, err := os.Lstat(storageDir); err != nil {
		return fmt.Errorf("stat --storage-dir: %w", err)
	} else if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
		return fmt.Errorf("--storage-dir is not a directory: %s", storageDir)
	}
	backupDir, err := resolveBackupDir(opts.backupDir)
	if err != nil {
		return err
	}
	if err := rejectBackupInsideStorage(storageDir, backupDir); err != nil {
		return err
	}
	if empty, err := dirMissingOrEmpty(backupDir); err != nil {
		return err
	} else if !empty {
		return fmt.Errorf("--backup-dir %s already exists and is not empty", backupDir)
	}
	if err := os.MkdirAll(filepath.Dir(backupDir), 0o750); err != nil {
		return fmt.Errorf("create backup parent: %w", err)
	}
	tmp := backupDir + ".tmp-" + fmt.Sprint(time.Now().UnixNano())
	if err := os.MkdirAll(tmp, 0o750); err != nil {
		return fmt.Errorf("create backup temp dir: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(tmp)
		}
	}()
	if err := copyDir(storageDir, filepath.Join(tmp, backupStorageSubdir)); err != nil {
		return fmt.Errorf("copy conductor storage: %w", err)
	}
	manifest := conductorBackupManifest{
		Schema:           conductorBackupSchema,
		CreatedAt:        time.Now().UTC(),
		SourceStorageDir: storageDir,
		Includes: []string{
			"policy-bundles",
			"enrollments.json",
			"emergency-controls",
			"audit.db",
		},
	}
	if err := writeBackupManifest(filepath.Join(tmp, backupManifestFile), manifest); err != nil {
		return err
	}
	if err := os.Rename(tmp, backupDir); err != nil {
		return fmt.Errorf("install backup directory: %w", err)
	}
	committed = true
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "created conductor storage backup at %s\n", backupDir)
	return nil
}

func runStoreRestore(cmd *cobra.Command, opts storeOfflineOptions) error {
	storageDir, err := resolveStorageDir(opts.storageDir)
	if err != nil {
		return err
	}
	backupDir, err := resolveBackupDir(opts.backupDir)
	if err != nil {
		return err
	}
	manifest, err := readBackupManifest(filepath.Join(backupDir, backupManifestFile))
	if err != nil {
		return err
	}
	if manifest.Schema != conductorBackupSchema {
		return fmt.Errorf("backup schema %q is unsupported", manifest.Schema)
	}
	source := filepath.Join(backupDir, backupStorageSubdir)
	if st, err := os.Stat(source); err != nil {
		return fmt.Errorf("stat backup storage: %w", err)
	} else if !st.IsDir() {
		return fmt.Errorf("backup storage path is not a directory: %s", source)
	}
	if !opts.confirm {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "DRY RUN: would restore Conductor storage from %s into %s\n", backupDir, storageDir)
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Re-run with --confirm while Conductor is stopped to apply.")
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(storageDir), 0o750); err != nil {
		return fmt.Errorf("create restore parent: %w", err)
	}
	tmp := storageDir + ".restore-tmp-" + fmt.Sprint(time.Now().UnixNano())
	if err := copyDir(source, tmp); err != nil {
		_ = os.RemoveAll(tmp)
		return fmt.Errorf("copy backup storage: %w", err)
	}
	previous := ""
	if st, err := os.Lstat(storageDir); err == nil {
		if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
			_ = os.RemoveAll(tmp)
			return fmt.Errorf("storage dir exists but is not a directory: %s", storageDir)
		}
		previous = storageDir + ".pre-restore-" + time.Now().UTC().Format("20060102T150405Z")
		if err := os.Rename(storageDir, previous); err != nil {
			_ = os.RemoveAll(tmp)
			return fmt.Errorf("move existing storage aside: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		_ = os.RemoveAll(tmp)
		return fmt.Errorf("stat storage dir: %w", err)
	}
	if err := os.Rename(tmp, storageDir); err != nil {
		if previous != "" {
			_ = os.Rename(previous, storageDir)
		}
		_ = os.RemoveAll(tmp)
		return fmt.Errorf("install restored storage: %w", err)
	}
	if previous == "" {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "restored conductor storage from %s into %s\n", backupDir, storageDir)
		return nil
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "restored conductor storage from %s into %s; previous storage moved to %s\n", backupDir, storageDir, previous)
	return nil
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

func resolveStorageDir(storageDir string) (string, error) {
	trimmed := strings.TrimSpace(storageDir)
	if trimmed == "" {
		return "", errors.New("--storage-dir is required")
	}
	abs, err := filepath.Abs(trimmed)
	if err != nil {
		return "", fmt.Errorf("resolve --storage-dir: %w", err)
	}
	return abs, nil
}

func resolveBackupDir(backupDir string) (string, error) {
	trimmed := strings.TrimSpace(backupDir)
	if trimmed == "" {
		return "", errors.New("--backup-dir is required")
	}
	abs, err := filepath.Abs(trimmed)
	if err != nil {
		return "", fmt.Errorf("resolve --backup-dir: %w", err)
	}
	return abs, nil
}

func rejectBackupInsideStorage(storageDir, backupDir string) error {
	rel, err := filepath.Rel(storageDir, backupDir)
	if err != nil {
		return fmt.Errorf("compare backup and storage dirs: %w", err)
	}
	if rel == "." || (!strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != "..") {
		return fmt.Errorf("--backup-dir must not be inside --storage-dir")
	}
	return nil
}

func dirMissingOrEmpty(dir string) (bool, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("read dir %s: %w", dir, err)
	}
	return len(entries) == 0, nil
}

func writeBackupManifest(path string, manifest conductorBackupManifest) error {
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal backup manifest: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(filepath.Clean(path), data, 0o600); err != nil {
		return fmt.Errorf("write backup manifest: %w", err)
	}
	return nil
}

func readBackupManifest(path string) (conductorBackupManifest, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return conductorBackupManifest{}, fmt.Errorf("read backup manifest: %w", err)
	}
	var manifest conductorBackupManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return conductorBackupManifest{}, fmt.Errorf("decode backup manifest: %w", err)
	}
	return manifest, nil
}

func copyDir(src, dst string) error {
	src = filepath.Clean(src)
	dst = filepath.Clean(dst)
	return filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to copy symlink %s", path)
		}
		if d.IsDir() {
			return os.MkdirAll(target, 0o750)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("refusing to copy non-regular file %s", path)
		}
		return copyRegularFile(path, target)
	})
}

func copyRegularFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		return err
	}
	in, err := os.Open(filepath.Clean(src))
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(filepath.Clean(dst), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		_ = out.Close()
		if !committed {
			_ = os.Remove(dst)
		}
	}()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	if err := out.Sync(); err != nil {
		return err
	}
	committed = true
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
