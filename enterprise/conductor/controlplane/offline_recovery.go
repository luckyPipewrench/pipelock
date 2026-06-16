//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package controlplane

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

const offlineBackupDirName = "offline-repair-backup"

// OfflineOrphan is one bundle record that the offline analyzer found to be a
// provably-orphaned, fatal record: not reachable from its stream's head, not
// covered by a durable rollback marker, and not a tolerated historical fork
// sibling. These are exactly the records that brick startup, and the only records
// the offline repair is permitted to remove.
type OfflineOrphan struct {
	BundleHash string `json:"bundle_hash"`
	BundleID   string `json:"bundle_id"`
	Version    uint64 `json:"version"`
	StreamKey  string `json:"stream_key"`
	FileName   string `json:"file_name"`
	Reason     string `json:"reason"`
	// Removable is true only for the plain "not reachable / not covered" orphan
	// class that repair is allowed to delete. Off-chain records whose own ancestry
	// chain is corrupt are reported with Removable=false for manual review.
	Removable bool `json:"removable"`
}

// OfflineStreamReport is the read-only view of one stream's chain topology as the
// offline analyzer reconstructed it directly from disk.
type OfflineStreamReport struct {
	StreamKey         string   `json:"stream_key"`
	HeadBundleID      string   `json:"head_bundle_id"`
	HeadBundleHash    string   `json:"head_bundle_hash"`
	HeadVersion       uint64   `json:"head_version"`
	MaxVersion        uint64   `json:"max_version"`
	RollbackMarker    bool     `json:"rollback_marker"`
	SupersededVersion uint64   `json:"superseded_version,omitempty"`
	ReachableHashes   []string `json:"reachable_hashes"`
	RecordCount       int      `json:"record_count"`
}

// OfflineUnreadableRecord is a bundle-record file the analyzer could not parse or
// validate. It is reported but NEVER removed by repair: an unreadable file may be
// a transient IO issue or a partially-written record, and deleting it could lose
// recoverable history. The operator must investigate these by hand.
type OfflineUnreadableRecord struct {
	FileName string `json:"file_name"`
	Err      string `json:"error"`
}

// OfflineReport is the full read-only result of analyzing a Conductor bundle store
// directory without a running server.
type OfflineReport struct {
	BundlesDir        string                    `json:"bundles_dir"`
	StreamHeadsDir    string                    `json:"stream_heads_dir"`
	Streams           []OfflineStreamReport     `json:"streams"`
	Orphans           []OfflineOrphan           `json:"orphans"`
	UnreadableRecords []OfflineUnreadableRecord `json:"unreadable_records"`
}

// OfflineRepairResult reports what a repair run removed (or, in dry-run mode,
// would remove) and where each removed record was backed up.
type OfflineRepairResult struct {
	BackupDir string          `json:"backup_dir"`
	Removed   []OfflineOrphan `json:"removed"`
	DryRun    bool            `json:"dry_run"`
}

// loadOfflineStore reads every bundle record and rollback marker under the given
// policy-bundles directory into an in-memory FileBundleStore WITHOUT running the
// fatal chain verification. Unparseable records are collected and skipped rather
// than aborting, so a single corrupt file never blinds the whole analysis. The
// returned store has records, streams (heads), and rollbackHeads populated.
//
// policyBundlesDir is the directory passed to OpenFileBundleStore (i.e.
// <storage-dir>/policy-bundles), inside which bundles/ and stream-heads/ live.
func loadOfflineStore(policyBundlesDir string) (*FileBundleStore, []OfflineUnreadableRecord, error) {
	clean := filepath.Clean(policyBundlesDir)
	if !filepath.IsAbs(clean) {
		return nil, nil, fmt.Errorf("conductor offline store dir must be absolute: %s", policyBundlesDir)
	}
	info, err := os.Stat(clean)
	if err != nil {
		return nil, nil, fmt.Errorf("conductor offline store dir: %w", err)
	}
	if !info.IsDir() {
		return nil, nil, fmt.Errorf("conductor offline store dir %s is not a directory", clean)
	}
	store := &FileBundleStore{
		dir:            clean,
		bundlesDir:     filepath.Join(clean, bundlesDirName),
		streamHeadsDir: filepath.Join(clean, streamHeadsDirName),
		records:        make(map[string]PublishedBundle),
		streams:        make(map[string]PublishedBundle),
		rollbackHeads:  make(map[string]streamHeadRecord),
	}

	var unreadable []OfflineUnreadableRecord
	bundleEntries, err := os.ReadDir(store.bundlesDir)
	if err != nil {
		return nil, nil, fmt.Errorf("conductor offline read bundle dir: %w", err)
	}
	names := make([]string, 0, len(bundleEntries))
	for _, entry := range bundleEntries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		names = append(names, entry.Name())
	}
	slices.Sort(names)
	for _, name := range names {
		record, err := readBundleRecord(filepath.Join(store.bundlesDir, name))
		if err != nil {
			unreadable = append(unreadable, OfflineUnreadableRecord{FileName: name, Err: err.Error()})
			continue
		}
		if _, exists := store.records[record.BundleHash]; exists {
			// A duplicate hash is genuine corruption, but offline analysis is
			// tolerant: report it as unreadable context rather than aborting.
			unreadable = append(unreadable, OfflineUnreadableRecord{
				FileName: name,
				Err:      fmt.Sprintf("%v: duplicate bundle_hash %q", ErrInvalidStoreRecord, record.BundleHash),
			})
			continue
		}
		if existing, err := store.bundleByIDVersionLocked(record.Bundle.BundleID, record.Bundle.Version); err == nil {
			unreadable = append(unreadable, OfflineUnreadableRecord{
				FileName: name,
				Err: fmt.Sprintf("%v: duplicate bundle_id/version %q/%d already present as %s",
					ErrInvalidStoreRecord, record.Bundle.BundleID, record.Bundle.Version, existing.BundleHash),
			})
			continue
		} else if !errors.Is(err, ErrBundleNotFound) {
			unreadable = append(unreadable, OfflineUnreadableRecord{FileName: name, Err: err.Error()})
			continue
		}
		store.records[record.BundleHash] = record
		if current, ok := store.streams[record.StreamKey]; !ok || newerRecord(record, current) {
			store.streams[record.StreamKey] = record
		}
	}

	headEntries, err := os.ReadDir(store.streamHeadsDir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, nil, fmt.Errorf("conductor offline read stream-head dir: %w", err)
	}
	headNames := make([]string, 0, len(headEntries))
	for _, entry := range headEntries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		headNames = append(headNames, entry.Name())
	}
	slices.Sort(headNames)
	for _, name := range headNames {
		marker, err := readStreamHeadRecord(filepath.Join(store.streamHeadsDir, name))
		if err != nil {
			unreadable = append(unreadable, OfflineUnreadableRecord{FileName: name, Err: err.Error()})
			continue
		}
		// Only honor a marker whose filename and target bundle match, mirroring
		// loadStreamHeadRecordsLocked. A mismatched marker is reported but ignored
		// for classification so it cannot cause a record to be wrongly tolerated.
		if name != streamHeadRecordFileName(marker.StreamKey) {
			unreadable = append(unreadable, OfflineUnreadableRecord{
				FileName: name,
				Err:      "stream-head marker filename does not match stream key",
			})
			continue
		}
		target, ok := store.records[marker.TargetBundleHash]
		if !ok {
			unreadable = append(unreadable, OfflineUnreadableRecord{
				FileName: name,
				Err:      "rollback target bundle missing",
			})
			continue
		}
		if err := validateStreamHeadRecord(marker, target); err != nil {
			unreadable = append(unreadable, OfflineUnreadableRecord{FileName: name, Err: err.Error()})
			continue
		}
		rawHead, ok := store.streams[marker.StreamKey]
		if !ok {
			unreadable = append(unreadable, OfflineUnreadableRecord{
				FileName: name,
				Err:      "stream-head marker references unknown stream",
			})
			continue
		}
		store.rollbackHeads[marker.StreamKey] = marker
		if rawHead.Bundle.Version <= marker.SupersededVersion {
			store.streams[marker.StreamKey] = target
		}
	}
	return store, unreadable, nil
}

// classifyOfflineLocked reconstructs the per-stream chain topology and the set of
// provably-orphaned records using the SAME reachability, rollback-coverage, and
// tolerated-historical-fork predicates the live load path uses. A record is an
// orphan only when it is fatal at load: not reachable from the head, not covered
// by a rollback marker, AND not a tolerated fork sibling. A head whose own chain
// is broken (missing/cross-stream/non-monotonic/cycle ancestor) is NOT silently
// repaired: its records are left untouched and the stream is reported so the
// operator investigates rather than the tool deleting head history.
func (s *FileBundleStore) classifyOfflineLocked() ([]OfflineStreamReport, []OfflineOrphan) {
	streamReports := make([]OfflineStreamReport, 0, len(s.streams))
	var orphans []OfflineOrphan

	for streamKey, head := range s.streams {
		seen := make(map[string]struct{}, 4)
		headChainOK := s.walkChainLocked(streamKey, head, seen) == nil
		reachable := make([]string, 0, len(seen))
		for h := range seen {
			reachable = append(reachable, h)
		}
		slices.Sort(reachable)

		marker, hasMarker := s.rollbackHeads[streamKey]
		streamReports = append(streamReports, OfflineStreamReport{
			StreamKey:         streamKey,
			HeadBundleID:      head.Bundle.BundleID,
			HeadBundleHash:    head.BundleHash,
			HeadVersion:       head.Bundle.Version,
			MaxVersion:        s.maxStreamVersionLocked(streamKey),
			RollbackMarker:    hasMarker,
			SupersededVersion: marker.SupersededVersion,
			ReachableHashes:   reachable,
			RecordCount:       s.streamRecordCountLocked(streamKey),
		})

		if !headChainOK {
			// Do not classify orphans against an unverifiable head chain; deleting
			// records here could destroy head history. Leave the stream for manual
			// inspection.
			continue
		}

		for hash, record := range s.records {
			if record.StreamKey != streamKey {
				continue
			}
			if _, ok := seen[hash]; ok {
				continue
			}
			if s.rollbackSupersedesRecordLocked(record) {
				continue
			}
			tolerated, err := s.isToleratedHistoricalForkLocked(streamKey, record, head, seen)
			if err != nil {
				// The sibling chain is itself corrupt. Do not auto-remove a record
				// whose own chain is broken; report it but leave it for the operator.
				orphans = append(orphans, OfflineOrphan{
					BundleHash: hash,
					BundleID:   record.Bundle.BundleID,
					Version:    record.Bundle.Version,
					StreamKey:  streamKey,
					FileName:   hash + ".json",
					Reason:     "off-chain record with a corrupt ancestry chain (manual review): " + err.Error(),
					Removable:  false,
				})
				continue
			}
			if tolerated {
				continue
			}
			orphans = append(orphans, OfflineOrphan{
				BundleHash: hash,
				BundleID:   record.Bundle.BundleID,
				Version:    record.Bundle.Version,
				StreamKey:  streamKey,
				FileName:   hash + ".json",
				Reason:     "not reachable from stream head and not covered by a rollback marker",
				Removable:  true,
			})
		}
	}

	slices.SortFunc(streamReports, func(a, b OfflineStreamReport) int {
		return strings.Compare(a.StreamKey, b.StreamKey)
	})
	slices.SortFunc(orphans, func(a, b OfflineOrphan) int {
		return strings.Compare(a.BundleHash, b.BundleHash)
	})
	return streamReports, orphans
}

func (s *FileBundleStore) streamRecordCountLocked(streamKey string) int {
	count := 0
	for _, record := range s.records {
		if record.StreamKey == streamKey {
			count++
		}
	}
	return count
}

// removableOrphans filters classified orphans to those the repair is allowed to
// delete: only the plain "not reachable / not covered" class (Removable=true).
// Off-chain records flagged for manual review (corrupt sibling chains) are excluded
// so repair never deletes a record whose own chain is broken.
func removableOrphans(orphans []OfflineOrphan) []OfflineOrphan {
	out := make([]OfflineOrphan, 0, len(orphans))
	for _, o := range orphans {
		if o.Removable {
			out = append(out, o)
		}
	}
	return out
}

// InspectOfflineStore analyzes a Conductor policy-bundle store directory without a
// running server and returns its stream topology plus any provably-orphaned or
// unreadable records. It is strictly read-only.
//
// policyBundlesDir is <storage-dir>/policy-bundles (the path serve passes to
// OpenFileBundleStore).
func InspectOfflineStore(policyBundlesDir string) (OfflineReport, error) {
	store, unreadable, err := loadOfflineStore(policyBundlesDir)
	if err != nil {
		return OfflineReport{}, err
	}
	streams, orphans := store.classifyOfflineLocked()
	return OfflineReport{
		BundlesDir:        store.bundlesDir,
		StreamHeadsDir:    store.streamHeadsDir,
		Streams:           streams,
		Orphans:           orphans,
		UnreadableRecords: unreadable,
	}, nil
}

// RepairOfflineStore removes provably-orphaned bundle records from a Conductor
// policy-bundle store directory, backing up each removed record first. It NEVER
// removes a record reachable from a head, a record covered by a rollback marker, a
// tolerated historical fork sibling, an unreadable record, an off-chain record
// flagged for manual review, or anything under stream-heads/ or the audit store.
//
// When confirm is false the function is a dry run: it reports what it WOULD remove
// and writes no backups and deletes nothing. backupDir, when empty, defaults to
// <storage-dir>/policy-bundles/offline-repair-backup/<RFC3339-UTC-timestamp>.
func RepairOfflineStore(policyBundlesDir, backupDir string, confirm bool, now time.Time) (OfflineRepairResult, error) {
	store, _, err := loadOfflineStore(policyBundlesDir)
	if err != nil {
		return OfflineRepairResult{}, err
	}
	_, orphans := store.classifyOfflineLocked()
	removable := removableOrphans(orphans)

	if !confirm {
		return OfflineRepairResult{Removed: removable, DryRun: true}, nil
	}
	if len(removable) == 0 {
		return OfflineRepairResult{Removed: nil, DryRun: false}, nil
	}

	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	resolvedBackup := strings.TrimSpace(backupDir)
	if resolvedBackup == "" {
		resolvedBackup = filepath.Join(store.dir, offlineBackupDirName, now.Format("20060102T150405Z"))
	}
	resolvedBackup = filepath.Clean(resolvedBackup)
	if err := os.MkdirAll(resolvedBackup, bundleStoreDirMode); err != nil {
		return OfflineRepairResult{}, fmt.Errorf("conductor offline repair create backup dir %s: %w", resolvedBackup, err)
	}

	removed := make([]OfflineOrphan, 0, len(removable))
	for _, orphan := range removable {
		src := filepath.Join(store.bundlesDir, orphan.FileName)
		// Re-validate that this is exactly one of the records we classified and that
		// the on-disk file still parses to the same orphan hash before touching it.
		record, err := readBundleRecord(src)
		if err != nil {
			return finalizeRepair(resolvedBackup, removed), fmt.Errorf("conductor offline repair re-read %s: %w", orphan.FileName, err)
		}
		if record.BundleHash != orphan.BundleHash {
			return finalizeRepair(resolvedBackup, removed), fmt.Errorf("conductor offline repair %s: on-disk hash %q does not match classified orphan %q",
				orphan.FileName, record.BundleHash, orphan.BundleHash)
		}
		data, err := os.ReadFile(filepath.Clean(src))
		if err != nil {
			return finalizeRepair(resolvedBackup, removed), fmt.Errorf("conductor offline repair read %s: %w", orphan.FileName, err)
		}
		backupPath := filepath.Join(resolvedBackup, orphan.FileName)
		if err := durableWrite(backupPath, data); err != nil {
			return finalizeRepair(resolvedBackup, removed), fmt.Errorf("conductor offline repair back up %s: %w", orphan.FileName, err)
		}
		if err := os.Remove(src); err != nil {
			return finalizeRepair(resolvedBackup, removed), fmt.Errorf("conductor offline repair remove %s: %w", orphan.FileName, err)
		}
		removed = append(removed, orphan)
	}
	if err := fsyncDir(store.bundlesDir); err != nil {
		return finalizeRepair(resolvedBackup, removed), err
	}
	return finalizeRepair(resolvedBackup, removed), nil
}

func finalizeRepair(backupDir string, removed []OfflineOrphan) OfflineRepairResult {
	return OfflineRepairResult{BackupDir: backupDir, Removed: removed, DryRun: false}
}
