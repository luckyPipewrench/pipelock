// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
	signing "github.com/luckyPipewrench/pipelock/internal/signing"
)

type (
	compactOptions  struct{ receiptDir, locationID, sessionID, publicKey string }
	compactManifest struct {
		Version     int                   `json:"version"`
		SessionID   string                `json:"session_id"`
		CreatedAt   time.Time             `json:"created_at"`
		Original    []compactManifestFile `json:"original"`
		Replacement []compactManifestFile `json:"replacement"`
		Mappings    []compactByteMapping  `json:"mappings"`
	}
)

type compactManifestFile struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}
type compactByteMapping struct {
	Source       string `json:"source"`
	Output       string `json:"output"`
	SourceOffset int64  `json:"source_offset"`
	OutputOffset int64  `json:"output_offset"`
	Bytes        int64  `json:"bytes"`
}

var (
	compactAcquireLock   = recorder.AcquireEvidenceCeremonyLock
	compactMakeStage     = os.MkdirTemp
	compactPrepareStage  = prepareCompactStage
	compactSyncPath      = syncCompactDirectory
	compactExchange      = exchangeEvidenceDirectories
	compactRename        = os.Rename
	compactWriteManifest = writeCompactManifest
	compactStreamStage   = streamCompactToStage
	compactVerifyStream  = streamCompactFiles
)

func compactCmd() *cobra.Command {
	opts := compactOptions{}
	cmd := &cobra.Command{Use: "compact", Short: "Offline-compact one stopped flight-recorder session", Long: `Compact one stopped flight-recorder session into bounded JSONL shards. It requires a trusted public key, verifies before and after the rewrite, atomically exchanges the active directory on Linux, and retains the original as a digest-listed archive.`, Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error { return runCompact(cmd, opts) }}
	cmd.Flags().StringVar(&opts.receiptDir, "receipt-dir", "", "flight-recorder evidence directory")
	cmd.Flags().StringVar(&opts.locationID, "location", "", "location path relative to the evidence directory")
	cmd.Flags().StringVar(&opts.sessionID, "session", "", "session ID to compact")
	cmd.Flags().StringVar(&opts.publicKey, "key", "", "trusted receipt signing public key (inline or file)")
	_ = cmd.MarkFlagRequired("receipt-dir")
	_ = cmd.MarkFlagRequired("session")
	_ = cmd.MarkFlagRequired("key")
	return cmd
}

func runCompact(cmd *cobra.Command, opts compactOptions) error {
	if strings.TrimSpace(opts.sessionID) == "" {
		return errors.New("--session is required")
	}
	root, err := validateReceiptDir(opts.receiptDir)
	if err != nil {
		return err
	}
	location, err := recorder.ResolveEvidenceLocation(root, opts.locationID)
	if err != nil {
		return fmt.Errorf("resolve evidence location: %w", err)
	}
	key, err := signing.LoadPublicKey(strings.TrimSpace(opts.publicKey))
	if err != nil {
		return fmt.Errorf("load --key: %w", err)
	}
	lock, err := compactAcquireLock(location.Dir)
	if err != nil {
		return fmt.Errorf("lock stopped evidence directory: %w", err)
	}
	defer func() { _ = lock.Close() }()
	sourceNames, err := compactStreamNames(location, opts.sessionID)
	if err != nil {
		return err
	}
	parent := filepath.Dir(location.Dir)
	stage, err := compactMakeStage(parent, ".pipelock-evidence-compact-")
	if err != nil {
		return fmt.Errorf("create compaction stage: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(stage)
		}
	}()
	if err := compactPrepareStage(location.Dir, stage); err != nil {
		return fmt.Errorf("preserve active directory metadata on stage: %w", err)
	}
	writer, original, err := compactStreamStage(location, sourceNames, opts.sessionID, key, stage)
	if err != nil {
		return err
	}
	if len(writer.files) > recorder.MaxEvidenceReadDirectoryEntries {
		return fmt.Errorf("compaction produced %d shards, exceeds %d", len(writer.files), recorder.MaxEvidenceReadDirectoryEntries)
	}
	if err := compactSyncPath(stage); err != nil {
		return fmt.Errorf("sync staged evidence directory: %w", err)
	}
	if err := compactSyncPath(parent); err != nil {
		return fmt.Errorf("sync evidence parent before publication: %w", err)
	}
	stageLocation := recorder.EvidenceLocation{Root: stage, Dir: stage}
	stagedNames, err := compactStreamNames(stageLocation, opts.sessionID)
	if err != nil {
		return fmt.Errorf("list staged evidence: %w", err)
	}
	post, err := compactVerifyStream(stageLocation, stagedNames, opts.sessionID, key, func(compactStreamFile, []byte, recorder.Entry) error { return nil })
	if err != nil {
		return fmt.Errorf("re-validate staged compacted evidence: %w", err)
	}
	if !sameCompactProof(original, post) {
		return errors.New("compaction changed original JSONL bytes or signed receipt proof")
	}
	manifest := compactManifest{Version: 1, SessionID: opts.sessionID, CreatedAt: time.Now().UTC(), Original: manifestStreamFiles(original.files), Replacement: manifestStreamFiles(writer.files), Mappings: writer.mappings}
	archive := filepath.Join(parent, ".pipelock-evidence-archive-"+time.Now().UTC().Format("20060102T150405.000000000Z"))
	stageLock, err := compactAcquireLock(stage)
	if err != nil {
		return fmt.Errorf("lock staged evidence directory: %w", err)
	}
	defer func() { _ = stageLock.Close() }()
	recheck, err := compactVerifyStream(location, sourceNames, opts.sessionID, key, func(compactStreamFile, []byte, recorder.Entry) error { return nil })
	if err != nil || !sameCompactProof(original, recheck) {
		if err == nil {
			err = errors.New("source digest changed")
		}
		return fmt.Errorf("source changed before publication: %w", err)
	}
	currentNames, err := compactStreamNames(location, opts.sessionID)
	if err != nil || !sameCompactNameSet(sourceNames, currentNames) {
		if err == nil {
			err = errors.New("source shard name set changed")
		}
		return fmt.Errorf("source changed before publication: %w", err)
	}
	if err := compactExchange(location.Dir, stage); err != nil {
		return fmt.Errorf("atomically exchange active evidence directory: %w", err)
	}
	if err := compactRename(stage, archive); err != nil {
		return rollbackCompactExchange(location.Dir, stage, fmt.Errorf("preserve original evidence archive at %s: %w", stage, err))
	}
	// The manifest belongs beside the archived inputs. Writing it only after
	// the exchange keeps the active directory to evidence shards alone and
	// leaves every original JSONL byte unchanged.
	if err := compactWriteManifest(archive, manifest); err != nil {
		return rollbackCompactExchange(location.Dir, archive, fmt.Errorf("write archive digest manifest: %w", err))
	}
	if err := compactSyncPath(archive); err != nil {
		return rollbackCompactExchange(location.Dir, archive, fmt.Errorf("sync archive manifest: %w", err))
	}
	if err := compactSyncPath(parent); err != nil {
		return rollbackCompactExchange(location.Dir, archive, fmt.Errorf("sync evidence parent after archive: %w", err))
	}
	committed = true
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "compacted session %q into %d bounded shard(s); original preserved at %s\n", opts.sessionID, len(writer.files), archive)
	return nil
}

func rollbackCompactExchange(active, old string, cause error) error {
	manifestPath := filepath.Join(old, "compaction-manifest.json")
	if err := os.Remove(manifestPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.Join(cause, fmt.Errorf("CRITICAL rollback could not remove archive manifest before restoring original: %w", err))
	}
	if err := syncCompactDirectory(old); err != nil {
		return errors.Join(cause, fmt.Errorf("CRITICAL rollback could not sync original archive before restoring it: %w", err))
	}
	if err := exchangeEvidenceDirectories(active, old); err != nil {
		return errors.Join(cause, fmt.Errorf("CRITICAL rollback exchange failed: %w", err))
	}
	if err := os.RemoveAll(old); err != nil {
		return errors.Join(cause, fmt.Errorf("rollback restored active but could not remove compacted directory %s: %w", old, err))
	}
	return cause
}

func writeCompactManifest(dir string, manifest compactManifest) error {
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("encode archive manifest: %w", err)
	}
	return os.WriteFile(filepath.Join(dir, "compaction-manifest.json"), append(data, '\n'), 0o600)
}
