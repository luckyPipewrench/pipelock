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
	compactOptions struct {
		receiptDir, locationID, sessionID, publicKey string
		allowDegradedReceipts                        int
		allowUnsignedCheckpoints                     int
	}
	compactManifest struct {
		Version                int                                   `json:"version"`
		SessionID              string                                `json:"session_id"`
		CreatedAt              time.Time                             `json:"created_at"`
		ReceiptVerification    compactManifestReceiptVerification    `json:"receipt_verification"`
		CheckpointVerification compactManifestCheckpointVerification `json:"checkpoint_verification"`
		Original               []compactManifestFile                 `json:"original"`
		Replacement            []compactManifestFile                 `json:"replacement"`
		Mappings               []compactByteMapping                  `json:"mappings"`
	}
)

type compactManifestCheckpointVerification struct {
	Status   string                      `json:"status"`
	Unsigned []compactUnsignedCheckpoint `json:"unsigned,omitempty"`
}

type compactManifestReceiptVerification struct {
	Status       string                      `json:"status"`
	V1Count      uint64                      `json:"v1_signed_receipts"`
	V1ChainHead  string                      `json:"v1_chain_head,omitempty"`
	V2Count      uint64                      `json:"v2_signed_receipts"`
	V2ChainHead  string                      `json:"v2_chain_head,omitempty"`
	Degradations []compactReceiptDegradation `json:"degradations,omitempty"`
	V1Suffixes   []compactReceiptSuffix      `json:"v1_verified_suffixes,omitempty"`
}

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
	cmd.Flags().IntVar(&opts.allowDegradedReceipts, "allow-degraded-receipts", 0, "acknowledge exactly N recognized irrecoverable receipt gaps")
	cmd.Flags().IntVar(&opts.allowUnsignedCheckpoints, "allow-unsigned-checkpoints", 0, "acknowledge exactly N historical unsigned checkpoints sealed by a later signed checkpoint")
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
	if original.v1FirstGap || original.v1TailGap {
		return errors.New("degraded v1 receipt gap is at the first or last action_receipt; refusing to publish an evidence directory that receipt resume cannot load")
	}
	if original.v1Degraded && opts.allowDegradedReceipts != len(original.degradations) {
		return fmt.Errorf("receipt proof is DEGRADED by %d recognized whole-receipt tombstone(s); inspect the source and rerun with --allow-degraded-receipts=%d to acknowledge exactly these gaps", len(original.degradations), len(original.degradations))
	}
	if len(original.v1Epochs) > 1 {
		return fmt.Errorf("recorder proof contains %d independent historical epochs; ordinary compaction cannot publish unlinked epochs as resumable live evidence; run evidence inspect-epochs and retire the session instead", len(original.v1Epochs))
	}
	for _, checkpoint := range original.unsignedCheckpoints {
		if !checkpoint.LaterSignedCovered {
			return fmt.Errorf("unsigned checkpoint at recorder seq %d is not sealed by a later signed checkpoint; refusing compaction", checkpoint.RecorderSeq)
		}
	}
	if opts.allowUnsignedCheckpoints != len(original.unsignedCheckpoints) {
		return fmt.Errorf("checkpoint proof contains %d historical unsigned checkpoint(s) sealed by a later signed checkpoint; inspect the source and rerun with --allow-unsigned-checkpoints=%d to acknowledge exactly these records", len(original.unsignedCheckpoints), len(original.unsignedCheckpoints))
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
	manifest := compactManifest{Version: 2, SessionID: opts.sessionID, CreatedAt: time.Now().UTC(), ReceiptVerification: manifestReceiptVerification(original), CheckpointVerification: manifestCheckpointVerification(original), Original: manifestStreamFiles(original.files), Replacement: manifestStreamFiles(writer.files), Mappings: writer.mappings}
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
	if original.v1Degraded {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "receipt proof: DEGRADED; preserved %d known whole-receipt redaction tombstone(s); see archive manifest\n", len(original.degradations))
	} else {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "receipt proof: VERIFIED")
	}
	if len(original.unsignedCheckpoints) > 0 {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "checkpoint proof: DEGRADED; preserved %d acknowledged historical unsigned checkpoint(s), each sealed by a later signed checkpoint; see archive manifest\n", len(original.unsignedCheckpoints))
	} else {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "checkpoint proof: VERIFIED")
	}
	return nil
}

func manifestCheckpointVerification(proof compactStreamProof) compactManifestCheckpointVerification {
	status := "verified"
	if len(proof.unsignedCheckpoints) > 0 {
		status = "degraded"
	}
	return compactManifestCheckpointVerification{Status: status, Unsigned: append([]compactUnsignedCheckpoint(nil), proof.unsignedCheckpoints...)}
}

func manifestReceiptVerification(proof compactStreamProof) compactManifestReceiptVerification {
	status := "verified"
	if proof.v1Degraded {
		status = "degraded"
	}
	return compactManifestReceiptVerification{Status: status, V1Count: proof.v1Count, V1ChainHead: proof.v1Head, V2Count: proof.v2Count, V2ChainHead: proof.v2Head, Degradations: append([]compactReceiptDegradation(nil), proof.degradations...), V1Suffixes: append([]compactReceiptSuffix(nil), proof.v1Suffixes...)}
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
