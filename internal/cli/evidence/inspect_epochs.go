// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/evidencename"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

type inspectEpochsOptions struct {
	receiptDir, locationID, sessionID, publicKey, outFile string
}

type inspectEpochsDocument struct {
	Version                int                                   `json:"version"`
	SessionID              string                                `json:"session_id"`
	SourceBytes            int64                                 `json:"source_bytes"`
	SourceSHA256           string                                `json:"source_sha256"`
	SourceFiles            []compactManifestFile                 `json:"source_files"`
	RecorderEpochs         []compactEpochProof                   `json:"recorder_epochs"`
	ReceiptVerification    compactManifestReceiptVerification    `json:"receipt_verification"`
	CheckpointVerification compactManifestCheckpointVerification `json:"checkpoint_verification"`
}

func inspectEpochsDocumentFromProof(session string, proof compactStreamProof) inspectEpochsDocument {
	receipts := manifestReceiptVerification(proof)
	if len(proof.v1Epochs) > 1 {
		receipts.Status = "verified_per_epoch"
		if proof.v1Degraded {
			receipts.Status = "degraded_per_epoch"
		}
		receipts.V1Count = 0
		receipts.V1ChainHead = ""
	}
	return inspectEpochsDocument{Version: 1, SessionID: session, SourceBytes: proof.bytes, SourceSHA256: proof.sum, SourceFiles: manifestStreamFiles(proof.files), RecorderEpochs: append([]compactEpochProof{}, proof.v1Epochs...), ReceiptVerification: receipts, CheckpointVerification: manifestCheckpointVerification(proof)}
}

var inspectSyncDirectory = func(output *inspectOutput) error { return output.syncParent() }

func inspectEpochsCmd() *cobra.Command {
	opts := inspectEpochsOptions{}
	cmd := &cobra.Command{Use: "inspect-epochs", Short: "Pin exact historical recorder epoch boundaries", Long: "Verify one stopped recorder session and write deterministic JSON containing every recorder epoch boundary and source-file digest. The printed SHA-256 pins the exact output bytes for a later retirement ceremony.", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error { return runInspectEpochs(cmd, opts) }}
	cmd.Flags().StringVar(&opts.receiptDir, "receipt-dir", "", "flight-recorder evidence directory")
	cmd.Flags().StringVar(&opts.locationID, "location", "", "location path relative to the evidence directory")
	cmd.Flags().StringVar(&opts.sessionID, "session", "", "session ID to inspect")
	cmd.Flags().StringVar(&opts.publicKey, "key", "", "trusted receipt signing public key (inline or file)")
	cmd.Flags().StringVar(&opts.outFile, "out", "", "new file to receive canonical epoch-boundary JSON")
	_ = cmd.MarkFlagRequired("receipt-dir")
	_ = cmd.MarkFlagRequired("session")
	_ = cmd.MarkFlagRequired("key")
	_ = cmd.MarkFlagRequired("out")
	return cmd
}

func runInspectEpochs(cmd *cobra.Command, opts inspectEpochsOptions) error {
	if strings.TrimSpace(opts.sessionID) == "" {
		return errors.New("--session is required")
	}
	if strings.TrimSpace(opts.outFile) == "" {
		return errors.New("--out is required")
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
	out, err := filepath.Abs(filepath.Clean(opts.outFile))
	if err != nil {
		return fmt.Errorf("resolve --out: %w", err)
	}
	resolvedParent, err := filepath.EvalSymlinks(filepath.Dir(out))
	if err != nil {
		return fmt.Errorf("resolve --out parent: %w", err)
	}
	out = filepath.Join(resolvedParent, filepath.Base(out))
	if rel, relErr := filepath.Rel(location.Root, out); relErr != nil || rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
		return errors.New("--out must be outside the evidence directory")
	}
	output, err := prepareInspectOutput(resolvedParent, filepath.Base(out), location.Root)
	if err != nil {
		return fmt.Errorf("create --out: %w", err)
	}
	published := false
	defer func() {
		if !published {
			_ = output.remove()
		}
		_ = output.close()
	}()
	lock, err := compactAcquireLock(location.Dir)
	if err != nil {
		return fmt.Errorf("lock stopped evidence directory: %w", err)
	}
	defer func() { _ = lock.Close() }()
	names, err := inspectEpochSourceNames(location, opts.sessionID)
	if err != nil {
		return err
	}
	proof, err := compactVerifyStream(location, names, opts.sessionID, key, func(compactStreamFile, []byte, recorder.Entry) error { return nil })
	if err != nil {
		return fmt.Errorf("verify epoch boundaries: %w", err)
	}
	document := inspectEpochsDocumentFromProof(opts.sessionID, proof)
	data, err := json.Marshal(document)
	if err != nil {
		return fmt.Errorf("encode epoch boundaries: %w", err)
	}
	data = append(data, '\n')
	writeErr := func() error {
		if _, err := output.file.Write(data); err != nil {
			return err
		}
		return output.file.Sync()
	}()
	if writeErr != nil {
		return fmt.Errorf("write --out: %w", writeErr)
	}
	if err := inspectSyncDirectory(output); err != nil {
		return fmt.Errorf("sync --out parent: %w", err)
	}
	matches, err := output.parentMatches(resolvedParent)
	if err != nil {
		return fmt.Errorf("verify --out parent identity: %w", err)
	}
	if !matches {
		return errors.New("--out parent changed during inspection")
	}
	published = true
	digest := sha256.Sum256(data)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s  %s\n", hex.EncodeToString(digest[:]), out)
	return nil
}

func inspectEpochSourceNames(location recorder.EvidenceLocation, session string) ([]string, error) {
	entries, truncated, err := recorder.ReadEvidenceLocationEntriesBounded(location, maxCompactInputShards)
	if err != nil {
		return nil, fmt.Errorf("list evidence directory: %w", err)
	}
	if truncated {
		return nil, fmt.Errorf("evidence directory exceeds inspection input limit %d", maxCompactInputShards)
	}
	names := make([]string, 0)
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("refuse symlink in evidence directory: %s", entry.Name())
		}
		if entry.IsDir() {
			continue
		}
		if strings.HasSuffix(entry.Name(), ".raw.enc") {
			return nil, fmt.Errorf("refuse raw escrow sidecar %q during epoch inspection; sidecar pinning is not implemented", entry.Name())
		}
		got, _, ok := recorder.ParseEvidenceFilename(entry.Name())
		if ok && got == session {
			names = append(names, entry.Name())
		}
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("session %q has no evidence shards", session)
	}
	sort.Slice(names, func(i, j int) bool {
		_, a, _ := recorder.ParseEvidenceFilename(names[i])
		_, b, _ := recorder.ParseEvidenceFilename(names[j])
		if a != b {
			return a < b
		}
		return names[i] < names[j]
	})
	if err := evidencename.CheckNoDuplicateSeqStart(names); err != nil {
		return nil, err
	}
	return names, nil
}
