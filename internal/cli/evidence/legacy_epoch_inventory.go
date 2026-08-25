// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/jsonscan"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

const (
	legacyInventoryVersion      = 1
	legacyInventoryKind         = "pipelock-legacy-epoch-inventory"
	maxLegacyInventoryEpochs    = 1024
	maxLegacyInventoryRuns      = 16384
	maxLegacyInventoryAnomalies = 65536
)

var (
	legacyInventoryWrite         = func(file *os.File, data []byte) (int, error) { return file.Write(data) }
	legacyInventoryFileSync      = func(file *os.File) error { return file.Sync() }
	legacyInventoryMarshal       = marshalLegacyInventory
	legacyInventoryParentMatches = func(output *inspectOutput, parent string) (bool, error) { return output.parentMatches(parent) }
)

type legacyInventoryOptions struct {
	receiptDir, locationID, sessionID, outFile string
}

type verifyLegacyInventoryOptions struct {
	receiptDir, locationID, sessionID, inventoryFile, inventorySHA256 string
}

type legacyInventoryDocument struct {
	Version      int                    `json:"version"`
	Kind         string                 `json:"kind"`
	SessionID    string                 `json:"session_id"`
	SourceBytes  int64                  `json:"source_bytes"`
	SourceSHA256 string                 `json:"snapshot_source_sha256"`
	SourceFiles  []legacyInventoryFile  `json:"source_files"`
	Epochs       []legacyInventoryEpoch `json:"epochs"`
}

type legacyInventoryFile struct {
	Name   string `json:"name"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

type legacyInventoryEpoch struct {
	Epoch                  uint64                   `json:"epoch"`
	StartSequence          uint64                   `json:"start_seq"`
	EndSequence            uint64                   `json:"end_seq"`
	StartHash              string                   `json:"start_hash"`
	EndHash                string                   `json:"end_hash"`
	StartFile              string                   `json:"start_file"`
	EndFile                string                   `json:"end_file"`
	EntryCount             uint64                   `json:"entry_count"`
	Assurance              string                   `json:"assurance"`
	CheckpointStatus       string                   `json:"checkpoint_status"`
	CheckpointCount        uint64                   `json:"checkpoint_count"`
	StrictReceiptCount     uint64                   `json:"strictly_verified_receipts"`
	StrictReceiptErrors    uint64                   `json:"strict_receipt_errors"`
	RotationEndorsements   uint64                   `json:"rotation_endorsements"`
	SignerRuns             []legacySignerRun        `json:"signer_runs"`
	SourceFiles            []legacyInventoryFile    `json:"source_files"`
	SourceMappings         []legacySourceMapping    `json:"source_mappings"`
	Anomalies              []legacyInventoryAnomaly `json:"anomalies"`
	outerIntegrityFailures uint64
}

type legacySignerRun struct {
	SignerKey           *string `json:"signer_key"`
	FirstSequence       uint64  `json:"first_recorder_seq"`
	LastSequence        uint64  `json:"last_recorder_seq"`
	ReceiptCount        uint64  `json:"receipt_count"`
	StrictVerifiedCount uint64  `json:"strictly_verified"`
	StrictErrors        uint64  `json:"strict_errors"`
}

type legacySourceMapping struct {
	File   string `json:"file"`
	Offset int64  `json:"offset"`
	Bytes  int64  `json:"bytes"`
}

type legacyInventoryAnomaly struct {
	Kind     string `json:"kind"`
	File     string `json:"file"`
	Offset   int64  `json:"offset"`
	Sequence uint64 `json:"sequence"`
}

func inventoryLegacyEpochsCmd() *cobra.Command {
	opts := legacyInventoryOptions{}
	cmd := &cobra.Command{
		Use:   "inventory-legacy-epochs",
		Short: "Inventory legacy recorder epochs without granting trust",
		Long:  "Walk one stopped recorder session and write a bounded, canonical inventory of every source byte, recorder epoch, signer run, and anomaly. Observing a signer never makes it trusted.",
		Args:  cobra.NoArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return runInventoryLegacyEpochs(cmd, opts) },
	}
	cmd.Flags().StringVar(&opts.receiptDir, "receipt-dir", "", "stopped flight-recorder evidence directory or immutable snapshot")
	cmd.Flags().StringVar(&opts.locationID, "location", "", "location path relative to the evidence directory")
	cmd.Flags().StringVar(&opts.sessionID, "session", "", "session ID to inventory")
	cmd.Flags().StringVar(&opts.outFile, "out", "", "new file outside the evidence directory for canonical inventory JSON")
	_ = cmd.MarkFlagRequired("receipt-dir")
	_ = cmd.MarkFlagRequired("session")
	_ = cmd.MarkFlagRequired("out")
	return cmd
}

func verifyLegacyEpochInventoryCmd() *cobra.Command {
	opts := verifyLegacyInventoryOptions{}
	cmd := &cobra.Command{
		Use:   "verify-legacy-epoch-inventory",
		Short: "Recompute and verify an exact legacy epoch inventory",
		Long:  "Strictly decode a pinned inventory, recompute it from every source byte, and require canonical byte-for-byte equality. Missing runs, anomalies, files, or source drift fail closed.",
		Args:  cobra.NoArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return runVerifyLegacyEpochInventory(cmd, opts) },
	}
	cmd.Flags().StringVar(&opts.receiptDir, "receipt-dir", "", "stopped flight-recorder evidence directory or immutable snapshot")
	cmd.Flags().StringVar(&opts.locationID, "location", "", "location path relative to the evidence directory")
	cmd.Flags().StringVar(&opts.sessionID, "session", "", "session ID to verify")
	cmd.Flags().StringVar(&opts.inventoryFile, "inventory", "", "canonical inventory JSON file")
	cmd.Flags().StringVar(&opts.inventorySHA256, "sha256", "", "expected SHA-256 of the exact inventory bytes")
	_ = cmd.MarkFlagRequired("receipt-dir")
	_ = cmd.MarkFlagRequired("session")
	_ = cmd.MarkFlagRequired("inventory")
	_ = cmd.MarkFlagRequired("sha256")
	return cmd
}

func runInventoryLegacyEpochs(cmd *cobra.Command, opts legacyInventoryOptions) error {
	location, err := resolveLegacyInventoryLocation(opts.receiptDir, opts.locationID, opts.sessionID)
	if err != nil {
		return err
	}
	out, parent, err := resolveLegacyInventoryOutput(opts.outFile, location.Root)
	if err != nil {
		return err
	}
	output, err := prepareInspectOutput(parent, filepath.Base(out), location.Root)
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
	document, err := buildLegacyInventory(location, strings.TrimSpace(opts.sessionID))
	if err != nil {
		return err
	}
	data, err := legacyInventoryMarshal(document)
	if err != nil {
		return err
	}
	if _, err := legacyInventoryWrite(output.file, data); err != nil {
		return fmt.Errorf("write --out: %w", err)
	}
	if err := legacyInventoryFileSync(output.file); err != nil {
		return fmt.Errorf("sync --out: %w", err)
	}
	if err := inspectSyncDirectory(output); err != nil {
		return fmt.Errorf("sync --out parent: %w", err)
	}
	matches, err := legacyInventoryParentMatches(output, parent)
	if err != nil {
		return fmt.Errorf("verify --out parent identity: %w", err)
	}
	if !matches {
		return errors.New("--out parent changed during inventory")
	}
	published = true
	digest := sha256.Sum256(data)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s  %s\n", hex.EncodeToString(digest[:]), out)
	return nil
}

func runVerifyLegacyEpochInventory(cmd *cobra.Command, opts verifyLegacyInventoryOptions) error {
	location, err := resolveLegacyInventoryLocation(opts.receiptDir, opts.locationID, opts.sessionID)
	if err != nil {
		return err
	}
	wantDigest := strings.ToLower(strings.TrimSpace(opts.inventorySHA256))
	if len(wantDigest) != sha256.Size*2 {
		return errors.New("--sha256 must be a 64-character hexadecimal SHA-256")
	}
	if _, err := hex.DecodeString(wantDigest); err != nil {
		return errors.New("--sha256 must be hexadecimal")
	}
	inventoryPath := filepath.Clean(opts.inventoryFile)
	file, err := os.Open(inventoryPath) // #nosec G304 -- operator-selected inventory is verified before use.
	if err != nil {
		return fmt.Errorf("read --inventory: %w", err)
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, recorder.MaxEvidenceReadFileBytes+1))
	if err != nil {
		return fmt.Errorf("read --inventory: %w", err)
	}
	if int64(len(data)) > recorder.MaxEvidenceReadFileBytes {
		return fmt.Errorf("--inventory exceeds %d-byte limit", recorder.MaxEvidenceReadFileBytes)
	}
	gotDigest := sha256.Sum256(data)
	if hex.EncodeToString(gotDigest[:]) != wantDigest {
		return errors.New("--inventory SHA-256 does not match --sha256")
	}
	if err := jsonscan.RejectDuplicateKeys(data); err != nil {
		return fmt.Errorf("decode --inventory: %w", err)
	}
	var supplied legacyInventoryDocument
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&supplied); err != nil {
		return fmt.Errorf("decode --inventory: %w", err)
	}
	if err := dec.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return errors.New("decode --inventory: trailing JSON value")
	}
	if supplied.Version != legacyInventoryVersion || supplied.Kind != legacyInventoryKind || supplied.SessionID != strings.TrimSpace(opts.sessionID) {
		return errors.New("--inventory identity does not match requested version, kind, and session")
	}
	lock, err := compactAcquireLock(location.Dir)
	if err != nil {
		return fmt.Errorf("lock stopped evidence directory: %w", err)
	}
	defer func() { _ = lock.Close() }()
	recomputed, err := buildLegacyInventory(location, strings.TrimSpace(opts.sessionID))
	if err != nil {
		return err
	}
	want, err := legacyInventoryMarshal(recomputed)
	if err != nil {
		return err
	}
	if !bytes.Equal(data, want) {
		return errors.New("inventory differs from full recomputation; source bytes or recorded files, epochs, runs, mappings, or anomalies changed")
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "verified %s  %s\n", wantDigest, filepath.Clean(opts.inventoryFile))
	return nil
}

func resolveLegacyInventoryLocation(root, locationID, session string) (recorder.EvidenceLocation, error) {
	if strings.TrimSpace(session) == "" {
		return recorder.EvidenceLocation{}, errors.New("--session is required")
	}
	cleanRoot, err := validateReceiptDir(root)
	if err != nil {
		return recorder.EvidenceLocation{}, err
	}
	location, err := recorder.ResolveEvidenceLocation(cleanRoot, locationID)
	if err != nil {
		return recorder.EvidenceLocation{}, fmt.Errorf("resolve evidence location: %w", err)
	}
	return location, nil
}

func resolveLegacyInventoryOutput(name, evidenceRoot string) (string, string, error) {
	if strings.TrimSpace(name) == "" {
		return "", "", errors.New("--out is required")
	}
	out, err := filepath.Abs(filepath.Clean(name))
	if err != nil {
		return "", "", fmt.Errorf("resolve --out: %w", err)
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(out))
	if err != nil {
		return "", "", fmt.Errorf("resolve --out parent: %w", err)
	}
	out = filepath.Join(parent, filepath.Base(out))
	if rel, relErr := filepath.Rel(evidenceRoot, out); relErr != nil || rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
		return "", "", errors.New("--out must be outside the evidence directory")
	}
	return out, parent, nil
}

func marshalLegacyInventory(document legacyInventoryDocument) ([]byte, error) {
	data, err := json.Marshal(document)
	if err != nil {
		return nil, fmt.Errorf("encode legacy inventory: %w", err)
	}
	return append(data, '\n'), nil
}

func buildLegacyInventory(location recorder.EvidenceLocation, session string) (legacyInventoryDocument, error) {
	names, err := inspectEpochSourceNames(location, session)
	if err != nil {
		return legacyInventoryDocument{}, err
	}
	doc := legacyInventoryDocument{Version: legacyInventoryVersion, Kind: legacyInventoryKind, SessionID: session, SourceFiles: make([]legacyInventoryFile, 0, len(names)), Epochs: make([]legacyInventoryEpoch, 0)}
	aggregate := sha256.New()
	var epoch *legacyInventoryEpoch
	seenSigner := make(map[string]struct{})
	for _, name := range names {
		fileHash := sha256.New()
		var offset int64
		err := recorder.StreamEvidenceLocationFileForOfflineCompaction(location, name, func(source io.Reader, info os.FileInfo) error {
			reader := bufio.NewReaderSize(source, recorder.MaxEntryLineBytes+1)
			for {
				line, readErr := reader.ReadSlice('\n')
				if errors.Is(readErr, bufio.ErrBufferFull) {
					return fmt.Errorf("source shard %q entry at byte %d exceeds %d-byte limit", name, offset, recorder.MaxEntryLineBytes)
				}
				if len(line) > 0 {
					if errors.Is(readErr, io.EOF) {
						return fmt.Errorf("source shard %q does not end in newline", name)
					}
					if len(line) > recorder.MaxEntryLineBytes+1 {
						return fmt.Errorf("source shard %q entry at byte %d exceeds %d-byte limit", name, offset, recorder.MaxEntryLineBytes)
					}
					_, _ = aggregate.Write(line)
					_, _ = fileHash.Write(line)
					doc.SourceBytes += int64(len(line))
					payload := bytes.TrimSuffix(line, []byte{'\n'})
					payload = bytes.TrimSuffix(payload, []byte{'\r'})
					entry, parseErr := recorder.ParseEntryLine(payload)
					if parseErr != nil {
						return fmt.Errorf("parse source shard %q at byte %d: %w", name, offset, parseErr)
					}
					if entry.SessionID != session {
						return fmt.Errorf("source shard %q at byte %d contains session %q, want %q", name, offset, entry.SessionID, session)
					}
					if epoch == nil || (epoch.EntryCount > 0 && entry.Sequence == 0) {
						if len(doc.Epochs) >= maxLegacyInventoryEpochs {
							return fmt.Errorf("legacy inventory exceeds %d epochs", maxLegacyInventoryEpochs)
						}
						doc.Epochs = append(doc.Epochs, legacyInventoryEpoch{Epoch: uint64(len(doc.Epochs)), StartSequence: entry.Sequence, StartHash: entry.Hash, Assurance: "receipts_strictly_verified", CheckpointStatus: "none", SignerRuns: []legacySignerRun{}, SourceFiles: []legacyInventoryFile{}, SourceMappings: []legacySourceMapping{}, Anomalies: []legacyInventoryAnomaly{}})
						epoch = &doc.Epochs[len(doc.Epochs)-1]
						seenSigner = make(map[string]struct{})
					}
					if err := addLegacyInventoryEntry(epoch, name, offset, int64(len(line)), entry, seenSigner); err != nil {
						return err
					}
					offset += int64(len(line))
				}
				if readErr != nil {
					if !errors.Is(readErr, io.EOF) {
						return fmt.Errorf("read source shard %q: %w", name, readErr)
					}
					break
				}
			}
			if offset != info.Size() {
				return fmt.Errorf("source shard %q changed size during inventory", name)
			}
			return nil
		})
		if err != nil {
			return legacyInventoryDocument{}, err
		}
		doc.SourceFiles = append(doc.SourceFiles, legacyInventoryFile{Name: name, Bytes: offset, SHA256: hex.EncodeToString(fileHash.Sum(nil))})
	}
	if len(doc.Epochs) == 0 {
		return legacyInventoryDocument{}, fmt.Errorf("session %q contains no recorder entries", session)
	}
	fileByName := make(map[string]legacyInventoryFile, len(doc.SourceFiles))
	for _, source := range doc.SourceFiles {
		fileByName[source.Name] = source
	}
	for i := range doc.Epochs {
		seenFile := make(map[string]struct{})
		for _, mapping := range doc.Epochs[i].SourceMappings {
			if _, exists := seenFile[mapping.File]; exists {
				continue
			}
			seenFile[mapping.File] = struct{}{}
			doc.Epochs[i].SourceFiles = append(doc.Epochs[i].SourceFiles, fileByName[mapping.File])
		}
		finalizeLegacyEpoch(&doc.Epochs[i])
	}
	doc.SourceSHA256 = hex.EncodeToString(aggregate.Sum(nil))
	return doc, nil
}

func addLegacyInventoryEntry(epoch *legacyInventoryEpoch, file string, offset, size int64, entry recorder.Entry, seenSigner map[string]struct{}) error {
	if epoch.EntryCount > 0 {
		if entry.Sequence != epoch.EndSequence+1 {
			kind := "sequence_gap"
			if entry.Sequence <= epoch.EndSequence {
				kind = "sequence_overlap"
			}
			if err := addLegacyAnomaly(epoch, kind, file, offset, entry.Sequence, true); err != nil {
				return err
			}
		}
		if entry.PrevHash != epoch.EndHash {
			if err := addLegacyAnomaly(epoch, "previous_hash_mismatch", file, offset, entry.Sequence, true); err != nil {
				return err
			}
		}
	} else if entry.Sequence != 0 || entry.PrevHash != recorder.GenesisHash {
		if err := addLegacyAnomaly(epoch, "non_genesis_epoch_start", file, offset, entry.Sequence, true); err != nil {
			return err
		}
	}
	if epoch.EntryCount == 0 {
		epoch.StartFile = file
	}
	if recorder.ComputeHash(entry) != entry.Hash {
		if err := addLegacyAnomaly(epoch, "stored_hash_mismatch", file, offset, entry.Sequence, true); err != nil {
			return err
		}
	}
	if len(epoch.SourceMappings) > 0 {
		last := &epoch.SourceMappings[len(epoch.SourceMappings)-1]
		if last.File == file && last.Offset+last.Bytes == offset {
			last.Bytes += size
		} else {
			epoch.SourceMappings = append(epoch.SourceMappings, legacySourceMapping{File: file, Offset: offset, Bytes: size})
		}
	} else {
		epoch.SourceMappings = append(epoch.SourceMappings, legacySourceMapping{File: file, Offset: offset, Bytes: size})
	}
	epoch.EntryCount++
	epoch.EndSequence = entry.Sequence
	epoch.EndHash = entry.Hash
	epoch.EndFile = file
	switch entry.Type {
	case "action_receipt":
		return addLegacyReceipt(epoch, file, offset, entry, seenSigner)
	case "checkpoint":
		epoch.CheckpointCount++
		var detail recorder.CheckpointDetail
		if err := json.Unmarshal(entry.RawDetail, &detail); err != nil {
			return fmt.Errorf("decode checkpoint in %q at byte %d: %w", file, offset, err)
		}
		if strings.TrimSpace(detail.Signature) == "" {
			epoch.CheckpointStatus = "unsigned_observed"
			return addLegacyAnomaly(epoch, "unsigned_checkpoint", file, offset, entry.Sequence, false)
		}
		if epoch.CheckpointStatus == "none" {
			epoch.CheckpointStatus = "signed_observed"
		}
	case "rotation_endorsement":
		epoch.RotationEndorsements++
		return addLegacyAnomaly(epoch, "rotation_endorsement_observed", file, offset, entry.Sequence, false)
	default:
		if _, ok := compactKnownRecorderTypes[entry.Type]; !ok {
			return addLegacyAnomaly(epoch, "unknown_entry_type", file, offset, entry.Sequence, false)
		}
	}
	return nil
}

func addLegacyReceipt(epoch *legacyInventoryEpoch, file string, offset int64, entry recorder.Entry, seenSigner map[string]struct{}) error {
	var envelope struct {
		SignerKey string `json:"signer_key"`
	}
	_ = json.Unmarshal(entry.RawDetail, &envelope)
	strict, strictErr := receipt.Unmarshal(entry.RawDetail)
	if strictErr == nil {
		envelope.SignerKey = strict.SignerKey
		strictErr = receipt.VerifyInternalConsistencyOnly(strict)
	}
	key := strings.TrimSpace(envelope.SignerKey)
	var keyPointer *string
	if key != "" {
		keyPointer = &key
	}
	newRun := len(epoch.SignerRuns) == 0 || signerRunKey(epoch.SignerRuns[len(epoch.SignerRuns)-1]) != key
	if newRun {
		if len(epoch.SignerRuns) >= maxLegacyInventoryRuns {
			return fmt.Errorf("legacy inventory exceeds %d signer runs", maxLegacyInventoryRuns)
		}
		if len(epoch.SignerRuns) > 0 {
			if err := addLegacyAnomaly(epoch, "signer_change", file, offset, entry.Sequence, false); err != nil {
				return err
			}
		}
		if _, exists := seenSigner[key]; key != "" && exists {
			if err := addLegacyAnomaly(epoch, "signer_key_reentry", file, offset, entry.Sequence, false); err != nil {
				return err
			}
		}
		if key != "" {
			seenSigner[key] = struct{}{}
		}
		epoch.SignerRuns = append(epoch.SignerRuns, legacySignerRun{SignerKey: keyPointer, FirstSequence: entry.Sequence})
	}
	run := &epoch.SignerRuns[len(epoch.SignerRuns)-1]
	run.LastSequence = entry.Sequence
	run.ReceiptCount++
	if strictErr != nil {
		run.StrictErrors++
		epoch.StrictReceiptErrors++
		return addLegacyAnomaly(epoch, "strict_receipt_error", file, offset, entry.Sequence, false)
	}
	run.StrictVerifiedCount++
	epoch.StrictReceiptCount++
	return nil
}

func signerRunKey(run legacySignerRun) string {
	if run.SignerKey == nil {
		return ""
	}
	return *run.SignerKey
}

func addLegacyAnomaly(epoch *legacyInventoryEpoch, kind, file string, offset int64, sequence uint64, outerFailure bool) error {
	if len(epoch.Anomalies) >= maxLegacyInventoryAnomalies {
		return fmt.Errorf("legacy inventory exceeds %d anomalies", maxLegacyInventoryAnomalies)
	}
	epoch.Anomalies = append(epoch.Anomalies, legacyInventoryAnomaly{Kind: kind, File: file, Offset: offset, Sequence: sequence})
	if outerFailure {
		epoch.outerIntegrityFailures++
	}
	return nil
}

func finalizeLegacyEpoch(epoch *legacyInventoryEpoch) {
	switch {
	case epoch.outerIntegrityFailures > 0:
		epoch.Assurance = "broken"
	case len(epoch.Anomalies) > 0 || epoch.StrictReceiptErrors > 0:
		epoch.Assurance = "observed_only"
	case epoch.StrictReceiptCount == 0:
		epoch.Assurance = "outer_verified"
	default:
		epoch.Assurance = "receipts_strictly_verified"
	}
}
