// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
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
type compactShard struct {
	name       string
	data       []byte
	start      uint64
	sourcePath string
	mappings   []compactByteMapping
}

var (
	compactAcquireLock   = recorder.AcquireEvidenceCeremonyLock
	compactPackRecords   = compactPack
	compactMakeStage     = os.MkdirTemp
	compactPrepareStage  = prepareCompactStage
	compactWriteShards   = writeCompactStage
	compactSyncPath      = syncCompactDirectory
	compactExtract       = contractreceipt.ExtractEvidenceReceiptsFromResolvedSessionDir
	compactVerify        = verifyCompactReceipts
	compactSameChain     = sameReceiptChain
	compactExchange      = exchangeEvidenceDirectories
	compactRename        = os.Rename
	compactWriteManifest = writeCompactManifest
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
	original, receipts, err := compactSource(location, opts.sessionID)
	if err != nil {
		return err
	}
	if err := compactVerify(receipts, key); err != nil {
		return fmt.Errorf("pre-compaction verification: %w", err)
	}
	replacement, err := compactPackRecords(opts.sessionID, original)
	if err != nil {
		return err
	}
	if len(replacement) > recorder.MaxEvidenceReadDirectoryEntries {
		return fmt.Errorf("compaction produced %d shards, exceeds %d", len(replacement), recorder.MaxEvidenceReadDirectoryEntries)
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
	if err := compactWriteShards(stage, replacement); err != nil {
		return err
	}
	if err := compactSyncPath(stage); err != nil {
		return fmt.Errorf("sync staged evidence directory: %w", err)
	}
	if err := compactSyncPath(parent); err != nil {
		return fmt.Errorf("sync evidence parent before publication: %w", err)
	}
	post, err := compactExtract(recorder.EvidenceLocation{Root: stage, Dir: stage}, opts.sessionID)
	if err != nil {
		return fmt.Errorf("read staged compacted evidence: %w", err)
	}
	if err := compactVerify(post, key); err != nil {
		return fmt.Errorf("post-compaction verification: %w", err)
	}
	if !compactSameChain(receipts, post) {
		return errors.New("post-compaction receipt chain differs from original")
	}
	manifest := compactManifest{Version: 1, SessionID: opts.sessionID, CreatedAt: time.Now().UTC(), Original: manifestShards(original), Replacement: manifestShards(replacement), Mappings: compactMappings(replacement)}
	archive := filepath.Join(parent, ".pipelock-evidence-archive-"+time.Now().UTC().Format("20060102T150405.000000000Z"))
	stageLock, err := compactAcquireLock(stage)
	if err != nil {
		return fmt.Errorf("lock staged evidence directory: %w", err)
	}
	defer func() { _ = stageLock.Close() }()
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
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "compacted session %q into %d bounded shard(s); original preserved at %s\n", opts.sessionID, len(replacement), archive)
	return nil
}

func compactSource(location recorder.EvidenceLocation, session string) ([]compactShard, []contractreceipt.EvidenceReceipt, error) {
	entries, err := recorder.ReadEvidenceLocationEntries(location)
	if err != nil {
		return nil, nil, fmt.Errorf("list evidence directory: %w", err)
	}
	var names []string
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 {
			return nil, nil, fmt.Errorf("refuse symlink in active evidence directory: %s", entry.Name())
		}
		if entry.IsDir() {
			return nil, nil, fmt.Errorf("refuse nested directory %q while compacting session %q", entry.Name(), session)
		}
		got, _, ok := recorder.ParseEvidenceFilename(entry.Name())
		if ok && got == session {
			names = append(names, entry.Name())
			continue
		}
		// A session compaction must never make unrelated evidence or raw escrow
		// vanish from the active directory. Support multi-session relocation in a
		// separate ceremony; this command fails closed until then.
		return nil, nil, fmt.Errorf("refuse non-selected evidence file %q while compacting session %q", entry.Name(), session)
	}
	if len(names) == 0 {
		return nil, nil, fmt.Errorf("session %q has no evidence shards", session)
	}
	sort.Slice(names, func(i, j int) bool {
		_, a, _ := recorder.ParseEvidenceFilename(names[i])
		_, b, _ := recorder.ParseEvidenceFilename(names[j])
		if a != b {
			return a < b
		}
		return names[i] < names[j]
	})
	starts := map[uint64]struct{}{}
	source := make([]compactShard, 0, len(names))
	allEntries := make([]recorder.Entry, 0)
	for _, name := range names {
		_, start, _ := recorder.ParseEvidenceFilename(name)
		if _, dup := starts[start]; dup {
			return nil, nil, fmt.Errorf("duplicate shard sequence start %d", start)
		}
		starts[start] = struct{}{}
		data, readErr := recorder.ReadEvidenceLocationFileBounded(location, name, recorder.MaxEvidenceReadFileBytes)
		if readErr != nil {
			return nil, nil, fmt.Errorf("read %s: %w", name, readErr)
		}
		if len(data) == 0 || data[len(data)-1] != '\n' {
			return nil, nil, fmt.Errorf("%s does not end in newline; refusing cross-file record concatenation", name)
		}
		parsed, parseErr := recorder.ReadEntriesFromReader(bytes.NewReader(data))
		if parseErr != nil {
			return nil, nil, fmt.Errorf("validate %s: %w", name, parseErr)
		}
		for _, entry := range parsed {
			if entry.SessionID != session {
				return nil, nil, fmt.Errorf("entry in %s belongs to %q, not %q", name, entry.SessionID, session)
			}
			allEntries = append(allEntries, entry)
		}
		source = append(source, compactShard{name: name, data: data, start: start, sourcePath: filepath.Join(location.Dir, name)})
	}
	if err := recorder.VerifyChain(allEntries); err != nil {
		return nil, nil, fmt.Errorf("verify recorder chain: %w", err)
	}
	for i, entry := range allEntries {
		if entry.Sequence != uint64(i) {
			return nil, nil, fmt.Errorf("recorder sequence gap or fork: entry %d declares seq %d", i, entry.Sequence)
		}
	}
	receipts, err := contractreceipt.ExtractEvidenceReceiptsFromResolvedSessionDir(location, session)
	if err != nil {
		return nil, nil, fmt.Errorf("extract evidence receipt chain: %w", err)
	}
	if len(receipts) == 0 {
		return nil, nil, errors.New("selected session contains no evidence receipts")
	}
	return source, receipts, nil
}

func verifyCompactReceipts(receipts []contractreceipt.EvidenceReceipt, key []byte) error {
	result := contractreceipt.VerifyChain(receipts, contractreceipt.ChainVerifyOptions{PinnedKey: key})
	if !result.Valid || !result.SignaturesVerified {
		return fmt.Errorf("signed receipt chain rejected: %s", result.Error)
	}
	return nil
}

func compactPack(session string, source []compactShard) ([]compactShard, error) {
	var out []compactShard
	var current bytes.Buffer
	var start uint64
	var mappings []compactByteMapping
	var currentSourcePath string
	for _, file := range source {
		var sourceOffset int64
		for _, line := range bytes.SplitAfter(file.data, []byte("\n")) {
			if len(line) == 0 {
				continue
			}
			if int64(len(line)) > recorder.MaxEvidenceReadFileBytes {
				return nil, errors.New("single JSONL line exceeds evidence shard limit")
			}
			if current.Len() > 0 && int64(current.Len()+len(line)) > recorder.MaxEvidenceReadFileBytes {
				out = append(out, compactShard{name: fmt.Sprintf("evidence-%s-%d.jsonl", filepath.Base(session), start), data: append([]byte(nil), current.Bytes()...), start: start, sourcePath: currentSourcePath, mappings: mappings})
				current.Reset()
				mappings = nil
				currentSourcePath = ""
			}
			if current.Len() == 0 {
				var entry recorder.Entry
				if err := json.Unmarshal(bytes.TrimSpace(line), &entry); err != nil {
					return nil, fmt.Errorf("parse compacted line: %w", err)
				}
				if entry.SessionID != session {
					return nil, fmt.Errorf("entry session %q does not match selected %q", entry.SessionID, session)
				}
				start = entry.Sequence
				currentSourcePath = file.sourcePath
			}
			outOffset := int64(current.Len())
			_, _ = current.Write(line)
			mappings = append(mappings, compactByteMapping{Source: file.name, Output: fmt.Sprintf("evidence-%s-%d.jsonl", filepath.Base(session), start), SourceOffset: sourceOffset, OutputOffset: outOffset, Bytes: int64(len(line))})
			sourceOffset += int64(len(line))
		}
	}
	if current.Len() > 0 {
		out = append(out, compactShard{name: fmt.Sprintf("evidence-%s-%d.jsonl", filepath.Base(session), start), data: append([]byte(nil), current.Bytes()...), start: start, sourcePath: currentSourcePath, mappings: mappings})
	}
	if len(out) == 0 {
		return nil, errors.New("no compacted evidence bytes produced")
	}
	return out, nil
}

func writeCompactStage(dir string, shards []compactShard) error {
	for _, shard := range shards {
		if int64(len(shard.data)) > recorder.MaxEvidenceReadFileBytes {
			return errors.New("compacted shard exceeds evidence read limit")
		}
		if err := os.WriteFile(filepath.Join(dir, shard.name), shard.data, 0o600); err != nil {
			return fmt.Errorf("write compacted shard %s: %w", shard.name, err)
		}
		if err := preserveCompactFileMetadata(shard.sourcePath, filepath.Join(dir, shard.name)); err != nil {
			return fmt.Errorf("preserve compacted shard metadata: %w", err)
		}
		if err := syncCompactFile(filepath.Join(dir, shard.name)); err != nil {
			return fmt.Errorf("sync compacted shard %s: %w", shard.name, err)
		}
	}
	return nil
}

func compactMappings(shards []compactShard) []compactByteMapping {
	var out []compactByteMapping
	for _, shard := range shards {
		out = append(out, shard.mappings...)
	}
	return out
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

func manifestShards(shards []compactShard) []compactManifestFile {
	out := make([]compactManifestFile, 0, len(shards))
	for _, shard := range shards {
		sum := sha256.Sum256(shard.data)
		out = append(out, compactManifestFile{Name: shard.name, SHA256: hex.EncodeToString(sum[:]), Bytes: int64(len(shard.data))})
	}
	return out
}

func sameReceiptChain(a, b []contractreceipt.EvidenceReceipt) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		ah, ae := contractreceipt.ReceiptHash(a[i])
		bh, be := contractreceipt.ReceiptHash(b[i])
		if ae != nil || be != nil || ah != bh {
			return false
		}
	}
	return true
}
