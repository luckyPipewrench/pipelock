// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package evidence

// This file contains the bounded-byte primitives used by the offline
// compaction ceremony.  Online evidence readers intentionally remain bounded
// by recorder.MaxEvidenceReadFileBytes; the ceremony is the only consumer that
// is allowed to walk an old oversized shard, one JSONL record at a time.

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/contract"
	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/evidencename"
	"github.com/luckyPipewrench/pipelock/internal/jsonscan"
	legacyreceipt "github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

type compactStreamWriter struct {
	dir, session  string
	current       *os.File
	currentName   string
	currentStart  uint64
	currentBytes  int64
	currentSource compactStreamFile
	files         []compactStreamFile
	mappings      []compactByteMapping
	sourceOffsets map[string]int64
}

// File-operation seams keep the offline ceremony's real error propagation
// testable without weakening its bounded production path. They are package
// local and retain the standard library operations by default.
var (
	compactStreamSync  = func(f *os.File) error { return f.Sync() }
	compactStreamClose = func(f *os.File) error { return f.Close() }
	compactStreamWrite = func(f *os.File, line []byte) (int, error) { return f.Write(line) }
	compactStreamRead  = os.ReadFile
)

func compactStreamNames(location recorder.EvidenceLocation, session string) ([]string, error) {
	entries, truncated, err := recorder.ReadEvidenceLocationEntriesBounded(location, maxCompactInputShards)
	if err != nil {
		return nil, fmt.Errorf("list evidence directory: %w", err)
	}
	if truncated {
		return nil, fmt.Errorf("evidence directory exceeds compaction input limit %d", maxCompactInputShards)
	}
	var names []string
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("refuse symlink in active evidence directory: %s", entry.Name())
		}
		if entry.IsDir() {
			return nil, fmt.Errorf("refuse nested directory %q while compacting session %q", entry.Name(), session)
		}
		if strings.HasSuffix(entry.Name(), ".raw.enc") {
			return nil, fmt.Errorf("refuse raw escrow sidecar %q during compaction; sidecar-preserving compaction is not implemented", entry.Name())
		}
		got, _, ok := recorder.ParseEvidenceFilename(entry.Name())
		if !ok || got != session {
			return nil, fmt.Errorf("refuse non-selected evidence file %q while compacting session %q", entry.Name(), session)
		}
		names = append(names, entry.Name())
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

func streamCompactToStage(location recorder.EvidenceLocation, names []string, session string, key ed25519.PublicKey, stage string) (*compactStreamWriter, compactStreamProof, error) {
	w := &compactStreamWriter{dir: stage, session: session, sourceOffsets: make(map[string]int64)}
	proof, err := streamCompactFiles(location, names, session, key, func(source compactStreamFile, line []byte, entry recorder.Entry) error {
		return w.add(source, line, entry)
	})
	if err != nil {
		_ = w.close()
		return nil, compactStreamProof{}, err
	}
	if err := w.close(); err != nil {
		return nil, compactStreamProof{}, err
	}
	return w, proof, nil
}

func (w *compactStreamWriter) add(source compactStreamFile, line []byte, entry recorder.Entry) error {
	if int64(len(line)) > recorder.MaxEvidenceReadFileBytes {
		return fmt.Errorf("single JSONL line exceeds evidence shard limit")
	}
	// Every output shard inherits the metadata of the source that opened it.
	// Reject a mode change before appending to that shard, even when the line
	// still fits and therefore would not trigger rotation.
	if w.current != nil && source.info.Mode().Perm() != w.currentSource.info.Mode().Perm() {
		return fmt.Errorf("source shard mode differs; compaction cannot preserve per-output provenance")
	}
	if w.current == nil || w.currentBytes+int64(len(line)) > recorder.MaxEvidenceReadFileBytes {
		if err := w.close(); err != nil {
			return err
		}
		if len(w.files) > 0 && source.info.Mode().Perm() != w.files[0].info.Mode().Perm() {
			return fmt.Errorf("source shard mode differs; compaction cannot preserve per-output provenance")
		}
		if len(w.files) >= recorder.MaxEvidenceReadDirectoryEntries {
			return fmt.Errorf("compaction produced %d shards, exceeds %d", len(w.files)+1, recorder.MaxEvidenceReadDirectoryEntries)
		}
		w.currentStart = entry.Sequence
		w.currentName = fmt.Sprintf("evidence-%s-%d.jsonl", filepath.Base(w.session), entry.Sequence)
		w.currentSource = source
		f, err := os.OpenFile(filepath.Join(w.dir, w.currentName), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		w.current = f
		w.currentBytes = 0
	}
	offset := w.currentBytes
	sourceOffset := w.sourceOffsets[source.name]
	written, err := compactStreamWrite(w.current, line)
	if err != nil {
		return err
	}
	if written != len(line) {
		return io.ErrShortWrite
	}
	w.currentBytes += int64(len(line))
	n := len(w.mappings)
	if n > 0 {
		last := &w.mappings[n-1]
		if last.Source == source.name && last.Output == w.currentName && last.SourceOffset+last.Bytes == sourceOffset && last.OutputOffset+last.Bytes == offset {
			last.Bytes += int64(len(line))
			w.sourceOffsets[source.name] += int64(len(line))
			return nil
		}
	}
	w.mappings = append(w.mappings, compactByteMapping{Source: source.name, Output: w.currentName, SourceOffset: sourceOffset, OutputOffset: offset, Bytes: int64(len(line))})
	w.sourceOffsets[source.name] += int64(len(line))
	return nil
}

func (w *compactStreamWriter) close() error {
	if w.current == nil {
		return nil
	}
	if err := compactStreamSync(w.current); err != nil {
		return err
	}
	if err := compactStreamClose(w.current); err != nil {
		return err
	}
	path := filepath.Join(w.dir, w.currentName)
	if err := preserveCompactFileMetadata(w.currentSource.path, path); err != nil {
		return err
	}
	// #nosec G304 -- path is the bounded staged shard we just created.
	data, err := compactStreamRead(path)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	w.files = append(w.files, compactStreamFile{name: w.currentName, path: path, info: w.currentSource.info, sum: hex.EncodeToString(sum[:]), bytes: int64(len(data))})
	w.current = nil
	return nil
}

func sameCompactProof(a, b compactStreamProof) bool {
	if a.bytes != b.bytes || a.sum != b.sum || a.v1Count != b.v1Count || a.v1Head != b.v1Head || a.v1Degraded != b.v1Degraded || a.v1FirstGap != b.v1FirstGap || a.v1TailGap != b.v1TailGap || a.v2Count != b.v2Count || a.v2Head != b.v2Head || len(a.degradations) != len(b.degradations) || len(a.v1Suffixes) != len(b.v1Suffixes) || len(a.unsignedCheckpoints) != len(b.unsignedCheckpoints) {
		return false
	}
	for i := range a.degradations {
		// Compaction can coalesce several source shards into one output shard,
		// so the same recorder entry can legitimately acquire a different file
		// name. The signed recorder sequence and tombstone metadata identify the
		// degradation; File remains provenance for the corresponding manifest.
		aGap, bGap := a.degradations[i], b.degradations[i]
		aGap.File, bGap.File = "", ""
		if aGap != bGap {
			return false
		}
	}
	for i := range a.v1Suffixes {
		if a.v1Suffixes[i] != b.v1Suffixes[i] {
			return false
		}
	}
	for i := range a.unsignedCheckpoints {
		aCheckpoint, bCheckpoint := a.unsignedCheckpoints[i], b.unsignedCheckpoints[i]
		aCheckpoint.File, bCheckpoint.File = "", ""
		if aCheckpoint != bCheckpoint {
			return false
		}
	}
	return true
}

func advanceCompactSuffixOrigin(current, delta uint64) (uint64, error) {
	if current > math.MaxUint64-delta {
		return 0, fmt.Errorf("v1 receipt suffix origin overflows after chain_seq %d", current)
	}
	return current + delta, nil
}

func sameCompactNameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func manifestStreamFiles(files []compactStreamFile) []compactManifestFile {
	out := make([]compactManifestFile, 0, len(files))
	for _, f := range files {
		out = append(out, compactManifestFile{Name: f.name, SHA256: f.sum, Bytes: f.bytes})
	}
	return out
}

// compactStreamFile is deliberately metadata-only. Keeping source content in
// this structure was the old compactor's 256MiB ceiling and made the live
// four-gigabyte recorder impossible to repair.
type compactStreamFile struct {
	name  string
	path  string
	info  os.FileInfo
	sum   string
	bytes int64
}

const (
	maxCompactInputShards         = 4096
	maxCompactUnsignedCheckpoints = 10_000
)

var compactKnownRecorderTypes = map[string]struct{}{
	"action_receipt": {}, "evidence_receipt": {}, "checkpoint": {}, "transcript_root": {}, "decision": {}, "capture": {}, "capture_drop": {},
}

type compactStreamProof struct {
	files               []compactStreamFile
	bytes               int64
	sum                 string
	v1Count             uint64
	v1Head              string
	v1Degraded          bool
	v1FirstGap          bool
	v1TailGap           bool
	degradations        []compactReceiptDegradation
	v1Suffixes          []compactReceiptSuffix
	v2Count             uint64
	v2Head              string
	unsignedCheckpoints []compactUnsignedCheckpoint
}

type compactUnsignedCheckpoint struct {
	File                 string `json:"file"`
	RecorderSeq          uint64 `json:"recorder_seq"`
	EntryCount           uint64 `json:"entry_count"`
	FirstSeq             uint64 `json:"first_seq"`
	LastSeq              uint64 `json:"last_seq"`
	LaterSignedCovered   bool   `json:"later_signed_checkpoint_covered"`
	CoveredByRecorderSeq uint64 `json:"covered_by_recorder_seq,omitempty"`
}

type compactReceiptSuffix struct {
	Count          uint64 `json:"signed_receipts"`
	OriginSeq      uint64 `json:"origin_seq"`
	OriginPrevHash string `json:"origin_prev_hash"`
	FinalSeq       uint64 `json:"final_seq"`
	Head           string `json:"head"`
}

type compactReceiptDegradation struct {
	File              string `json:"file"`
	RecorderSeq       uint64 `json:"recorder_seq"`
	OriginalSize      int64  `json:"original_size"`
	CheckpointCovered bool   `json:"checkpoint_covered"`
	Reason            string `json:"reason"`
}

const compactLegacyRedactionReason = "known whole-receipt redaction tombstone"

type compactLegacyReceiptTombstone struct {
	Redacted         bool        `json:"redacted"`
	DetectedPatterns []string    `json:"detected_patterns"`
	OriginalSize     json.Number `json:"original_size"`
}

func decodeCompactLegacyReceiptTombstone(raw []byte) (int64, bool) {
	if err := jsonscan.RejectDuplicateKeys(raw); err != nil {
		return 0, false
	}
	var tombstone compactLegacyReceiptTombstone
	if err := contract.DecodeStrictJSON(raw, &tombstone); err != nil || !tombstone.Redacted || len(tombstone.DetectedPatterns) == 0 {
		return 0, false
	}
	for _, marker := range tombstone.DetectedPatterns {
		if !strings.HasPrefix(marker, "[REDACTED:") || !strings.HasSuffix(marker, "]") || len(marker) <= len("[REDACTED:]") || strings.ContainsAny(marker, "\r\n") {
			return 0, false
		}
	}
	size, err := strconv.ParseInt(string(tombstone.OriginalSize), 10, 64)
	if err != nil || size <= 0 {
		return 0, false
	}
	return size, true
}

// compactOuterVerifier checks the recorder envelope while each line is still
// in its original byte form.  RawDetail is retained by ParseEntryLine, so the
// compatibility hash covers historical v1 detail bytes rather than a decoded
// map re-marshaled in a different order.
type compactOuterVerifier struct {
	key                 ed25519.PublicKey
	seen                bool
	previous            string
	nextSeq             uint64
	v3Seen              bool
	v3Session           string
	v3Kind              string
	v3Writer            string
	unsignedCheckpoints []compactUnsignedCheckpoint
}

func (v *compactOuterVerifier) add(e recorder.Entry, session string, files ...string) error {
	file := ""
	if len(files) > 0 {
		file = files[0]
	}
	if e.SessionID != session {
		return fmt.Errorf("entry seq %d belongs to %q, not %q", e.Sequence, e.SessionID, session)
	}
	if err := recorder.ValidateEntrySchema(e); err != nil {
		return fmt.Errorf("entry seq %d: %w", e.Sequence, err)
	}
	if recorder.EntryVersionHasNamespace(e.Version) {
		if v.seen && !v.v3Seen {
			return fmt.Errorf("entry seq %d: v3 chain cannot continue legacy recorder namespace", e.Sequence)
		}
		if !v.v3Seen {
			v.v3Seen, v.v3Session, v.v3Kind, v.v3Writer = true, e.SessionID, e.ChainKind, e.WriterInstanceID
		} else if e.SessionID != v.v3Session || e.ChainKind != v.v3Kind || e.WriterInstanceID != v.v3Writer {
			return fmt.Errorf("entry seq %d: v3 recorder namespace changed", e.Sequence)
		}
	} else if v.v3Seen {
		return fmt.Errorf("entry seq %d: legacy entry cannot continue v3 recorder namespace", e.Sequence)
	}
	if got := recorder.ComputeHash(e); got == "" || got != e.Hash {
		return fmt.Errorf("entry seq %d: hash mismatch", e.Sequence)
	}
	if !v.seen {
		if e.Sequence != 0 || e.PrevHash != recorder.GenesisHash {
			return fmt.Errorf("entry seq %d: invalid recorder genesis", e.Sequence)
		}
		v.seen = true
	} else if e.Sequence != v.nextSeq || e.PrevHash != v.previous {
		return fmt.Errorf("entry seq %d: recorder sequence or hash chain break", e.Sequence)
	}
	if e.Type == "checkpoint" {
		var detail recorder.CheckpointDetail
		if err := json.Unmarshal(e.RawDetail, &detail); err != nil {
			return fmt.Errorf("entry seq %d: unmarshaling checkpoint detail: %w", e.Sequence, err)
		}
		if detail.Signature == "" {
			if len(v.unsignedCheckpoints) >= maxCompactUnsignedCheckpoints {
				return fmt.Errorf("entry seq %d: unsigned checkpoint count exceeds compaction limit %d", e.Sequence, maxCompactUnsignedCheckpoints)
			}
			v.unsignedCheckpoints = append(v.unsignedCheckpoints, compactUnsignedCheckpoint{File: file, RecorderSeq: e.Sequence, EntryCount: detail.EntryCount, FirstSeq: detail.FirstSeq, LastSeq: detail.LastSeq})
		} else {
			if len(v.key) != ed25519.PublicKeySize {
				return fmt.Errorf("entry seq %d: trusted checkpoint public key is required", e.Sequence)
			}
			if err := recorder.VerifyCheckpoints([]recorder.Entry{e}, v.key); err != nil {
				return err
			}
			for i := range v.unsignedCheckpoints {
				v.unsignedCheckpoints[i].LaterSignedCovered = true
				if v.unsignedCheckpoints[i].CoveredByRecorderSeq == 0 {
					v.unsignedCheckpoints[i].CoveredByRecorderSeq = e.Sequence
				}
			}
		}
	}
	v.previous, v.nextSeq = e.Hash, e.Sequence+1
	return nil
}

// streamCompactFiles processes every source shard with a bounded scanner and
// calls consume once per complete JSONL record.  It never retains a source
// shard, parsed entry set, or aggregate corpus in memory.
func streamCompactFiles(location recorder.EvidenceLocation, files []string, session string, key ed25519.PublicKey, consume func(compactStreamFile, []byte, recorder.Entry) error) (compactStreamProof, error) {
	var proof compactStreamProof
	h := sha256.New()
	outer := compactOuterVerifier{key: key}
	keyHex := hex.EncodeToString(key)
	v1, err := legacyreceipt.NewStreamingVerifier(keyHex)
	if err != nil {
		return compactStreamProof{}, fmt.Errorf("initialize v1 receipt verifier: %w", err)
	}
	v2, err := contractreceipt.NewPinnedStreamingVerifier(key)
	if err != nil {
		return compactStreamProof{}, fmt.Errorf("initialize v2 receipt verifier: %w", err)
	}
	var suffix *legacyreceipt.UnanchoredSuffixVerifier
	var suffixCount uint64
	var expectedSuffixOrigin *uint64
	var v1EntrySeen bool
	finishSuffix := func() error {
		if suffix == nil || suffixCount == 0 {
			return nil
		}
		result, finishErr := suffix.Finish()
		if finishErr != nil {
			return finishErr
		}
		proof.v1Suffixes = append(proof.v1Suffixes, compactReceiptSuffix{Count: result.Count, OriginSeq: result.OriginSeq, OriginPrevHash: result.OriginPrevHash, FinalSeq: result.FinalSeq, Head: result.Head})
		suffix = nil
		suffixCount = 0
		return nil
	}
	for _, name := range files {
		path := filepath.Join(location.Dir, name)
		var fileProof compactStreamFile
		err := recorder.StreamEvidenceLocationFileForOfflineCompaction(location, name, func(r io.Reader, info os.FileInfo) error {
			fileProof = compactStreamFile{name: name, path: path, info: info}
			fileHash := sha256.New()
			s := bufio.NewScanner(r)
			// A single output record must fit in a normal reader shard.  Scanner's
			// buffer is therefore bounded to that same operator-visible limit plus
			// the required newline, instead of accepting an attacker-sized line.
			s.Buffer(make([]byte, 64<<10), recorder.MaxEntryLineBytes+1)
			for s.Scan() {
				line := append(append([]byte(nil), s.Bytes()...), '\n')
				entry, parseErr := recorder.ParseEntryLine(bytes.TrimSuffix(line, []byte("\n")))
				if parseErr != nil {
					return fmt.Errorf("parse %s: %w", name, parseErr)
				}
				if err := outer.add(entry, session, name); err != nil {
					return err
				}
				if _, ok := compactKnownRecorderTypes[entry.Type]; !ok {
					return fmt.Errorf("unknown recorder entry type %q at seq %d", entry.Type, entry.Sequence)
				}
				if entry.Type == "checkpoint" {
					for i := range proof.degradations {
						proof.degradations[i].CheckpointCovered = true
					}
				}
				switch entry.Type {
				case "action_receipt":
					originalSize, tombstone := decodeCompactLegacyReceiptTombstone(entry.RawDetail)
					if !v1EntrySeen {
						proof.v1FirstGap = tombstone
						v1EntrySeen = true
					}
					proof.v1TailGap = tombstone
					if tombstone {
						if !proof.v1Degraded && proof.v1Count > 0 {
							result := v1.Finish()
							proof.v1Suffixes = append(proof.v1Suffixes, compactReceiptSuffix{Count: result.ReceiptCount, OriginSeq: 0, OriginPrevHash: legacyreceipt.GenesisHash, FinalSeq: result.FinalSeq, Head: result.RootHash})
							next, nextErr := advanceCompactSuffixOrigin(result.FinalSeq, 2)
							if nextErr != nil {
								return nextErr
							}
							expectedSuffixOrigin = &next
						} else if suffixCount > 0 {
							result, finishErr := suffix.Finish()
							if finishErr != nil {
								return fmt.Errorf("finish v1 suffix before redaction tombstone: %w", finishErr)
							}
							if err := finishSuffix(); err != nil {
								return fmt.Errorf("record v1 suffix before redaction tombstone: %w", err)
							}
							next, nextErr := advanceCompactSuffixOrigin(result.FinalSeq, 2)
							if nextErr != nil {
								return nextErr
							}
							expectedSuffixOrigin = &next
						} else if expectedSuffixOrigin != nil {
							next, nextErr := advanceCompactSuffixOrigin(*expectedSuffixOrigin, 1)
							if nextErr != nil {
								return nextErr
							}
							*expectedSuffixOrigin = next
						} else {
							next := uint64(1)
							expectedSuffixOrigin = &next
						}
						proof.v1Degraded = true
						proof.degradations = append(proof.degradations, compactReceiptDegradation{File: name, RecorderSeq: entry.Sequence, OriginalSize: originalSize, Reason: compactLegacyRedactionReason})
					} else if proof.v1Degraded {
						if suffix == nil {
							suffix, err = legacyreceipt.NewUnanchoredSuffixVerifier(keyHex)
							if err != nil {
								return fmt.Errorf("initialize v1 suffix verifier: %w", err)
							}
						}
						if err := suffix.Add(entry.RawDetail); err != nil {
							return fmt.Errorf("verify v1 action_receipt after degraded chain at recorder seq %d: %w", entry.Sequence, err)
						}
						if suffixCount == 0 && expectedSuffixOrigin != nil {
							result, finishErr := suffix.Finish()
							if finishErr != nil {
								return fmt.Errorf("inspect v1 suffix origin: %w", finishErr)
							}
							if result.OriginSeq != *expectedSuffixOrigin {
								return fmt.Errorf("verify v1 action_receipt after degraded chain at recorder seq %d: expected suffix chain_seq %d, got %d", entry.Sequence, *expectedSuffixOrigin, result.OriginSeq)
							}
						}
						suffixCount++
						proof.v1Count++
					} else if err := v1.Add(entry.RawDetail); err != nil {
						return fmt.Errorf("verify v1 action_receipt at recorder seq %d: %w", entry.Sequence, err)
					} else {
						proof.v1Count++
					}
				case contractreceipt.EvidenceEntryType:
					if err := v2.AddRaw(entry.RawDetail); err != nil {
						return fmt.Errorf("verify v2 evidence_receipt at recorder seq %d: %w", entry.Sequence, err)
					}
					proof.v2Count++
				}
				if err := consume(fileProof, line, entry); err != nil {
					return err
				}
				_, _ = h.Write(line)
				_, _ = fileHash.Write(line)
				fileProof.bytes += int64(len(line))
			}
			if err := s.Err(); err != nil {
				return fmt.Errorf("read %s: %w", name, err)
			}
			if fileProof.bytes == 0 {
				return fmt.Errorf("%s is empty", name)
			}
			// Scanner discards delimiters.  A missing final newline is unsafe:
			// otherwise the first record of the next shard could be glued to it.
			if fileProof.bytes != info.Size() {
				return fmt.Errorf("%s does not end in newline or changed during read", name)
			}
			fileProof.sum = hex.EncodeToString(fileHash.Sum(nil))
			return nil
		})
		if err != nil {
			return compactStreamProof{}, err
		}
		// Per-file digest is computed in a second bounded stream during the
		// source identity recheck.  The first pass only records identity and
		// byte count, so it cannot accidentally double memory with a 4GiB hash
		// input buffer.
		proof.files = append(proof.files, fileProof)
		proof.bytes += fileProof.bytes
	}
	if !outer.seen {
		return compactStreamProof{}, fmt.Errorf("session %q contains no entries", session)
	}
	proof.unsignedCheckpoints = append(proof.unsignedCheckpoints, outer.unsignedCheckpoints...)
	if proof.v1Count == 0 && proof.v2Count == 0 {
		return compactStreamProof{}, fmt.Errorf("session %q contains no signed evidence receipts", session)
	}
	if proof.v1Count > 0 && !proof.v1Degraded {
		result := v1.Finish()
		if !result.Valid {
			return compactStreamProof{}, fmt.Errorf("verify v1 receipt chain: %s", result.Error)
		}
		proof.v1Head = result.RootHash
	} else if proof.v1Degraded {
		if err := finishSuffix(); err != nil {
			return compactStreamProof{}, fmt.Errorf("finish v1 degraded suffix: %w", err)
		}
	}
	if proof.v2Count > 0 {
		result := v2.Finish()
		if !result.Valid || !result.SignaturesVerified {
			return compactStreamProof{}, fmt.Errorf("verify v2 receipt chain: %s", result.Error)
		}
		proof.v2Head = result.RootHash
	}
	proof.sum = hex.EncodeToString(h.Sum(nil))
	return proof, nil
}
