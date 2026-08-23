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
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/evidencename"
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
	if w.current == nil || w.currentBytes+int64(len(line)) > recorder.MaxEvidenceReadFileBytes {
		if err := w.close(); err != nil {
			return err
		}
		if len(w.files) > 0 && source.info.Mode().Perm() != w.files[0].info.Mode().Perm() {
			return fmt.Errorf("source shard mode differs; compaction cannot preserve per-output provenance")
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
	return a.bytes == b.bytes && a.sum == b.sum && a.v1Count == b.v1Count && a.v1Head == b.v1Head && a.v2Count == b.v2Count && a.v2Head == b.v2Head
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

const maxCompactInputShards = 4096

var compactKnownRecorderTypes = map[string]struct{}{
	"action_receipt": {}, "evidence_receipt": {}, "checkpoint": {}, "transcript_root": {}, "decision": {}, "capture": {}, "capture_drop": {},
}

type compactStreamProof struct {
	files   []compactStreamFile
	bytes   int64
	sum     string
	v1Count uint64
	v1Head  string
	v2Count uint64
	v2Head  string
}

// compactOuterVerifier checks the recorder envelope while each line is still
// in its original byte form.  RawDetail is retained by ParseEntryLine, so the
// compatibility hash covers historical v1 detail bytes rather than a decoded
// map re-marshaled in a different order.
type compactOuterVerifier struct {
	key       ed25519.PublicKey
	seen      bool
	previous  string
	nextSeq   uint64
	v3Seen    bool
	v3Session string
	v3Kind    string
	v3Writer  string
}

func (v *compactOuterVerifier) add(e recorder.Entry, session string) error {
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
	if e.Type == "checkpoint" && len(v.key) != 0 {
		if err := recorder.VerifyCheckpoints([]recorder.Entry{e}, v.key); err != nil {
			return err
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
	v1, err := legacyreceipt.NewStreamingVerifier(hex.EncodeToString(key))
	if err != nil {
		return compactStreamProof{}, fmt.Errorf("initialize v1 receipt verifier: %w", err)
	}
	v2, err := contractreceipt.NewPinnedStreamingVerifier(key)
	if err != nil {
		return compactStreamProof{}, fmt.Errorf("initialize v2 receipt verifier: %w", err)
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
				if err := outer.add(entry, session); err != nil {
					return err
				}
				if _, ok := compactKnownRecorderTypes[entry.Type]; !ok {
					return fmt.Errorf("unknown recorder entry type %q at seq %d", entry.Type, entry.Sequence)
				}
				switch entry.Type {
				case "action_receipt":
					if err := v1.Add(entry.RawDetail); err != nil {
						return fmt.Errorf("verify v1 action_receipt at recorder seq %d: %w", entry.Sequence, err)
					}
					proof.v1Count++
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
	if proof.v1Count == 0 && proof.v2Count == 0 {
		return compactStreamProof{}, fmt.Errorf("session %q contains no signed evidence receipts", session)
	}
	if proof.v1Count > 0 {
		result := v1.Finish()
		if !result.Valid {
			return compactStreamProof{}, fmt.Errorf("verify v1 receipt chain: %s", result.Error)
		}
		proof.v1Head = result.RootHash
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
