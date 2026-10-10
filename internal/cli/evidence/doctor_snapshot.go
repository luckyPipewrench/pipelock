// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// doctorInventoryRecord is one evidence file as the doctor's inventory saw it.
type doctorInventoryRecord struct {
	location string
	info     os.FileInfo
	identity string
	mode     os.FileMode
	size     int64
	mtime    int64
	session  string
	seq      uint64
	jsonl    bool
	path     string
	// prefix is the SHA-256 of the first prefixLen bytes, recorded for
	// each session's active shard so growth can be shown to be an append.
	prefix    []byte
	prefixLen int64
}

// doctorInventory maps location ID and file name to the file's record.
type doctorInventory map[string]doctorInventoryRecord

// doctorCorpusInventory binds both location discovery and the files consumed
// by the structural and continuity scans. A final comparison is required even
// when a consumer reports damage or returns an error. Unrelated files are not
// evidence; their arrival must not make an otherwise stable audit unavailable.
func doctorCorpusInventory(locations []recorder.EvidenceLocation) (doctorInventory, error) {
	inv := make(doctorInventory)
	for _, location := range locations {
		entries, err := recorder.ReadEvidenceLocationEntries(location)
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			name := entry.Name()
			if !isDoctorEvidenceJSONL(name) && !isDoctorRawSidecar(name) &&
				!strings.HasPrefix(name, "chain-link-") && !strings.HasPrefix(name, "receipt-group-") && name != "ael" {
				continue
			}
			path := filepath.Join(location.Dir, name)
			info, err := os.Lstat(path)
			if err != nil {
				return nil, err
			}
			identity, err := recorder.EvidenceMetadataIdentity(path, info)
			if err != nil {
				return nil, err
			}
			record := doctorInventoryRecord{location: location.ID, info: info, identity: identity, mode: info.Mode(), size: info.Size(), mtime: info.ModTime().UnixNano()}
			record.session, record.seq, record.jsonl = parseDoctorEvidenceName(name, ".jsonl")
			record.path = path
			inv[fmt.Sprintf("%q %q", location.ID, name)] = record
		}
	}
	for key := range inv.activeShards() {
		record := inv[key]
		// Hash at most one byte past the doctor's per-file read limit. A
		// shard over that limit gets no growth allowance: the scan reports
		// it as oversized, and the audit cannot vouch for bytes it skipped.
		sum, n, err := hashEvidencePrefix(record.path, recorder.MaxEvidenceReadFileBytes+1)
		if err != nil || n > recorder.MaxEvidenceReadFileBytes {
			// No proof of the starting bytes means no growth allowance; the
			// scan itself reports why the shard could not be read.
			continue
		}
		record.prefix, record.prefixLen = sum, n
		inv[key] = record
	}
	return inv, nil
}

// activeShards names the highest-sequence JSONL shard of each session in
// each location: the one shard a running recorder may still append to.
func (inv doctorInventory) activeShards() map[string]bool {
	active := make(map[string]string)
	for key, r := range inv {
		if !r.jsonl {
			continue
		}
		group := fmt.Sprintf("%q %q", r.location, r.session)
		if current, ok := active[group]; !ok || inv[current].seq < r.seq {
			active[group] = key
		}
	}
	keys := make(map[string]bool, len(active))
	for _, key := range active {
		keys[key] = true
	}
	return keys
}

// hashEvidencePrefix hashes the first limit bytes of an evidence file
// through the recorder's no-follow open. It returns the digest and the number
// of bytes hashed.
func hashEvidencePrefix(path string, limit int64) ([]byte, int64, error) {
	file, _, err := recorder.OpenEvidenceFile(path)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = file.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(file, limit))
	if err != nil {
		return nil, 0, err
	}
	return h.Sum(nil), n, nil
}

// stableWith reports whether after describes the same evidence as inv. The
// one change it accepts is a live recorder appending to its active shard: the
// highest-sequence JSONL shard of each session may grow in place: same file,
// same mode, and the bytes it held at inventory time still at its front.
// Anything else, including a new shard, a rotated or rewritten one, or a
// change to links, sidecars or group artifacts, is a change. Facts the scan
// drew from the shard's earlier bytes still hold after an append, so the
// audit stays conclusive while a proxy runs. Bytes appended after the scan
// were not examined; the next run covers them.
//
// This compares two inventories, not an atomic snapshot: a writer that
// rewrites a shard during the scan and restores it, metadata included, before
// the final inventory is not detected. When a result must be stable, stop the
// writer or audit a copied snapshot.
func (inv doctorInventory) stableWith(after doctorInventory) bool {
	if len(inv) != len(after) {
		return false
	}
	growable := inv.activeShards()
	for key, b := range inv {
		a, ok := after[key]
		if !ok {
			return false
		}
		if a.identity == b.identity && a.mode == b.mode && a.size == b.size && a.mtime == b.mtime {
			continue
		}
		if growable[key] && b.prefix != nil && os.SameFile(b.info, a.info) && a.mode == b.mode && a.size >= b.prefixLen {
			// Same file and not shorter is not yet an append: the bytes the
			// scan read must still be the bytes at the front of the file.
			sum, n, err := hashEvidencePrefix(b.path, b.prefixLen)
			if err == nil && n == b.prefixLen && bytes.Equal(sum, b.prefix) {
				continue
			}
		}
		return false
	}
	return true
}

func inconclusiveDoctorReport(dir string, err error) evidenceDoctorReport {
	return evidenceDoctorReport{
		Dir: dir, ReadIncomplete: true,
		Findings: []evidenceDoctorFinding{{Kind: "directory_read_error", Message: "evidence audit incomplete: " + err.Error()}},
	}
}
