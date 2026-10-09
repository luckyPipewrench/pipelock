// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"fmt"
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
			inv[fmt.Sprintf("%q %q", location.ID, name)] = record
		}
	}
	return inv, nil
}

// stableWith reports whether after describes the same evidence as inv. The
// one change it accepts is a live recorder appending to its active shard: the
// highest-sequence JSONL shard of each session may grow in place (same file,
// same mode, no shrink). Anything else, including a new shard, a rotated or
// rewritten one, or a change to links, sidecars or group artifacts, is a
// change. Facts the scan drew from the shard's earlier bytes still hold
// after an append, so the audit stays conclusive while a proxy runs.
func (inv doctorInventory) stableWith(after doctorInventory) bool {
	if len(inv) != len(after) {
		return false
	}
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
	growable := make(map[string]bool, len(active))
	for _, key := range active {
		growable[key] = true
	}
	for key, b := range inv {
		a, ok := after[key]
		if !ok {
			return false
		}
		if a.identity == b.identity && a.mode == b.mode && a.size == b.size && a.mtime == b.mtime {
			continue
		}
		if growable[key] && os.SameFile(b.info, a.info) && a.mode == b.mode && a.size >= b.size {
			continue
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
