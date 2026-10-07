// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build js && wasm

package receipt

import (
	"fmt"
	"path/filepath"
	"sort"

	"github.com/luckyPipewrench/pipelock/internal/evidencename"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

const maxWASMReceiptInventoryEntries = 4096

type wasmIndexedRecorderFile struct {
	session string
	name    string
	seq     uint64
}

// indexRecorderFilesExcludingGroupsSpill keeps the same session grouping and
// ordering as the native disk index. In the browser the input archive is
// already limited to 4096 entries, so sorting this bounded slice is safe.
func indexRecorderFilesExcludingGroupsSpill(dir string) (evidenceIndex, error) {
	entries, truncated, err := recorder.ReadEvidenceLocationEntriesBounded(
		recorder.EvidenceLocation{Root: dir, Dir: dir}, maxWASMReceiptInventoryEntries)
	if err != nil {
		return nil, err
	}
	if truncated {
		return nil, fmt.Errorf("receipt archive inventory exceeds %d entries", maxWASMReceiptInventoryEntries)
	}
	files := make([]wasmIndexedRecorderFile, 0, len(entries))
	for _, entry := range entries {
		session, seq, ok := evidencename.Parse(entry.Name())
		if !ok {
			continue
		}
		files = append(files, wasmIndexedRecorderFile{session: session, name: entry.Name(), seq: seq})
	}
	sort.Slice(files, func(i, j int) bool {
		if files[i].session != files[j].session {
			return files[i].session < files[j].session
		}
		if files[i].seq != files[j].seq {
			return files[i].seq < files[j].seq
		}
		return files[i].name < files[j].name
	})
	index := make(evidenceIndex)
	current := ""
	var shards []indexedRecorderShard
	flush := func() {
		if current != "" && len(shards) > 0 && !isGroupSessionShards(shards) {
			paths := make([]string, 0, len(shards))
			for _, shard := range shards {
				paths = append(paths, shard.path)
			}
			index[current] = paths
		}
		current, shards = "", nil
	}
	for _, file := range files {
		if current != "" && current != file.session {
			flush()
		}
		current = file.session
		shards = append(shards, indexedRecorderShard{
			path: filepath.Join(filepath.Clean(dir), file.name), base: file.name, seqStart: file.seq,
		})
	}
	flush()
	return index, nil
}
