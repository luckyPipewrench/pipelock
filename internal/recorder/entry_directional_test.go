// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeDirectionalEntries(t *testing.T, path string, count int) {
	t.Helper()
	file, err := os.OpenFile(filepath.Clean(path), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	encoder := json.NewEncoder(file)
	for i := range count {
		entry := Entry{
			Version:   EntryVersion,
			Sequence:  uint64(i),
			Timestamp: time.Unix(1712345678, 0).UTC(),
			SessionID: "directional",
			Type:      "request",
			Transport: "http",
			Summary:   "bounded directional fixture",
			Detail:    map[string]string{"safe": "value"},
			PrevHash:  "prev",
			Hash:      "hash",
		}
		if err := encoder.Encode(entry); err != nil {
			_ = file.Close()
			t.Fatalf("Encode: %v", err)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestReadDirectionalEntriesBounded_OrderAndTruncation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence-directional-0.jsonl")
	writeDirectionalEntries(t, path, 5)

	head, headTruncated, err := ReadHeadEntriesBounded(path, 2, MaxEvidenceReadFileBytes)
	if err != nil {
		t.Fatalf("ReadHeadEntriesBounded: %v", err)
	}
	if !headTruncated || len(head) != 2 || head[0].Sequence != 0 || head[1].Sequence != 1 {
		t.Fatalf("head = seqs %v truncated=%v, want [0 1] true", entrySequences(head), headTruncated)
	}

	tail, tailTruncated, err := ReadTailEntriesBounded(path, 2, MaxEvidenceReadFileBytes)
	if err != nil {
		t.Fatalf("ReadTailEntriesBounded: %v", err)
	}
	if !tailTruncated || len(tail) != 2 || tail[0].Sequence != 4 || tail[1].Sequence != 3 {
		t.Fatalf("tail = seqs %v truncated=%v, want [4 3] true", entrySequences(tail), tailTruncated)
	}
}

func TestReadTailEntriesBounded_SkipsPartialBoundaryButRejectsMalformedTail(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "evidence-directional-0.jsonl")
	writeDirectionalEntries(t, path, 1)
	validTail, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	prefix := strings.Repeat("x", MaxEntryLineBytes+128) + "\n"
	if err := os.WriteFile(path, append([]byte(prefix), validTail...), 0o600); err != nil {
		t.Fatalf("WriteFile partial-boundary fixture: %v", err)
	}

	entries, truncated, err := ReadTailEntriesBounded(path, 1, int64(len(validTail)))
	if err != nil {
		t.Fatalf("ReadTailEntriesBounded after partial boundary: %v", err)
	}
	if !truncated || len(entries) != 1 || entries[0].Sequence != 0 {
		t.Fatalf("entries = seqs %v truncated=%v, want [0] true", entrySequences(entries), truncated)
	}

	if err := os.WriteFile(path, []byte(`{"v":2,"seq":9`), 0o600); err != nil {
		t.Fatalf("WriteFile malformed tail: %v", err)
	}
	if _, _, err := ReadTailEntriesBounded(path, 1, MaxEvidenceReadFileBytes); err == nil {
		t.Fatal("ReadTailEntriesBounded malformed tail = nil error, want refusal")
	}
}

func TestReadDirectionalEntriesBounded_RejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "evidence-target-0.jsonl")
	link := filepath.Join(dir, "evidence-link-0.jsonl")
	writeDirectionalEntries(t, target, 1)
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	if _, _, err := ReadHeadEntriesBounded(link, 1, MaxEvidenceReadFileBytes); err == nil {
		t.Fatal("ReadHeadEntriesBounded symlink = nil error, want refusal")
	}
	if _, _, err := ReadTailEntriesBounded(link, 1, MaxEvidenceReadFileBytes); err == nil {
		t.Fatal("ReadTailEntriesBounded symlink = nil error, want refusal")
	}
}

func entrySequences(entries []Entry) []uint64 {
	sequences := make([]uint64, 0, len(entries))
	for _, entry := range entries {
		sequences = append(sequences, entry.Sequence)
	}
	return sequences
}
