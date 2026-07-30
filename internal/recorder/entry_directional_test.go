// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
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
	t.Run("skips partial boundary", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "evidence-directional-0.jsonl")
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
	})

	t.Run("rejects malformed tail", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "evidence-directional-0.jsonl")
		if err := os.WriteFile(path, []byte(`{"v":2,"seq":9`), 0o600); err != nil {
			t.Fatalf("WriteFile malformed tail: %v", err)
		}
		if _, _, err := ReadTailEntriesBounded(path, 1, MaxEvidenceReadFileBytes); err == nil {
			t.Fatal("ReadTailEntriesBounded malformed tail = nil error, want refusal")
		}
	})
}

func TestFindLastEntry_ScansPastBoundedTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence-directional-0.jsonl")
	file, err := os.OpenFile(filepath.Clean(path), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	encoder := json.NewEncoder(file)
	want := Entry{Version: EntryVersion, Sequence: 7, Timestamp: time.Unix(1712345678, 0).UTC(), SessionID: "directional", Type: "receipt", Transport: "http", Summary: "target", Detail: map[string]string{"safe": "value"}, PrevHash: "prev", Hash: "hash"}
	if err := encoder.Encode(want); err != nil {
		t.Fatalf("Encode target: %v", err)
	}
	padding := strings.Repeat("x", 512<<10)
	for seq := uint64(8); ; seq++ {
		entry := want
		entry.Sequence = seq
		entry.Type = "request"
		entry.Summary = padding
		if err := encoder.Encode(entry); err != nil {
			t.Fatalf("Encode padding: %v", err)
		}
		info, statErr := file.Stat()
		if statErr != nil {
			t.Fatalf("Stat: %v", statErr)
		}
		if info.Size() > MaxEvidenceReadFileBytes+(1<<20) {
			break
		}
	}
	if err := file.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	got, found, err := FindLastEntry(path, func(entry Entry) bool { return entry.Type == "receipt" })
	if err != nil {
		t.Fatalf("FindLastEntry: %v", err)
	}
	if !found || got.Sequence != want.Sequence {
		t.Fatalf("FindLastEntry = seq %d found=%v, want seq %d true", got.Sequence, found, want.Sequence)
	}
}

func TestFindLastEntry_FailsClosedOnMalformedNewerEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence-directional-0.jsonl")
	writeDirectionalEntries(t, path, 1)
	file, err := os.OpenFile(filepath.Clean(path), os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if _, err := file.WriteString(`{"v":2,"seq":9`); err != nil {
		_ = file.Close()
		t.Fatalf("WriteString malformed tail: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, _, err := FindLastEntry(path, func(Entry) bool { return true }); err == nil {
		t.Fatal("FindLastEntry malformed newer entry = nil error, want refusal")
	}
}

func TestFindLastEntry_RejectsOversizedLineAtWindowBoundary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence-directional-0.jsonl")
	window := MaxEvidenceReadFileBytes + int64(maxEntryWireLineBytes+1)
	data := strings.Repeat("x", int(window)) + "\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("WriteFile oversized line: %v", err)
	}

	if _, _, err := FindLastEntry(path, func(Entry) bool { return true }); err == nil || !strings.Contains(err.Error(), "tail line exceeds") {
		t.Fatalf("FindLastEntry oversized line error = %v, want bounded refusal", err)
	}
}

func TestFindLastEntry_EmptyAndNoMatch(t *testing.T) {
	empty := filepath.Join(t.TempDir(), "evidence-directional-0.jsonl")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatalf("WriteFile empty shard: %v", err)
	}
	if _, found, err := FindLastEntry(empty, func(Entry) bool { return true }); err != nil || found {
		t.Fatalf("FindLastEntry(empty) found=%v error=%v, want false nil", found, err)
	}

	populated := filepath.Join(t.TempDir(), "evidence-directional-1.jsonl")
	writeDirectionalEntries(t, populated, 2)
	if _, found, err := FindLastEntry(populated, func(entry Entry) bool { return entry.Type == "receipt" }); err != nil || found {
		t.Fatalf("FindLastEntry(no match) found=%v error=%v, want false nil", found, err)
	}
}

func TestFindLastEntry_RequiresMatcher(t *testing.T) {
	if _, _, err := FindLastEntry(filepath.Join(t.TempDir(), "missing.jsonl"), nil); err == nil {
		t.Fatal("FindLastEntry nil matcher = nil error, want refusal")
	}
}

func TestEnsureEvidenceFileUnchanged_RejectsMutation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence-directional-0.jsonl")
	writeDirectionalEntries(t, path, 1)
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = file.Close() }()
	before, err := file.Stat()
	if err != nil {
		t.Fatalf("Stat before: %v", err)
	}
	if err := os.Truncate(path, before.Size()-1); err != nil {
		t.Fatalf("Truncate: %v", err)
	}
	if err := ensureEvidenceFileUnchanged(file, before); err == nil {
		t.Fatal("ensureEvidenceFileUnchanged after mutation = nil error, want refusal")
	}
}

func TestReadDirectionalEntriesBounded_RejectsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires elevated privileges on Windows")
	}
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

func TestDirectionalEntryReaders_EdgeCases(t *testing.T) {
	t.Run("missing paths", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "missing.jsonl")
		if _, _, err := ReadHeadEntriesBounded(path, 1, 1); err == nil {
			t.Fatal("ReadHeadEntriesBounded(missing) error = nil")
		}
		if _, _, err := ReadTailEntriesBounded(path, 1, 1); err == nil {
			t.Fatal("ReadTailEntriesBounded(missing) error = nil")
		}
		if _, _, err := FindLastEntry(path, func(Entry) bool { return true }); err == nil {
			t.Fatal("FindLastEntry(missing) error = nil")
		}
	})

	t.Run("empty tail", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "empty.jsonl")
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		entries, truncated, err := ReadTailEntriesBounded(path, 0, 0)
		if err != nil || truncated || len(entries) != 0 {
			t.Fatalf("ReadTailEntriesBounded(empty) entries=%v truncated=%v error=%v", entries, truncated, err)
		}
	})

	t.Run("default limits and CRLF", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "crlf.jsonl")
		writeDirectionalEntries(t, path, 1)
		data, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			t.Fatal(err)
		}
		data = bytes.ReplaceAll(data, []byte("\n"), []byte("\r\n"))
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if entries, _, err := ReadHeadEntriesBounded(path, 0, 0); err != nil || len(entries) != 1 {
			t.Fatalf("ReadHeadEntriesBounded(CRLF) entries=%v error=%v", entries, err)
		}
		if entries, _, err := ReadTailEntriesBounded(path, 0, 0); err != nil || len(entries) != 1 {
			t.Fatalf("ReadTailEntriesBounded(CRLF) entries=%v error=%v", entries, err)
		}
		if _, found, err := FindLastEntry(path, func(Entry) bool { return true }); err != nil || !found {
			t.Fatalf("FindLastEntry(CRLF) found=%v error=%v", found, err)
		}
	})

	t.Run("malformed head", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "malformed.jsonl")
		if err := os.WriteFile(path, []byte("{bad\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := ReadHeadEntriesBounded(path, 1, MaxEvidenceReadFileBytes); err == nil {
			t.Fatal("ReadHeadEntriesBounded(malformed) error = nil")
		}
	})

	t.Run("oversized complete line", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "oversized.jsonl")
		if err := os.WriteFile(path, []byte(strings.Repeat("x", MaxEntryLineBytes+1)+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := ReadTailEntriesBounded(path, 1, MaxEvidenceReadFileBytes); err == nil || !strings.Contains(err.Error(), "tail line exceeds") {
			t.Fatalf("ReadTailEntriesBounded(oversized) error=%v", err)
		}
		if _, _, err := FindLastEntry(path, func(Entry) bool { return true }); err == nil || !strings.Contains(err.Error(), "tail line exceeds") {
			t.Fatalf("FindLastEntry(oversized) error=%v", err)
		}
	})

	t.Run("oversized boundary without newline", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "oversized-boundary.jsonl")
		window := MaxEvidenceReadFileBytes + int64(maxEntryWireLineBytes+1)
		if err := os.WriteFile(path, []byte(strings.Repeat("x", int(window+1))), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := FindLastEntry(path, func(Entry) bool { return true }); err == nil || !strings.Contains(err.Error(), "tail line exceeds") {
			t.Fatalf("FindLastEntry(no newline) error=%v", err)
		}
	})

	t.Run("parser and stat failures", func(t *testing.T) {
		if _, err := parseDirectionalEntry(nil); err == nil {
			t.Fatal("parseDirectionalEntry(empty) error = nil")
		}
		path := filepath.Join(t.TempDir(), "closed.jsonl")
		writeDirectionalEntries(t, path, 1)
		file, err := os.Open(filepath.Clean(path))
		if err != nil {
			t.Fatal(err)
		}
		before, err := file.Stat()
		if err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		if err := ensureEvidenceFileUnchanged(file, before); err == nil {
			t.Fatal("ensureEvidenceFileUnchanged(closed) error = nil")
		}
	})
}

func entrySequences(entries []Entry) []uint64 {
	sequences := make([]uint64, 0, len(entries))
	for _, entry := range entries {
		sequences = append(sequences, entry.Sequence)
	}
	return sequences
}
