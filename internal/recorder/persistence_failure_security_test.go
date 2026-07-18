// Copyright 2026 Pipelock contributors
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

func newPersistenceTestRecorder(t *testing.T, dir string) *Recorder {
	t.Helper()

	rec, err := New(Config{
		Enabled:            true,
		Dir:                dir,
		CheckpointInterval: 1000,
		SignCheckpoints:    false,
	}, nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return rec
}

func openSSFCoverageEntry(sessionID, summary string) Entry {
	return Entry{
		SessionID: sessionID,
		Type:      "request",
		Transport: "fetch",
		Summary:   summary,
		Detail:    map[string]string{"result": "clean"},
	}
}

func TestRecorderEnsureFileAfterDirectoryDisappearanceReopensVisibleFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "evidence")
	rec := newPersistenceTestRecorder(t, dir)
	defer func() { _ = rec.Close() }()

	if err := rec.Record(openSSFCoverageEntry("storage-loss", "before disappearance")); err != nil {
		t.Fatalf("first Record: %v", err)
	}
	firstHash := rec.prevHash

	if err := os.RemoveAll(dir); err != nil {
		t.Fatalf("RemoveAll evidence directory: %v", err)
	}
	rec.mu.Lock()
	err := rec.ensureFile("storage-loss", rec.seq)
	rec.mu.Unlock()
	if err != nil {
		t.Fatalf("ensureFile after evidence directory disappearance: %v", err)
	}
	if err := rec.Record(openSSFCoverageEntry("storage-loss", "after disappearance")); err != nil {
		t.Fatalf("Record after evidence directory disappearance: %v", err)
	}

	files, err := filepath.Glob(filepath.Join(dir, "evidence-storage-loss-*.jsonl"))
	if err != nil {
		t.Fatalf("Glob: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("visible evidence files = %v, want one reopened shard", files)
	}
	entries, err := ReadEntries(files[0])
	if err != nil {
		t.Fatalf("ReadEntries: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("visible entries = %d, want 1", len(entries))
	}
	if entries[0].Sequence != 1 {
		t.Fatalf("reopened entry sequence = %d, want 1", entries[0].Sequence)
	}
	if entries[0].PrevHash != firstHash {
		t.Fatalf("reopened entry prev_hash = %q, want lost entry hash %q", entries[0].PrevHash, firstHash)
	}
}

func TestRecorderEnsureFileRecreationFailureDoesNotAdvanceChain(t *testing.T) {
	root := t.TempDir()
	volume := filepath.Join(root, "volume")
	dir := filepath.Join(volume, "evidence")
	rec := newPersistenceTestRecorder(t, dir)
	defer func() { _ = rec.Close() }()

	if err := rec.Record(openSSFCoverageEntry("recreate-failure", "persisted")); err != nil {
		t.Fatalf("first Record: %v", err)
	}
	seqBefore := rec.seq
	hashBefore := rec.prevHash

	if err := os.RemoveAll(volume); err != nil {
		t.Fatalf("RemoveAll evidence volume: %v", err)
	}
	if err := os.Symlink(filepath.Join(root, "missing-volume"), volume); err != nil {
		t.Fatalf("replace evidence volume with dangling symlink: %v", err)
	}

	rec.mu.Lock()
	err := rec.ensureFile("recreate-failure", rec.seq)
	rec.mu.Unlock()
	if err == nil || !strings.Contains(err.Error(), "could not be recreated") {
		t.Fatalf("ensureFile error = %v, want evidence recreation failure", err)
	}
	if rec.seq != seqBefore {
		t.Fatalf("sequence advanced after failed persistence: got %d, want %d", rec.seq, seqBefore)
	}
	if rec.prevHash != hashBefore {
		t.Fatal("chain hash advanced after failed persistence")
	}
}

func TestRecorderResumeRejectsEmptyTailHashWithoutAdvancing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "evidence-empty-tail-0.jsonl")
	entry := Entry{
		Version:   EntryVersion,
		Sequence:  0,
		Timestamp: time.Unix(1712345678, 0).UTC(),
		SessionID: "empty-tail",
		Type:      "request",
		Transport: "fetch",
		Summary:   "tampered tail",
		Detail:    map[string]string{"result": "clean"},
		PrevHash:  GenesisHash,
		Hash:      "",
	}
	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), filePermissions); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	rec := newPersistenceTestRecorder(t, dir)
	defer func() { _ = rec.Close() }()

	err = rec.Record(openSSFCoverageEntry("empty-tail", "must not append"))
	if err == nil || !strings.Contains(err.Error(), "empty hash") {
		t.Fatalf("Record error = %v, want empty tail hash rejection", err)
	}
	if rec.seq != 0 || rec.sessionID != "" || rec.prevHash != GenesisHash {
		t.Fatalf("recorder state changed after rejected tail: seq=%d session=%q prev=%q", rec.seq, rec.sessionID, rec.prevHash)
	}
}

func TestQuerySessionGlobalEntryCapSkipsLaterMalformedShard(t *testing.T) {
	dir := t.TempDir()
	firstPath := filepath.Join(dir, "evidence-query-cap-0.jsonl")
	secondPath := filepath.Join(dir, "evidence-query-cap-1.jsonl")
	entry := Entry{
		Version:   EntryVersion,
		Sequence:  0,
		Timestamp: time.Unix(1712345678, 0).UTC(),
		SessionID: "query-cap",
		Type:      "request",
		Transport: "fetch",
		Summary:   "bounded result",
		Detail:    map[string]string{"result": "clean"},
		PrevHash:  GenesisHash,
		Hash:      "non-empty",
	}
	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := os.WriteFile(firstPath, append(data, '\n'), filePermissions); err != nil {
		t.Fatalf("write first shard: %v", err)
	}
	if err := os.WriteFile(secondPath, []byte("{malformed\n"), filePermissions); err != nil {
		t.Fatalf("write malformed second shard: %v", err)
	}

	result, err := QuerySession(dir, "query-cap", &QueryFilter{MaxEntriesRead: 1})
	if err != nil {
		t.Fatalf("QuerySession: %v", err)
	}
	if !result.Truncated || result.EntriesRead != 1 || result.FilesRead != 1 {
		t.Fatalf("result = %+v, want one read entry/file and truncation", result)
	}
	if len(result.Entries) != 1 || result.Entries[0].Summary != "bounded result" {
		t.Fatalf("entries = %+v, want only first bounded result", result.Entries)
	}

	if _, err := ReadEntries(secondPath); err == nil {
		t.Fatal("malformed shard unexpectedly parsed; cap test did not use a hostile later shard")
	}
}
