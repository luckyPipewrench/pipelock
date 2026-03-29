// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func writeTestEntries(t *testing.T, dir string, sessionID string, count int) {
	t.Helper()
	cfg := recorder.Config{
		Enabled:            true,
		Dir:                dir,
		Redact:             false,
		CheckpointInterval: 1000, // High to avoid auto-checkpoints
	}
	rec, err := recorder.New(cfg, nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for i := range count {
		transport := testTransport
		entryType := testType
		if i%2 == 1 {
			transport = "mcp-stdio"
			entryType = "tool_call"
		}
		if err := rec.Record(recorder.Entry{
			SessionID: sessionID,
			Type:      entryType,
			Transport: transport,
			Summary:   fmt.Sprintf("entry %d", i),
		}); err != nil {
			t.Fatalf("Record(%d): %v", i, err)
		}
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestQuerySession_NoFilter(t *testing.T) {
	dir := t.TempDir()
	writeTestEntries(t, dir, "sess-1", 5)

	result, err := recorder.QuerySession(dir, "sess-1", nil)
	if err != nil {
		t.Fatalf("QuerySession: %v", err)
	}
	// 5 data entries + 1 final checkpoint
	if len(result.Entries) < 5 {
		t.Errorf("expected at least 5 entries, got %d", len(result.Entries))
	}
	if result.TotalFiles != 1 {
		t.Errorf("TotalFiles = %d, want 1", result.TotalFiles)
	}
	if result.FilesRead != 1 {
		t.Errorf("FilesRead = %d, want 1", result.FilesRead)
	}
}

func TestQuerySession_FilterByType(t *testing.T) {
	dir := t.TempDir()
	writeTestEntries(t, dir, "sess-1", 6)

	filter := &recorder.QueryFilter{Type: "request"}
	result, err := recorder.QuerySession(dir, "sess-1", filter)
	if err != nil {
		t.Fatalf("QuerySession: %v", err)
	}
	// Entries 0, 2, 4 are requests (even indices)
	if len(result.Entries) != 3 {
		t.Errorf("expected 3 request entries, got %d", len(result.Entries))
	}
	for _, e := range result.Entries {
		if e.Type != "request" {
			t.Errorf("unexpected type %q in filtered results", e.Type)
		}
	}
}

func TestQuerySession_FilterByTransport(t *testing.T) {
	dir := t.TempDir()
	writeTestEntries(t, dir, "sess-1", 6)

	filter := &recorder.QueryFilter{Transport: "mcp-stdio"}
	result, err := recorder.QuerySession(dir, "sess-1", filter)
	if err != nil {
		t.Fatalf("QuerySession: %v", err)
	}
	// Entries 1, 3, 5 are mcp-stdio (odd indices)
	if len(result.Entries) != 3 {
		t.Errorf("expected 3 mcp-stdio entries, got %d", len(result.Entries))
	}
}

func TestQuerySession_FilterByTimeRange(t *testing.T) {
	dir := t.TempDir()
	writeTestEntries(t, dir, "sess-1", 3)

	// All entries should be after epoch
	filter := &recorder.QueryFilter{
		After: time.Unix(0, 0),
	}
	result, err := recorder.QuerySession(dir, "sess-1", filter)
	if err != nil {
		t.Fatalf("QuerySession: %v", err)
	}
	if len(result.Entries) < 3 {
		t.Errorf("expected at least 3 entries after epoch, got %d", len(result.Entries))
	}

	// No entries should be in the far future
	filter = &recorder.QueryFilter{
		After: time.Now().Add(24 * time.Hour),
	}
	result, err = recorder.QuerySession(dir, "sess-1", filter)
	if err != nil {
		t.Fatalf("QuerySession: %v", err)
	}
	if len(result.Entries) != 0 {
		t.Errorf("expected 0 entries in the future, got %d", len(result.Entries))
	}
}

func TestQuerySession_FilterBySequenceRange(t *testing.T) {
	dir := t.TempDir()
	writeTestEntries(t, dir, "sess-1", 5)

	filter := &recorder.QueryFilter{
		MinSeq:    1,
		MaxSeq:    3,
		HasMaxSeq: true,
	}
	result, err := recorder.QuerySession(dir, "sess-1", filter)
	if err != nil {
		t.Fatalf("QuerySession: %v", err)
	}
	// Should have entries with seq 1, 2, 3
	if len(result.Entries) != 3 {
		t.Errorf("expected 3 entries in seq range [1,3], got %d", len(result.Entries))
	}
	for _, e := range result.Entries {
		if e.Sequence < 1 || e.Sequence > 3 {
			t.Errorf("entry seq %d outside range [1,3]", e.Sequence)
		}
	}
}

func TestQuerySession_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	result, err := recorder.QuerySession(dir, "nonexistent", nil)
	if err != nil {
		t.Fatalf("QuerySession: %v", err)
	}
	if len(result.Entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(result.Entries))
	}
	if result.TotalFiles != 0 {
		t.Errorf("TotalFiles = %d, want 0", result.TotalFiles)
	}
}

func TestQuerySession_NonexistentDir(t *testing.T) {
	_, err := recorder.QuerySession("/nonexistent/dir", "s1", nil)
	if err == nil {
		t.Fatal("expected error for nonexistent directory")
	}
}

func TestQuerySession_MultipleFiles(t *testing.T) {
	dir := t.TempDir()

	// Use small MaxEntriesPerFile to create multiple files
	cfg := recorder.Config{
		Enabled:            true,
		Dir:                dir,
		Redact:             false,
		CheckpointInterval: 1000,
		MaxEntriesPerFile:  2,
	}
	rec, err := recorder.New(cfg, nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for i := range 5 {
		if err := rec.Record(recorder.Entry{
			SessionID: "multi",
			Type:      testType,
			Transport: testTransport,
			Summary:   fmt.Sprintf("entry %d", i),
		}); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	result, err := recorder.QuerySession(dir, "multi", nil)
	if err != nil {
		t.Fatalf("QuerySession: %v", err)
	}
	if result.TotalFiles < 2 {
		t.Errorf("expected at least 2 files, got %d", result.TotalFiles)
	}
	if len(result.Entries) < 5 {
		t.Errorf("expected at least 5 entries across files, got %d", len(result.Entries))
	}
}

func TestListSessions(t *testing.T) {
	dir := t.TempDir()
	writeTestEntries(t, dir, "alpha", 2)
	writeTestEntries(t, dir, "beta", 2)

	sessions, err := recorder.ListSessions(dir)
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(sessions) < 2 {
		t.Fatalf("expected at least 2 sessions, got %d: %v", len(sessions), sessions)
	}

	// Sessions should be sorted
	found := map[string]bool{}
	for _, s := range sessions {
		found[s] = true
	}
	if !found["alpha"] {
		t.Error("missing session 'alpha'")
	}
	if !found["beta"] {
		t.Error("missing session 'beta'")
	}
}

func TestListSessions_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	sessions, err := recorder.ListSessions(dir)
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(sessions) != 0 {
		t.Errorf("expected 0 sessions, got %d", len(sessions))
	}
}

func TestListSessions_NonexistentDir(t *testing.T) {
	_, err := recorder.ListSessions(filepath.Join(t.TempDir(), "nonexistent"))
	if err == nil {
		t.Fatal("expected error for nonexistent directory")
	}
}

func TestListSessions_IgnoresNonEvidenceFiles(t *testing.T) {
	dir := t.TempDir()
	writeTestEntries(t, dir, "real", 1)

	// Create a non-evidence file
	nonEvidence := filepath.Join(dir, "notes.txt")
	if err := writeFile(nonEvidence, []byte("not evidence")); err != nil {
		t.Fatal(err)
	}

	sessions, err := recorder.ListSessions(dir)
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	for _, s := range sessions {
		if s == "notes" {
			t.Error("should not include non-evidence files")
		}
	}
}

func TestQuerySession_CombinedFilters(t *testing.T) {
	dir := t.TempDir()
	writeTestEntries(t, dir, "sess-1", 10)

	// Combine type + transport + sequence range
	filter := &recorder.QueryFilter{
		Type:      "request",
		Transport: "fetch",
		MinSeq:    2,
		MaxSeq:    8,
		HasMaxSeq: true,
	}
	result, err := recorder.QuerySession(dir, "sess-1", filter)
	if err != nil {
		t.Fatalf("QuerySession: %v", err)
	}
	for _, e := range result.Entries {
		if e.Type != "request" {
			t.Errorf("type = %q, want request", e.Type)
		}
		if e.Transport != "fetch" {
			t.Errorf("transport = %q, want fetch", e.Transport)
		}
		if e.Sequence < 2 || e.Sequence > 8 {
			t.Errorf("seq %d outside range [2,8]", e.Sequence)
		}
	}
}

func TestQuerySession_FilterByBeforeTime(t *testing.T) {
	dir := t.TempDir()
	writeTestEntries(t, dir, "sess-1", 3)

	// Before a time in the far past should return nothing
	filter := &recorder.QueryFilter{
		Before: time.Unix(0, 0),
	}
	result, err := recorder.QuerySession(dir, "sess-1", filter)
	if err != nil {
		t.Fatalf("QuerySession: %v", err)
	}
	if len(result.Entries) != 0 {
		t.Errorf("expected 0 entries before epoch, got %d", len(result.Entries))
	}

	// Before a time in the future should return all
	filter = &recorder.QueryFilter{
		Before: time.Now().Add(24 * time.Hour),
	}
	result, err = recorder.QuerySession(dir, "sess-1", filter)
	if err != nil {
		t.Fatalf("QuerySession: %v", err)
	}
	if len(result.Entries) < 3 {
		t.Errorf("expected at least 3 entries before tomorrow, got %d", len(result.Entries))
	}
}

func TestQuerySession_FilterBySessionID(t *testing.T) {
	dir := t.TempDir()
	writeTestEntries(t, dir, "sess-1", 3)

	// SessionID filter on QuerySession is redundant (already filtered by filename)
	// but matchesFilter still checks it
	filter := &recorder.QueryFilter{
		SessionID: "sess-1",
	}
	result, err := recorder.QuerySession(dir, "sess-1", filter)
	if err != nil {
		t.Fatalf("QuerySession: %v", err)
	}
	if len(result.Entries) < 3 {
		t.Errorf("expected at least 3 entries, got %d", len(result.Entries))
	}

	// Mismatched SessionID should return nothing
	filter = &recorder.QueryFilter{
		SessionID: "other-session",
	}
	result, err = recorder.QuerySession(dir, "sess-1", filter)
	if err != nil {
		t.Fatalf("QuerySession: %v", err)
	}
	if len(result.Entries) != 0 {
		t.Errorf("expected 0 entries for mismatched session, got %d", len(result.Entries))
	}
}

func TestQuerySession_NumericShardSort(t *testing.T) {
	dir := t.TempDir()

	// Create shard files with numbers that sort wrong lexicographically:
	// lex order: 1, 10, 2, 20  vs  numeric order: 1, 2, 10, 20
	shardNums := []int{1, 2, 10, 20}
	ts := time.Now().UTC()
	prevHash := recorder.GenesisHash
	globalSeq := uint64(0)

	for _, sn := range shardNums {
		name := fmt.Sprintf("evidence-numsort-%d.jsonl", sn)
		path := filepath.Join(dir, name)

		e := recorder.Entry{
			Version:   recorder.EntryVersion,
			Sequence:  globalSeq,
			Timestamp: ts.Add(time.Duration(globalSeq) * time.Second),
			SessionID: "numsort",
			Type:      testType,
			Transport: testTransport,
			Summary:   fmt.Sprintf("shard %d", sn),
			PrevHash:  prevHash,
		}
		e.Hash = recorder.ComputeHash(e)
		prevHash = e.Hash
		globalSeq++

		data, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		if err := writeFile(path, append(data, '\n')); err != nil {
			t.Fatal(err)
		}
	}

	result, err := recorder.QuerySession(dir, "numsort", nil)
	if err != nil {
		t.Fatalf("QuerySession: %v", err)
	}
	if result.TotalFiles != len(shardNums) {
		t.Fatalf("TotalFiles = %d, want %d", result.TotalFiles, len(shardNums))
	}

	// Entries must come back in numeric shard order (seq 0, 1, 2, 3)
	for i, e := range result.Entries {
		expectedSeq := uint64(i)
		if e.Sequence != expectedSeq {
			t.Errorf("entry %d: seq = %d, want %d (numeric order broken)", i, e.Sequence, expectedSeq)
		}
	}
}

func TestExtractSeqStart_EdgeCases(t *testing.T) {
	// extractSeqStart is unexported, so we test it indirectly via file sort order.
	// Create files with edge-case names and verify QuerySession handles them.
	dir := t.TempDir()

	// Create a file with no dash (should sort as 0)
	noDash := filepath.Join(dir, "evidence-nodash.jsonl")
	e := recorder.Entry{
		Version:   recorder.EntryVersion,
		Sequence:  0,
		SessionID: "nodash",
		Type:      testType,
		Transport: testTransport,
		PrevHash:  recorder.GenesisHash,
	}
	e.Hash = recorder.ComputeHash(e)
	data, _ := json.Marshal(e)
	if err := writeFile(noDash, append(data, '\n')); err != nil {
		t.Fatal(err)
	}

	// This file won't match the prefix "evidence-nodash-" so it won't be included
	// unless the session ID IS "nodash" (it is).
	// Actually the prefix check is "evidence-" + sessionID + "-", so "evidence-nodash.jsonl"
	// does NOT match "evidence-nodash-" prefix. Let's test what we can.

	// Test with a properly named file that has non-numeric suffix
	badNum := filepath.Join(dir, "evidence-edgetest-abc.jsonl")
	e2 := recorder.Entry{
		Version:   recorder.EntryVersion,
		Sequence:  0,
		SessionID: "edgetest",
		Type:      testType,
		Transport: testTransport,
		PrevHash:  recorder.GenesisHash,
	}
	e2.Hash = recorder.ComputeHash(e2)
	data2, _ := json.Marshal(e2)
	if err := writeFile(badNum, append(data2, '\n')); err != nil {
		t.Fatal(err)
	}

	// QuerySession should still work (extractSeqStart returns 0 for non-numeric)
	result, err := recorder.QuerySession(dir, "edgetest", nil)
	if err != nil {
		t.Fatalf("QuerySession: %v", err)
	}
	if len(result.Entries) != 1 {
		t.Errorf("expected 1 entry, got %d", len(result.Entries))
	}
}

func TestQuerySession_CorruptedFile(t *testing.T) {
	dir := t.TempDir()

	// Create a file with invalid JSON
	badFile := filepath.Join(dir, "evidence-corrupt-0.jsonl")
	if err := writeFile(badFile, []byte("not-json\n")); err != nil {
		t.Fatal(err)
	}

	_, err := recorder.QuerySession(dir, "corrupt", nil)
	if err == nil {
		t.Fatal("expected error for corrupted evidence file")
	}
}

func TestListSessions_SkipsMalformedFilenames(t *testing.T) {
	dir := t.TempDir()

	// File with no trailing dash before seq: "evidence-.jsonl"
	noSession := filepath.Join(dir, "evidence-.jsonl")
	if err := writeFile(noSession, []byte("{}\n")); err != nil {
		t.Fatal(err)
	}

	// File with just "evidence-X.jsonl" where X has no dash separator
	singlePart := filepath.Join(dir, "evidence-justname.jsonl")
	if err := writeFile(singlePart, []byte("{}\n")); err != nil {
		t.Fatal(err)
	}

	sessions, err := recorder.ListSessions(dir)
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}

	// "evidence-.jsonl" -> rest="" after trimming, lastDash=-1 -> skip
	// "evidence-justname.jsonl" -> rest="justname", lastDash=-1 -> skip
	// Both should be skipped (no sessions found)
	if len(sessions) != 0 {
		t.Errorf("expected 0 sessions from malformed files, got %d: %v", len(sessions), sessions)
	}
}

func TestQuerySession_DirectoryEntries(t *testing.T) {
	dir := t.TempDir()

	// Create a subdirectory that looks like an evidence file -- should be skipped
	subdir := filepath.Join(dir, "evidence-sess-0.jsonl")
	if err := os.MkdirAll(subdir, 0o750); err != nil {
		t.Fatal(err)
	}

	result, err := recorder.QuerySession(dir, "sess", nil)
	if err != nil {
		t.Fatalf("QuerySession: %v", err)
	}
	// No actual files, so nothing should be returned
	if result.TotalFiles != 0 {
		t.Errorf("TotalFiles = %d, want 0 (directories should be skipped by ReadDir)", result.TotalFiles)
	}
}

func writeFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}
