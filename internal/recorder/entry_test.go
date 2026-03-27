// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// buildChain creates a valid hash-chained sequence of entries.
func buildChain(t *testing.T, count int) []recorder.Entry {
	t.Helper()
	ts := time.Now().UTC()
	entries := make([]recorder.Entry, count)
	prevHash := recorder.GenesisHash
	for i := range entries {
		entries[i] = recorder.Entry{
			Version:   recorder.EntryVersion,
			Sequence:  uint64(i),
			Timestamp: ts.Add(time.Duration(i) * time.Second),
			SessionID: "s1",
			Type:      testType,
			Transport: testTransport,
			Summary:   "entry",
			PrevHash:  prevHash,
		}
		entries[i].Hash = recorder.ComputeHash(entries[i])
		prevHash = entries[i].Hash
	}
	return entries
}

func TestComputeHash_Deterministic(t *testing.T) {
	ts := time.Date(2026, 3, 27, 12, 0, 0, 0, time.UTC)
	e := recorder.Entry{
		Version:   recorder.EntryVersion,
		Sequence:  1,
		Timestamp: ts,
		SessionID: "sess-1",
		Type:      testType,
		Transport: testTransport,
		Summary:   "GET https://example.com",
		Detail:    map[string]string{"url": "https://example.com"},
		PrevHash:  recorder.GenesisHash,
	}

	h1 := recorder.ComputeHash(e)
	h2 := recorder.ComputeHash(e)
	if h1 != h2 {
		t.Fatalf("hash not deterministic: %s != %s", h1, h2)
	}

	const sha256HexLen = 64
	if len(h1) != sha256HexLen {
		t.Fatalf("unexpected hash length: %d", len(h1))
	}
}

func TestComputeHash_FieldChange(t *testing.T) {
	ts := time.Date(2026, 3, 27, 12, 0, 0, 0, time.UTC)
	base := recorder.Entry{
		Version:   recorder.EntryVersion,
		Sequence:  1,
		Timestamp: ts,
		SessionID: "sess-1",
		Type:      testType,
		Transport: testTransport,
		Summary:   "test",
		PrevHash:  recorder.GenesisHash,
	}

	baseHash := recorder.ComputeHash(base)

	// Each field change must produce a different hash
	tests := []struct {
		name   string
		modify func(e recorder.Entry) recorder.Entry
	}{
		{"version", func(e recorder.Entry) recorder.Entry { e.Version = 2; return e }},
		{"sequence", func(e recorder.Entry) recorder.Entry { e.Sequence = 2; return e }},
		{"timestamp", func(e recorder.Entry) recorder.Entry {
			e.Timestamp = ts.Add(time.Second)
			return e
		}},
		{"session_id", func(e recorder.Entry) recorder.Entry { e.SessionID = "sess-2"; return e }},
		{"trace_id", func(e recorder.Entry) recorder.Entry { e.TraceID = "trace-1"; return e }},
		{"type", func(e recorder.Entry) recorder.Entry { e.Type = "response"; return e }},
		{"transport", func(e recorder.Entry) recorder.Entry { e.Transport = "connect"; return e }},
		{"summary", func(e recorder.Entry) recorder.Entry { e.Summary = "changed"; return e }},
		{"detail", func(e recorder.Entry) recorder.Entry {
			e.Detail = map[string]string{"key": "val"}
			return e
		}},
		{"raw_ref", func(e recorder.Entry) recorder.Entry { e.RawRef = "file.enc"; return e }},
		{"prev_hash", func(e recorder.Entry) recorder.Entry { e.PrevHash = "abc123"; return e }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			modified := tt.modify(base)
			h := recorder.ComputeHash(modified)
			if h == baseHash {
				t.Errorf("changing %s did not change hash", tt.name)
			}
		})
	}
}

func TestReadEntries_ValidFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.jsonl")

	entries := []recorder.Entry{
		{
			Version: recorder.EntryVersion, Sequence: 0, SessionID: "s1",
			Timestamp: time.Now().UTC(), Type: testType, Transport: testTransport,
			Summary: "first", PrevHash: recorder.GenesisHash,
		},
	}
	entries[0].Hash = recorder.ComputeHash(entries[0])

	f, err := os.Create(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	enc := json.NewEncoder(f)
	for _, e := range entries {
		if err := enc.Encode(e); err != nil {
			t.Fatal(err)
		}
	}
	_ = f.Close()

	got, err := recorder.ReadEntries(path)
	if err != nil {
		t.Fatalf("ReadEntries: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(got))
	}
	if got[0].SessionID != "s1" {
		t.Errorf("session_id = %q, want %q", got[0].SessionID, "s1")
	}
}

func TestReadEntries_RejectsUnknownVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.jsonl")

	// Write an entry with Version=2 (unknown)
	e := recorder.Entry{
		Version: 2, Sequence: 0, SessionID: "s1",
		Timestamp: time.Now().UTC(), Type: testType, Transport: testTransport,
		Summary: "future", PrevHash: recorder.GenesisHash,
	}
	data, _ := json.Marshal(e)
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := recorder.ReadEntries(path)
	if err == nil {
		t.Fatal("expected error for unknown version, got nil")
	}
	if got := err.Error(); !strings.Contains(got, "unsupported entry version 2") {
		t.Errorf("error = %q, want mention of unsupported version", got)
	}
}

func TestReadEntries_AcceptsVersion1(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.jsonl")

	e := recorder.Entry{
		Version: 1, Sequence: 0, SessionID: "s1",
		Timestamp: time.Now().UTC(), Type: testType, Transport: testTransport,
		Summary: "current", PrevHash: recorder.GenesisHash,
	}
	e.Hash = recorder.ComputeHash(e)
	data, _ := json.Marshal(e)
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	entries, err := recorder.ReadEntries(path)
	if err != nil {
		t.Fatalf("ReadEntries: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
}

func TestReadEntries_FileNotFound(t *testing.T) {
	_, err := recorder.ReadEntries("/nonexistent/path/file.jsonl")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestReadEntries_MalformedJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.jsonl")
	if err := os.WriteFile(path, []byte("not json\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := recorder.ReadEntries(path)
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestVerifyChain_Valid(t *testing.T) {
	entries := buildChain(t, 3)
	if err := recorder.VerifyChain(entries); err != nil {
		t.Fatalf("valid chain verification failed: %v", err)
	}
}

func TestVerifyChain_TamperedHash(t *testing.T) {
	entries := buildChain(t, 2)
	entries[0].Hash = "tampered"

	err := recorder.VerifyChain(entries)
	if err == nil {
		t.Fatal("expected error for tampered chain")
	}
}

func TestVerifyChain_BrokenLink(t *testing.T) {
	entries := buildChain(t, 2)
	// Break the link by changing PrevHash of second entry
	entries[1].PrevHash = "wrong_hash"
	entries[1].Hash = recorder.ComputeHash(entries[1])

	err := recorder.VerifyChain(entries)
	if err == nil {
		t.Fatal("expected error for broken chain link")
	}
}

func TestVerifyChain_WrongGenesisStart(t *testing.T) {
	e := recorder.Entry{
		Version:   recorder.EntryVersion,
		Sequence:  0,
		Timestamp: time.Now().UTC(),
		SessionID: "s1",
		Type:      testType,
		Transport: testTransport,
		Summary:   "entry",
		PrevHash:  "not_genesis",
	}
	e.Hash = recorder.ComputeHash(e)

	err := recorder.VerifyChain([]recorder.Entry{e})
	if err == nil {
		t.Fatal("expected error for wrong genesis PrevHash")
	}
}

func TestVerifyChain_UnsupportedVersion(t *testing.T) {
	e := recorder.Entry{
		Version:   99,
		Sequence:  0,
		Timestamp: time.Now().UTC(),
		SessionID: "s1",
		Type:      testType,
		Transport: testTransport,
		PrevHash:  recorder.GenesisHash,
	}
	e.Hash = recorder.ComputeHash(e)

	err := recorder.VerifyChain([]recorder.Entry{e})
	if err == nil {
		t.Fatal("expected error for unsupported version")
	}
}

func TestVerifyChain_Empty(t *testing.T) {
	if err := recorder.VerifyChain(nil); err != nil {
		t.Fatalf("empty chain should be valid: %v", err)
	}
}
