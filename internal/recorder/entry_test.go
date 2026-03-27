// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
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

// signedChainCheckpointInterval is the number of data entries between checkpoints
// in buildSignedChain. Fixed at 3 for test determinism.
const signedChainCheckpointInterval = 3

// buildSignedChain creates a valid hash chain with signed checkpoint entries.
// Checkpoints are inserted every signedChainCheckpointInterval data entries.
func buildSignedChain(t *testing.T, dataCount int, priv ed25519.PrivateKey) []recorder.Entry {
	t.Helper()
	ts := time.Now().UTC()
	var entries []recorder.Entry
	prevHash := recorder.GenesisHash
	seq := uint64(0)
	sinceCheckpoint := 0
	firstSeqInSpan := uint64(0)

	for i := range dataCount {
		e := recorder.Entry{
			Version:   recorder.EntryVersion,
			Sequence:  seq,
			Timestamp: ts.Add(time.Duration(seq) * time.Second),
			SessionID: "s1",
			Type:      testType,
			Transport: testTransport,
			Summary:   fmt.Sprintf("entry %d", i),
			PrevHash:  prevHash,
		}
		e.Hash = recorder.ComputeHash(e)
		prevHash = e.Hash
		entries = append(entries, e)
		seq++
		sinceCheckpoint++

		if sinceCheckpoint >= signedChainCheckpointInterval {
			cpDetail := recorder.CheckpointDetail{
				EntryCount: uint64(sinceCheckpoint),
				FirstSeq:   firstSeqInSpan,
				LastSeq:    seq - 1,
			}
			if priv != nil {
				sig := ed25519.Sign(priv, []byte(prevHash))
				cpDetail.Signature = hex.EncodeToString(sig)
			}

			cp := recorder.Entry{
				Version:   recorder.EntryVersion,
				Sequence:  seq,
				Timestamp: ts.Add(time.Duration(seq) * time.Second),
				SessionID: "s1",
				Type:      testCheckpoint,
				Summary:   fmt.Sprintf("checkpoint: %d entries", sinceCheckpoint),
				Detail:    cpDetail,
				PrevHash:  prevHash,
			}
			cp.Hash = recorder.ComputeHash(cp)
			prevHash = cp.Hash
			entries = append(entries, cp)
			seq++
			sinceCheckpoint = 0
			firstSeqInSpan = seq
		}
	}
	return entries
}

func TestVerifyChain_CheckpointSignatures(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	t.Run("valid_signed_checkpoints", func(t *testing.T) {
		entries := buildSignedChain(t, 6, priv)
		if err := recorder.VerifyChain(entries, pub); err != nil {
			t.Fatalf("valid signed chain should verify: %v", err)
		}
	})

	t.Run("tampered_checkpoint_fails", func(t *testing.T) {
		entries := buildSignedChain(t, 6, priv)

		// Find a checkpoint and tamper with its summary (changes hash but
		// the checkpoint detail/signature still refers to old prevHash)
		for i, e := range entries {
			if e.Type != testCheckpoint {
				continue
			}
			// Tamper: change the PrevHash in the checkpoint then recompute
			// its hash so the chain still links, but the signature no longer
			// matches because it was signed over the original PrevHash.
			detailJSON, _ := json.Marshal(e.Detail)
			var cpDetail recorder.CheckpointDetail
			_ = json.Unmarshal(detailJSON, &cpDetail)

			// Resign with wrong data to simulate tampering
			wrongSig := ed25519.Sign(priv, []byte("tampered-data"))
			cpDetail.Signature = hex.EncodeToString(wrongSig)
			entries[i].Detail = cpDetail
			entries[i].Hash = recorder.ComputeHash(entries[i])

			// Fix chain links for subsequent entries
			for j := i + 1; j < len(entries); j++ {
				entries[j].PrevHash = entries[j-1].Hash
				entries[j].Hash = recorder.ComputeHash(entries[j])
			}
			break
		}

		err := recorder.VerifyChain(entries, pub)
		if err == nil {
			t.Fatal("tampered checkpoint should fail verification")
		}
		if !strings.Contains(err.Error(), "signature verification failed") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("missing_signature_fails", func(t *testing.T) {
		// Build chain with unsigned checkpoints
		entries := buildSignedChain(t, 3, nil)

		err := recorder.VerifyChain(entries, pub)
		if err == nil {
			t.Fatal("missing signatures should fail when pubkey provided")
		}
		if !strings.Contains(err.Error(), "missing signature") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("no_pubkey_skips_verification", func(t *testing.T) {
		// Even unsigned checkpoints pass when no pubkey is given
		entries := buildSignedChain(t, 3, nil)
		if err := recorder.VerifyChain(entries); err != nil {
			t.Fatalf("should pass without pubkey: %v", err)
		}
	})
}

func TestVerifyCheckpoints_Standalone(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	entries := buildSignedChain(t, 6, priv)
	if err := recorder.VerifyCheckpoints(entries, pub); err != nil {
		t.Fatalf("VerifyCheckpoints: %v", err)
	}
}

func TestVerifyCheckpoints_NoCheckpoints(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	// Chain with no checkpoints should pass (nothing to verify)
	entries := buildChain(t, 3)
	if err := recorder.VerifyCheckpoints(entries, pub); err != nil {
		t.Fatalf("chain with no checkpoints should pass: %v", err)
	}
}
