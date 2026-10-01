// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package anchor

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func TestLocalLogTornTailRecovery(t *testing.T) {
	for _, tc := range []struct {
		name          string
		tail          []byte
		removeNewline bool
	}{
		{name: "nul", tail: []byte{0, 0, 0}},
		{name: "truncated", tail: []byte(`{"version":`)},
		{name: "missing-newline", removeNewline: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "anchor.jsonl")
			log := LocalLog{Path: path}
			cp := Checkpoint{SessionID: "test-session", RootHash: strings.Repeat("a", 64)}
			if _, err := log.Submit(cp); err != nil {
				t.Fatal(err)
			}
			original, err := os.ReadFile(filepath.Clean(path))
			if err != nil {
				t.Fatal(err)
			}
			damaged := append(bytes.Clone(original), tc.tail...)
			if tc.removeNewline {
				damaged = damaged[:len(damaged)-1]
			}
			if err := os.WriteFile(path, damaged, 0o600); err != nil {
				t.Fatal(err)
			}
			before := sha256.Sum256(damaged)
			entries, err := ReadLocalLog(path)
			if !errors.Is(err, recorder.ErrTornTail) {
				t.Fatalf("want torn tail, got %v", err)
			}
			if tc.removeNewline && len(entries) != 0 {
				t.Fatal("unterminated entry accepted as complete")
			}
			proofs := make([]Proof, 0, 2)
			for range 2 {
				reconstructed := LocalLog{Path: path}
				proof, err := reconstructed.Submit(cp)
				if err != nil {
					t.Fatal(err)
				}
				proofs = append(proofs, proof)
			}
			for _, proof := range proofs {
				if err := log.Verify(proof, cp); err != nil {
					t.Fatal(err)
				}
			}
			after, err := os.ReadFile(filepath.Clean(path))
			if err != nil {
				t.Fatal(err)
			}
			if sha256.Sum256(after) != before {
				t.Fatal("damaged log bytes changed")
			}
			files, err := filepath.Glob(path + ".segment-*")
			if err != nil || len(files) != 1 {
				t.Fatalf("segments %v, err %v", files, err)
			}
			if _, err := ReadLocalLog(path); !errors.Is(err, recorder.ErrTornTail) {
				t.Fatalf("original damage hidden: %v", err)
			}
		})
	}
}

func TestLocalLogTamperBeforeTornFailsClosed(t *testing.T) {
	for _, name := range []string{"garbage", "hash", "missing-newline-hash"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "anchor.jsonl")
			log := LocalLog{Path: path}
			cp := Checkpoint{SessionID: "test-session", RootHash: strings.Repeat("a", 64)}
			if _, err := log.Submit(cp); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(filepath.Clean(path))
			if err != nil {
				t.Fatal(err)
			}
			if name == "garbage" {
				data = append([]byte("garbage\n"), data...)
			} else {
				var entry LocalLogEntry
				if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
					t.Fatal(err)
				}
				entry.Hash = strings.Repeat("b", 64)
				data, err = json.Marshal(entry)
				if err != nil {
					t.Fatal(err)
				}
				if name != "missing-newline-hash" {
					data = append(data, '\n')
				}
			}
			if name != "missing-newline-hash" {
				data = append(data, 0, 0)
			}
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			before := sha256.Sum256(data)
			if _, err := log.Submit(cp); err == nil || errors.Is(err, recorder.ErrTornTail) {
				t.Fatalf("tamper must fail closed, got %v", err)
			}
			after, err := os.ReadFile(filepath.Clean(path))
			if err != nil {
				t.Fatal(err)
			}
			if sha256.Sum256(after) != before {
				t.Fatal("tampered file changed")
			}
			segments, err := filepath.Glob(path + ".segment-*")
			if err != nil || len(segments) != 0 {
				t.Fatalf("tamper produced segment: %v %v", segments, err)
			}
		})
	}
}

func TestLocalLogEmptyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "anchor.jsonl")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	log := LocalLog{Path: path}
	cp := Checkpoint{SessionID: "test-session"}
	proof, err := log.Submit(cp)
	if err != nil {
		t.Fatal(err)
	}
	if proof.LogIndex != 0 {
		t.Fatalf("index %d", proof.LogIndex)
	}
	if err := log.Verify(proof, cp); err != nil {
		t.Fatal(err)
	}
}

func TestLocalLogSyncFailure(t *testing.T) {
	log := LocalLog{Path: filepath.Join(t.TempDir(), "anchor.jsonl")}
	syncErr := errors.New("injected sync failure")
	proof, err := log.submitWithSync(Checkpoint{SessionID: "test-session"}, func(*os.File) error { return syncErr })
	if !errors.Is(err, syncErr) {
		t.Fatalf("want sync failure, got %v", err)
	}
	if proof.EntryHash != "" {
		t.Fatal("returned proof before durable write")
	}
}

func TestLocalLogSegmentSequenceFailsClosed(t *testing.T) {
	for _, name := range []string{"missing-base", "segment-gap", "bad-name"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "anchor.jsonl")
			log := LocalLog{Path: path}
			cp := Checkpoint{SessionID: "test-session"}
			if name != "missing-base" {
				if _, err := log.Submit(cp); err != nil {
					t.Fatal(err)
				}
			}
			suffix := ".segment-00000000000000000002"
			if name == "missing-base" {
				suffix = ".segment-00000000000000000001"
			}
			if name == "bad-name" {
				suffix = ".segment-invalid"
			}
			if err := os.WriteFile(path+suffix, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := log.Submit(cp); err == nil {
				t.Fatal("invalid segment sequence accepted")
			}
		})
	}
}

func TestLocalLogRepeatedSegmentRecovery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "anchor[one].jsonl")
	log := LocalLog{Path: path}
	cp := Checkpoint{SessionID: "test-session"}
	var proofs []Proof
	damagedPaths := []string{path, path + ".segment-00000000000000000001"}
	for _, damagedPath := range damagedPaths {
		proof, err := log.Submit(cp)
		if err != nil {
			t.Fatal(err)
		}
		proofs = append(proofs, proof)
		f, err := os.OpenFile(filepath.Clean(damagedPath), os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write([]byte{0, 0}); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	proof, err := log.Submit(cp)
	if err != nil {
		t.Fatal(err)
	}
	proofs = append(proofs, proof)
	for _, proof := range proofs {
		if err := log.Verify(proof, cp); err != nil {
			t.Fatal(err)
		}
	}
	if proofs[2].LogIndex != 2 {
		t.Fatalf("index %d", proofs[2].LogIndex)
	}
}
