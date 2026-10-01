// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestInspectJSONLTailClassification(t *testing.T) {
	for _, tc := range []struct {
		name, content string
		torn, bad     bool
		good          int64
	}{
		{"empty", "", false, false, 0},
		{"complete", "{}\n", false, false, 0},
		{"nul", "{}\n\x00\x00", true, false, 3},
		{"truncated", "{}\n{\"value\":", true, false, 3},
		{"missing newline", "{}\n{}", true, false, 3},
		{"nul only", "\x00\x00", true, false, 0},
		{"nul partial", "{}\n{\"value\":\x00\x00", true, false, 3},
		{"midfile garbage plus torn", "oops\n{}", false, true, 0},
		{"embedded nul plus torn", "{}\n\x00{}", false, true, 0},
		{"bad complete plus nul", "oops\n\x00", false, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "log.jsonl")
			before := []byte(tc.content)
			if err := os.WriteFile(path, before, 0o600); err != nil {
				t.Fatal(err)
			}
			err := InspectJSONLTail(path)
			if errors.Is(err, ErrTornTail) != tc.torn {
				t.Fatalf("error=%v torn want %v", err, tc.torn)
			}
			if tc.bad && err == nil {
				t.Fatal("malformed prefix accepted")
			}
			if !tc.bad && !tc.torn && err != nil {
				t.Fatal(err)
			}
			if tc.torn {
				var tail *TornTailError
				if !errors.As(err, &tail) || tail.LastGoodOffset != tc.good || tail.Path != path {
					t.Fatalf("tail = %+v", tail)
				}
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("damaged bytes changed")
			}
		})
	}
}

func TestInspectJSONLTailValidationPrecedesTorn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log.jsonl")
	sentinel := errors.New("bad signature")
	for _, content := range []string{"{}\n\x00", "{}"} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		err := InspectJSONLTailWithValidator(path, func([]byte) error { return sentinel })
		if !errors.Is(err, sentinel) || errors.Is(err, ErrTornTail) {
			t.Fatalf("error=%v", err)
		}
	}
}

func TestDirectionalReadersRejectTornTail(t *testing.T) {
	for _, suffix := range []string{"\x00\x00", "{\"type\":", "valid-json"} {
		path := filepath.Join(t.TempDir(), "evidence-directional-0.jsonl")
		writeDirectionalEntries(t, path, 1)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var entry Entry
		if err := json.Unmarshal(data, &entry); err != nil {
			t.Fatal(err)
		}
		entry.Hash = ComputeHash(entry)
		data, err = json.Marshal(entry)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
		if suffix == "valid-json" {
			entry.Sequence++
			entry.PrevHash = entry.Hash
			entry.Hash = ComputeHash(entry)
			data, err := json.Marshal(entry)
			if err != nil {
				t.Fatal(err)
			}
			suffix = string(data)
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteString(suffix); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		for _, read := range []func() error{
			func() error { _, _, err := ReadHeadEntriesBounded(path, 1, MaxEvidenceReadFileBytes); return err },
			func() error { _, _, err := ReadTailEntriesBounded(path, 1, MaxEvidenceReadFileBytes); return err },
			func() error { _, _, err := FindLastEntry(path, func(Entry) bool { return true }); return err },
		} {
			if err := read(); !errors.Is(err, ErrTornTail) {
				t.Fatalf("suffix %q: %v", suffix, err)
			}
		}
	}
}

func TestRecorderTornTailRecoveryPreservesBytes(t *testing.T) {
	rec := newTestRecorderForAcquire(t)
	session, err := AcquireRunSession(rec, "proxy")
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Record(Entry{SessionID: session, Type: "request", Summary: "complete"}); err != nil {
		t.Fatal(err)
	}
	path := rec.file.Name()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("\x00\x00"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.AcquireSession(session); !errors.Is(err, ErrTornTail) {
		t.Fatalf("reacquire=%v", err)
	}
	if err := rec.Record(Entry{SessionID: session, Type: "request"}); !errors.Is(err, ErrTornTail) {
		t.Fatalf("append=%v", err)
	}
	next, err := rec.RecoverTornRunSession("proxy")
	if err != nil {
		t.Fatal(err)
	}
	if next == session {
		t.Fatal("reused torn session")
	}
	if err := rec.Record(Entry{SessionID: session, Type: "request"}); err == nil {
		t.Fatal("old emitter accepted")
	}
	if err := rec.Record(Entry{SessionID: next, Type: "request"}); err != nil {
		t.Fatal(err)
	}
	if err := rec.AcquireSession(next); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("torn shard rewritten")
	}
	if _, err := rec.RecoverTornRunSession("proxy"); err == nil {
		t.Fatal("healthy recovery accepted")
	}
}

func TestInspectJSONLTailBoundedLineAndAccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log.jsonl")
	if err := InspectJSONLTail(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing=%v", err)
	}
	if err := os.WriteFile(path, bytes.Repeat([]byte("a"), MaxEntryLineBytes+2), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := InspectJSONLTail(path); err == nil || errors.Is(err, ErrTornTail) {
		t.Fatalf("oversized=%v", err)
	}
}

func TestEvidenceTornTailCannotMaskHashTamper(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence-directional-0.jsonl")
	writeDirectionalEntries(t, path, 1)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("\x00"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := InspectEvidenceTail(path, nil); err == nil || errors.Is(err, ErrTornTail) {
		t.Fatalf("hash tamper masked: %v", err)
	}
}
