// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
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
			after, err := os.ReadFile(filepath.Clean(path))
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

func TestInspectEvidenceTailBytesValidatesCompleteFinalJSON(t *testing.T) {
	rec := newTestRecorderForAcquire(t)
	if err := rec.Record(Entry{SessionID: "hash-test", Type: "request", Summary: "real producer"}); err != nil {
		t.Fatal(err)
	}
	path := rec.file.Name()
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	last := bytes.TrimSuffix(raw, []byte{'\n'})
	valid := last[bytes.LastIndexByte(last, '\n')+1:]
	var entry Entry
	if err := json.Unmarshal(valid, &entry); err != nil {
		t.Fatal(err)
	}
	entry.Hash = strings.Repeat("0", len(entry.Hash))
	badHash, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, content string
		torn, damage  bool
		validated     bool
	}{
		{"valid without LF", string(valid), true, false, true},
		{"bad hash without LF", string(badHash), false, true, false},
		{"incomplete JSON", `{"version":`, true, false, false},
		{"NUL crash fragment", "\x00", true, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			err := InspectEvidenceTailBytes(path, []byte(tc.content), func(Entry) error {
				called = true
				return nil
			})
			if errors.Is(err, ErrTornTail) != tc.torn || (err != nil && !tc.torn) != tc.damage || called != tc.validated {
				t.Fatalf("error=%v validated=%v", err, called)
			}
		})
	}
}

func TestDirectionalReadersRejectTornTail(t *testing.T) {
	for _, suffix := range []string{"\x00\x00", "{\"type\":", "valid-json"} {
		path := filepath.Join(t.TempDir(), "evidence-directional-0.jsonl")
		writeDirectionalEntries(t, path, 1)
		data, err := os.ReadFile(filepath.Clean(path))
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
		f, err := os.OpenFile(filepath.Clean(path), os.O_WRONLY|os.O_APPEND, 0o600)
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
			func() error { _, err := ReadEntries(path); return err },
			func() error {
				file, err := os.Open(filepath.Clean(path))
				if err != nil {
					return err
				}
				defer func() { _ = file.Close() }()
				_, err = ReadEntriesFromReader(file)
				return err
			},
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
	f, err := os.OpenFile(filepath.Clean(path), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("\x00\x00"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Clean(path))
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
	if got := rec.RecoveryPredecessor(); got != session {
		t.Fatalf("recovery predecessor = %q, want abandoned session %q", got, session)
	}
	rec.AcknowledgeRecovery("stale-predecessor", next)
	if got := rec.RecoveryPredecessor(); got != session {
		t.Fatalf("stale predecessor acknowledgement cleared recovery: %q", got)
	}
	rec.AcknowledgeRecovery(session, "stale-successor")
	if got := rec.RecoveryPredecessor(); got != session {
		t.Fatalf("stale successor acknowledgement cleared recovery: %q", got)
	}
	rec.AcknowledgeRecovery(session, next)
	if got := rec.RecoveryPredecessor(); got != "" {
		t.Fatalf("matching acknowledgement left recovery predecessor %q", got)
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
	after, err := os.ReadFile(filepath.Clean(path))
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

func TestRecorderRecoveryRejectsTornEarlierSegment(t *testing.T) {
	dir := t.TempDir()
	rec, err := New(Config{Enabled: true, Dir: dir, MaxEntriesPerFile: 1, CheckpointInterval: 100}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rec.Close() }()
	session, err := AcquireRunSession(rec, "proxy")
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := rec.Record(Entry{SessionID: session, Type: "request"}); err != nil {
			t.Fatal(err)
		}
	}
	files, err := rec.sessionResumeCandidates(session)
	if err != nil || len(files) < 2 {
		t.Fatalf("writer did not rotate: %v %v", files, err)
	}
	older := files[len(files)-1].path
	f, err := os.OpenFile(older, os.O_APPEND|os.O_WRONLY, 0o600) // #nosec G304 -- path belongs to this test's recorder.
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"partial":`); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := rec.RecoverTornRunSession("proxy"); err == nil || errors.Is(err, ErrTornTail) || !strings.Contains(err.Error(), "torn segment") {
		t.Fatalf("non-final recovery error = %v", err)
	}
	if rec.sessionID != session || rec.RecoveryPredecessor() != "" {
		t.Fatal("non-final damage changed recorder session")
	}
}

func TestRecorderTornTailCannotEscapeBySizeRotation(t *testing.T) {
	rec := newTestRecorderForAcquire(t)
	defer func() { _ = rec.Close() }()
	session, err := AcquireRunSession(rec, "proxy")
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Record(Entry{SessionID: session, Type: "request"}); err != nil {
		t.Fatal(err)
	}
	path := rec.file.Name()
	// A sparse NUL tail fills the shard to its rotation boundary.
	if err := os.Truncate(filepath.Clean(path), MaxEvidenceReadFileBytes); err != nil {
		t.Fatal(err)
	}
	if err := rec.Record(Entry{SessionID: session, Type: "request"}); !errors.Is(err, ErrTornTail) {
		t.Fatalf("rotation bypassed torn tail: %v", err)
	}
	files, err := filepath.Glob(filepath.Join(rec.Dir(), "evidence-*.jsonl"))
	if err != nil || len(files) != 1 {
		t.Fatalf("files=%v err=%v", files, err)
	}
	info, err := os.Stat(filepath.Clean(path))
	if err != nil || info.Size() != MaxEvidenceReadFileBytes {
		t.Fatalf("damaged shard changed: info=%v err=%v", info, err)
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
	for _, tc := range []struct{ name, suffix string }{
		{"complete", "\n"},
		{"complete with NUL", "\n\x00\x00"},
		{"unterminated", ""},
		{"unterminated with NUL", "\x00\x00"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := newTestRecorderForAcquire(t)
			if err := rec.Record(Entry{SessionID: "hash-test", Type: "request", Summary: "real producer"}); err != nil {
				t.Fatal(err)
			}
			path := rec.file.Name()
			if err := rec.Close(); err != nil {
				t.Fatal(err)
			}
			if err := ValidateEvidenceFile(path, nil); err != nil {
				t.Fatalf("positive control: %v", err)
			}
			entries, err := ReadEntries(path)
			if err != nil || len(entries) == 0 {
				t.Fatalf("entries=%v err=%v", entries, err)
			}
			entry := entries[0]
			if entry.Version == 0 || entry.Hash != ComputeHash(entry) {
				t.Fatal("fixture is not real hashed evidence")
			}
			flipped := byte('0')
			if entry.Hash[0] == flipped {
				flipped = '1'
			}
			entry.Hash = string(flipped) + entry.Hash[1:]
			data, err := json.Marshal(entry)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, append(data, []byte(tc.suffix)...), 0o600); err != nil {
				t.Fatal(err)
			}
			err = ValidateEvidenceFile(path, nil)
			if err == nil || errors.Is(err, ErrTornTail) || !strings.Contains(err.Error(), "hash mismatch") {
				t.Fatalf("want hash TAMPER, got %v", err)
			}
			if tc.suffix != "\n" {
				if err := InspectEvidenceTail(path, nil); err == nil || errors.Is(err, ErrTornTail) || !strings.Contains(err.Error(), "hash mismatch") {
					t.Fatalf("tail inspection masked hash TAMPER: %v", err)
				}
			}
		})
	}
}

func TestBadHashUnterminatedTailRefusesRecoveryAndReload(t *testing.T) {
	rec := newTestRecorderForAcquire(t)
	session, err := AcquireRunSession(rec, "proxy")
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Record(Entry{SessionID: session, Type: "request", Summary: "real producer"}); err != nil {
		t.Fatal(err)
	}
	path := rec.file.Name()
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	last := bytes.TrimSuffix(raw, []byte{'\n'})
	boundary := bytes.LastIndexByte(last, '\n') + 1
	var entry Entry
	if err := json.Unmarshal(last[boundary:], &entry); err != nil {
		t.Fatal(err)
	}
	entry.Hash = strings.Repeat("0", len(entry.Hash))
	damaged, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	damaged = append(bytes.Clone(raw[:boundary]), damaged...)
	reloaded, err := New(Config{Enabled: true, Dir: rec.Dir(), CheckpointInterval: 100}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := reloaded.AcquireSession(session); err != nil {
		t.Fatalf("positive control reload: %v", err)
	}
	if err := os.WriteFile(path, damaged, 0o600); err != nil {
		t.Fatal(err)
	}
	for name, check := range map[string]func() error{
		"reacquire": func() error { return reloaded.AcquireSession(session) },
		"recover": func() error {
			_, err := reloaded.RecoverTornRunSession("proxy")
			return err
		},
		"capture for seal": func() error {
			_, err := CaptureTornEvidence(path, MaxEvidenceReadFileBytes, nil, nil)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := check(); err == nil || errors.Is(err, ErrTornTail) || !strings.Contains(err.Error(), "hash mismatch") {
				t.Fatalf("damage classified as recoverable: %v", err)
			}
		})
	}
	_ = reloaded.Close()
	reloaded, err = New(Config{Enabled: true, Dir: rec.Dir(), CheckpointInterval: 100}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reloaded.Close() }()
	if err := reloaded.AcquireSession(session); err == nil || errors.Is(err, ErrTornTail) || !strings.Contains(err.Error(), "hash mismatch") {
		t.Fatalf("reload classified damage as recoverable: %v", err)
	}
	after, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, damaged) {
		t.Fatal("recovery or reload changed damaged evidence")
	}
}

func TestRecorderAppendLocksBoundedAcrossRunsAndRotations(t *testing.T) {
	dir := t.TempDir()
	const runs = 12
	for range runs {
		rec, err := New(Config{Enabled: true, Dir: dir, MaxEntriesPerFile: 2, CheckpointInterval: 100}, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		session, err := AcquireRunSession(rec, "proxy")
		if err != nil {
			_ = rec.Close()
			t.Fatal(err)
		}
		for range 3 {
			if err := rec.Record(Entry{SessionID: session, Type: "request"}); err != nil {
				_ = rec.Close()
				t.Fatal(err)
			}
		}
		if err := rec.Close(); err != nil {
			t.Fatal(err)
		}
	}
	shards, err := filepath.Glob(filepath.Join(dir, "evidence-*.jsonl"))
	if err != nil || len(shards) <= runs {
		t.Fatalf("rotation not exercised: shards=%d err=%v", len(shards), err)
	}
	locks, err := filepath.Glob(filepath.Join(dir, ".append*.lock"))
	if err != nil || len(locks) != 1 {
		t.Fatalf("append lock files grow with runs: count=%d err=%v", len(locks), err)
	}
}
