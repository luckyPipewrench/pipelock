// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"bytes"
	"container/heap"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/evidencename"
)

const historyTestType = "request"

// historyEntries returns count chained entries of session starting at seq.
func historyEntries(t *testing.T, session string, seq uint64, count int, summary string) []Entry {
	t.Helper()
	out := make([]Entry, 0, count)
	prev := GenesisHash
	for i := range count {
		e := Entry{
			Version: EntryVersion, Sequence: seq + uint64(i), Timestamp: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
			SessionID: session, Type: historyTestType, Transport: "fetch", Summary: summary, PrevHash: prev,
		}
		e.Hash = ComputeHash(e)
		prev = e.Hash
		out = append(out, e)
	}
	return out
}

func historyLines(t *testing.T, entries []Entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	for _, e := range entries {
		raw, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		buf.Write(raw)
		buf.WriteByte('\n')
	}
	return buf.Bytes()
}

func writeHistoryShard(t *testing.T, dir, session string, seq uint64, count int) string {
	t.Helper()
	name := fmt.Sprintf("evidence-%s-%d.jsonl", session, seq)
	if err := os.WriteFile(filepath.Join(dir, name), historyLines(t, historyEntries(t, session, seq, count, "s")), 0o600); err != nil {
		t.Fatal(err)
	}
	return name
}

// writeUnrelatedEvidence fills dir with sessions, sidecars, stray files and
// directories that belong to no walked session.
func writeUnrelatedEvidence(t *testing.T, dir string, sessions int) {
	t.Helper()
	for i := range sessions {
		other := fmt.Sprintf("other-%03d", i)
		writeHistoryShard(t, dir, other, 0, 1)
		for _, name := range []string{
			"chain-link-" + other + ".json",
			RunWriterLockPrefix + other + RunWriterLockSuffix,
			"evidence-" + other + "-raw-1.raw.enc",
			"stray-" + other + ".txt",
		} {
			if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := os.WriteFile(filepath.Join(dir, anchorStateMarker), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "subdir"), 0o750); err != nil {
		t.Fatal(err)
	}
}

func collectHistory(t *testing.T, location EvidenceLocation, session string, window int) ([]Entry, error) {
	t.Helper()
	var got []Entry
	err := walkSessionHistoryEntries(location, session, window, func(e Entry) error {
		got = append(got, e)
		return nil
	})
	return got, err
}

func historyLocation(t *testing.T, dir string) EvidenceLocation {
	t.Helper()
	location, err := ResolveEvidenceLocation(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	return location
}

func TestWalkSessionHistoryNeverCountsUnrelatedFiles(t *testing.T) {
	dir := t.TempDir()
	writeUnrelatedEvidence(t, dir, 300)
	writeHistoryShard(t, dir, "mine", 0, 2)
	writeHistoryShard(t, dir, "mine", 2, 2)
	// A session whose name extends "mine" must never be folded in.
	writeHistoryShard(t, dir, "mine-evil", 9, 1)

	// Control: the bounded display reader refuses this directory, so the
	// fixture really is past its budget.
	if _, err := QuerySession(dir, "mine", nil); err != nil {
		t.Fatalf("display control: %v", err)
	}
	result, err := QuerySession(dir, "mine", nil)
	if err != nil || !result.Truncated {
		t.Fatalf("display reader should truncate a %d+ entry directory: result=%+v err=%v", 300*5, result, err)
	}

	var seqs []uint64
	if err := WalkSessionHistory(dir, "mine", func(e Entry) error {
		seqs = append(seqs, e.Sequence)
		return nil
	}); err != nil {
		t.Fatalf("WalkSessionHistory: %v", err)
	}
	if fmt.Sprint(seqs) != "[0 1 2 3]" {
		t.Fatalf("walked sequences %v, want [0 1 2 3]", seqs)
	}
	if err := WalkSessionHistory(dir, "absent", func(Entry) error { return errors.New("unexpected entry") }); err != nil {
		t.Fatalf("absent session: %v", err)
	}
}

func TestWalkSessionHistoryOrdersManyShardsInBoundedWindows(t *testing.T) {
	dir := t.TempDir()
	const shards = 300
	// Create in reverse so directory order cannot supply the chain order.
	for i := shards - 1; i >= 0; i-- {
		writeHistoryShard(t, dir, "long", uint64(i*2), 2)
	}
	writeUnrelatedEvidence(t, dir, 3)
	location := historyLocation(t, dir)
	for _, window := range []int{1, 7, shards - 1, shards, sessionHistoryWindow} {
		got, err := collectHistory(t, location, "long", window)
		if err != nil {
			t.Fatalf("window %d: %v", window, err)
		}
		if len(got) != shards*2 {
			t.Fatalf("window %d: walked %d entries, want %d", window, len(got), shards*2)
		}
		for i, e := range got {
			if e.Sequence != uint64(i) {
				t.Fatalf("window %d: entry %d has seq %d", window, i, e.Sequence)
			}
		}
	}
	// The public walk reads the same history.
	count := 0
	if err := WalkSessionHistoryResolved(location, "long", func(Entry) error { count++; return nil }); err != nil || count != shards*2 {
		t.Fatalf("WalkSessionHistoryResolved: count=%d err=%v", count, err)
	}
}

func TestWalkSessionHistoryHasNoFileBudget(t *testing.T) {
	t.Run("more entries than the display budget", func(t *testing.T) {
		dir := t.TempDir()
		writeHistoryShard(t, dir, "wide", 0, MaxEvidenceReadEntries+5)
		result, err := QuerySession(dir, "wide", nil)
		if err != nil || !result.Truncated {
			t.Fatalf("display control: result truncated=%v err=%v", result != nil && result.Truncated, err)
		}
		got, err := collectHistory(t, historyLocation(t, dir), "wide", sessionHistoryWindow)
		if err != nil || len(got) != MaxEvidenceReadEntries+5 {
			t.Fatalf("walked %d entries, err=%v", len(got), err)
		}
	})
	t.Run("more bytes than the display budget", func(t *testing.T) {
		dir := t.TempDir()
		summary := strings.Repeat("x", 512<<10)
		count := int(MaxEvidenceReadFileBytes/(512<<10)) + 2
		name := filepath.Join(dir, "evidence-heavy-0.jsonl")
		if err := os.WriteFile(name, historyLines(t, historyEntries(t, "heavy", 0, count, summary)), 0o600); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(name)
		if err != nil || info.Size() <= MaxEvidenceReadFileBytes {
			t.Fatalf("fixture is not past the byte budget: %v %v", info, err)
		}
		got, err := collectHistory(t, historyLocation(t, dir), "heavy", sessionHistoryWindow)
		if err != nil || len(got) != count {
			t.Fatalf("walked %d of %d entries, err=%v", len(got), count, err)
		}
	})
	t.Run("the per-entry line limit still applies", func(t *testing.T) {
		dir := t.TempDir()
		long := historyEntries(t, "lines", 0, 1, strings.Repeat("y", MaxEntryLineBytes))
		if err := os.WriteFile(filepath.Join(dir, "evidence-lines-0.jsonl"), historyLines(t, long), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := collectHistory(t, historyLocation(t, dir), "lines", sessionHistoryWindow); err == nil || !strings.Contains(err.Error(), "recorder entry limit") {
			t.Fatalf("over-long line error = %v", err)
		}
		unterminated := bytes.Repeat([]byte("z"), MaxEntryLineBytes+8)
		if err := os.WriteFile(filepath.Join(dir, "evidence-lines-0.jsonl"), unterminated, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := collectHistory(t, historyLocation(t, dir), "lines", sessionHistoryWindow); err == nil || !strings.Contains(err.Error(), "recorder entry limit") {
			t.Fatalf("over-long fragment error = %v", err)
		}
	})
}

func TestWalkSessionHistoryRefusesAmbiguousShards(t *testing.T) {
	for _, tc := range []struct {
		name   string
		names  []string
		window int
	}{
		{"same window", []string{"evidence-dup-0.jsonl", "evidence-dup-5.jsonl", "evidence-dup-05.jsonl"}, sessionHistoryWindow},
		{"across windows", []string{"evidence-dup-0.jsonl", "evidence-dup-5.jsonl", "evidence-dup-05.jsonl"}, 2},
		{"non-numeric ties", []string{"evidence-dup-x.jsonl", "evidence-dup-y.jsonl"}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for _, name := range tc.names {
				if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := collectHistory(t, historyLocation(t, dir), "dup", tc.window); !errors.Is(err, evidencename.ErrAmbiguousSeqStart) {
				t.Fatalf("error = %v, want ErrAmbiguousSeqStart", err)
			}
		})
	}
}

func TestWalkSessionHistoryTornTails(t *testing.T) {
	appendTorn := func(t *testing.T, path string) {
		t.Helper()
		f, err := os.OpenFile(filepath.Clean(path), os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteString(`{"v":3`); err != nil {
			_ = f.Close()
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("final shard", func(t *testing.T) {
		dir := t.TempDir()
		writeHistoryShard(t, dir, "torn", 0, 2)
		last := writeHistoryShard(t, dir, "torn", 2, 2)
		appendTorn(t, filepath.Join(dir, last))
		got, err := collectHistory(t, historyLocation(t, dir), "torn", 1)
		if !errors.Is(err, ErrTornTail) {
			t.Fatalf("error = %v, want ErrTornTail", err)
		}
		if len(got) != 4 {
			t.Fatalf("delivered %d complete entries before the torn write, want 4", len(got))
		}
	})
	for _, window := range []int{1, sessionHistoryWindow} {
		t.Run(fmt.Sprintf("non-final shard window %d", window), func(t *testing.T) {
			dir := t.TempDir()
			first := writeHistoryShard(t, dir, "torn", 0, 2)
			writeHistoryShard(t, dir, "torn", 2, 2)
			appendTorn(t, filepath.Join(dir, first))
			_, err := collectHistory(t, historyLocation(t, dir), "torn", window)
			if err == nil || errors.Is(err, ErrTornTail) || !strings.Contains(err.Error(), "torn segment") {
				t.Fatalf("error = %v, want a torn-segment refusal that is not recoverable", err)
			}
		})
	}
}

func TestWalkSessionHistoryFailsClosed(t *testing.T) {
	t.Run("foreign entry", func(t *testing.T) {
		dir := t.TempDir()
		raw := historyLines(t, historyEntries(t, "intruder", 0, 1, "s"))
		if err := os.WriteFile(filepath.Join(dir, "evidence-victim-0.jsonl"), raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := collectHistory(t, historyLocation(t, dir), "victim", 4); !errors.Is(err, ErrEvidenceRefused) {
			t.Fatalf("error = %v, want ErrEvidenceRefused", err)
		}
	})
	t.Run("malformed entry", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "evidence-bad-0.jsonl"), []byte("{not json}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := collectHistory(t, historyLocation(t, dir), "bad", 4); err == nil || !strings.Contains(err.Error(), "parsing entry") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("unsupported version", func(t *testing.T) {
		dir := t.TempDir()
		es := historyEntries(t, "old", 0, 1, "s")
		es[0].Version = 99
		if err := os.WriteFile(filepath.Join(dir, "evidence-old-0.jsonl"), historyLines(t, es), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := collectHistory(t, historyLocation(t, dir), "old", 4); err == nil || !strings.Contains(err.Error(), "unsupported entry version") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("schema violation", func(t *testing.T) {
		dir := t.TempDir()
		es := historyEntries(t, "schema", 0, 1, "bad\x00summary")
		if err := os.WriteFile(filepath.Join(dir, "evidence-schema-0.jsonl"), historyLines(t, es), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := collectHistory(t, historyLocation(t, dir), "schema", 4); err == nil {
			t.Fatal("schema violation accepted")
		}
	})
	t.Run("symlinked shard", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(t.TempDir(), "elsewhere.jsonl")
		if err := os.WriteFile(target, historyLines(t, historyEntries(t, "link", 0, 1, "s")), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(dir, "evidence-link-0.jsonl")); err != nil {
			t.Skipf("symlink unsupported: %v", err)
		}
		if _, err := collectHistory(t, EvidenceLocation{Root: dir, Dir: dir}, "link", 4); err == nil {
			t.Fatal("symlinked shard accepted")
		}
	})
	t.Run("directory named as a shard", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Mkdir(filepath.Join(dir, "evidence-dirshard-0.jsonl"), 0o750); err != nil {
			t.Fatal(err)
		}
		if _, err := collectHistory(t, historyLocation(t, dir), "dirshard", 4); err == nil {
			t.Fatal("directory shard accepted")
		}
	})
	t.Run("missing directory", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "gone")
		if err := WalkSessionHistory(missing, "s", func(Entry) error { return nil }); err == nil {
			t.Fatal("missing directory accepted")
		}
		location := EvidenceLocation{Root: missing, Dir: missing}
		if _, err := collectHistory(t, location, "s", 4); err == nil || !strings.Contains(err.Error(), "reading evidence directory") {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestWalkSessionHistoryInterruptedReads(t *testing.T) {
	t.Run("consumer error stops the walk", func(t *testing.T) {
		dir := t.TempDir()
		for i := range 5 {
			writeHistoryShard(t, dir, "stop", uint64(i), 1)
		}
		stop := errors.New("stop here")
		seen := 0
		err := walkSessionHistoryEntries(historyLocation(t, dir), "stop", 2, func(Entry) error {
			seen++
			if seen == 3 {
				return stop
			}
			return nil
		})
		if !errors.Is(err, stop) || seen != 3 {
			t.Fatalf("err=%v seen=%d, want the consumer error after 3 entries", err, seen)
		}
	})
	t.Run("file changed while read", func(t *testing.T) {
		dir := t.TempDir()
		name := writeHistoryShard(t, dir, "changing", 0, 2)
		path := filepath.Join(dir, name)
		changed := false
		err := WalkSessionHistory(dir, "changing", func(Entry) error {
			if changed {
				return nil
			}
			changed = true
			f, err := os.OpenFile(filepath.Clean(path), os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				return err
			}
			defer func() { _ = f.Close() }()
			_, err = f.Write(historyLines(t, historyEntries(t, "changing", 2, 1, "s")))
			return err
		})
		if err == nil || !strings.Contains(err.Error(), "changed during read") {
			t.Fatalf("error = %v, want a changed-file refusal", err)
		}
	})
	t.Run("shard removed between windows", func(t *testing.T) {
		dir := t.TempDir()
		writeHistoryShard(t, dir, "vanish", 0, 1)
		second := writeHistoryShard(t, dir, "vanish", 1, 1)
		writeHistoryShard(t, dir, "vanish", 2, 1)
		removed := false
		err := walkSessionHistoryEntries(historyLocation(t, dir), "vanish", 2, func(Entry) error {
			if removed {
				return nil
			}
			removed = true
			return os.Remove(filepath.Join(dir, second))
		})
		if err == nil || !strings.Contains(err.Error(), second) {
			t.Fatalf("error = %v, want the vanished shard named", err)
		}
	})
}

func TestWalkSessionHistoryRefusesBadArguments(t *testing.T) {
	dir := t.TempDir()
	location := historyLocation(t, dir)
	for _, session := range []string{"", ".", "..", "a/b", `a\b`, "bad\xff"} {
		if err := WalkSessionHistoryResolved(location, session, func(Entry) error { return nil }); err == nil {
			t.Errorf("session %q accepted", session)
		}
	}
	if err := WalkSessionHistoryResolved(location, "s", nil); err == nil {
		t.Error("nil entry consumer accepted")
	}
	if err := WalkSessionHistoryFiles(location, "s", nil); err == nil {
		t.Error("nil shard consumer accepted")
	}
	if err := walkSessionHistoryShards(location, "s", 0, func(SessionHistoryShard) error { return nil }); err == nil {
		t.Error("zero window accepted")
	}
	if err := WalkHistoryEntriesFromReader(strings.NewReader(""), nil); err == nil {
		t.Error("nil reader consumer accepted")
	}
}

func TestWalkSessionHistoryFiles(t *testing.T) {
	dir := t.TempDir()
	writeUnrelatedEvidence(t, dir, 300)
	var want [][]byte
	for i := range 3 {
		name := writeHistoryShard(t, dir, "files", uint64(i*3), 3)
		raw, err := os.ReadFile(filepath.Clean(filepath.Join(dir, name)))
		if err != nil {
			t.Fatal(err)
		}
		want = append(want, raw)
	}
	var got [][]byte
	var finals []bool
	err := WalkSessionHistoryFiles(historyLocation(t, dir), "files", func(shard SessionHistoryShard, r io.Reader) error {
		raw, err := io.ReadAll(r)
		got = append(got, raw)
		finals = append(finals, shard.Final)
		return err
	})
	if err != nil {
		t.Fatalf("WalkSessionHistoryFiles: %v", err)
	}
	if len(got) != 3 || fmt.Sprint(finals) != "[false false true]" {
		t.Fatalf("shards=%d finals=%v", len(got), finals)
	}
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Fatalf("shard %d bytes differ", i)
		}
	}
	stop := errors.New("stop")
	if err := WalkSessionHistoryFiles(historyLocation(t, dir), "files", func(SessionHistoryShard, io.Reader) error { return stop }); !errors.Is(err, stop) {
		t.Fatalf("consumer error = %v", err)
	}
	if err := WalkSessionHistoryFiles(historyLocation(t, dir), "files", func(shard SessionHistoryShard, _ io.Reader) error {
		return os.WriteFile(filepath.Join(dir, shard.Name), []byte("changed\n"), 0o600)
	}); err == nil || !strings.Contains(err.Error(), "changed during read") {
		t.Fatalf("changed shard error = %v", err)
	}
	if err := os.Remove(filepath.Join(dir, "evidence-files-0.jsonl")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "evidence-files-3.jsonl"), filepath.Join(dir, "evidence-files-0.jsonl")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if err := WalkSessionHistoryFiles(EvidenceLocation{Root: dir, Dir: dir}, "files", func(SessionHistoryShard, io.Reader) error { return nil }); err == nil {
		t.Fatal("symlinked shard accepted")
	}
}

func TestHistoryHelpersErrorPaths(t *testing.T) {
	h := historyMaxHeap{}
	heap.Push(&h, historyKey{name: "b", seq: 2})
	heap.Push(&h, historyKey{name: "a", seq: 1})
	if got := heap.Pop(&h).(historyKey); got.seq != 2 {
		t.Fatalf("max-heap popped %+v, want the greatest key", got)
	}

	dir := t.TempDir()
	bad := filepath.Join(dir, "evidence-bad-0.jsonl")
	if err := os.WriteFile(bad, []byte("{bad}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadHistoryEntries(bad); err == nil || !strings.Contains(err.Error(), "reading evidence file") {
		t.Fatalf("ReadHistoryEntries malformed error = %v", err)
	}
	if _, err := WalkEvidenceFile(filepath.Join(dir, "missing.jsonl"), nil, func(Entry) error { return nil }); err == nil {
		t.Fatal("WalkEvidenceFile accepted a missing file")
	}
	if _, err := WalkEvidenceFile(bad, nil, func(Entry) error { return nil }); err == nil {
		t.Fatal("WalkEvidenceFile accepted a malformed file")
	}
}

func TestPerFileHistoryReadersHaveNoBudget(t *testing.T) {
	dir := t.TempDir()
	name := writeHistoryShard(t, dir, "file", 0, MaxEvidenceReadEntries+3)
	path := filepath.Join(dir, name)
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	// Control: the default per-file reader refuses this valid file.
	if _, err := ReadEntries(path); !errors.Is(err, ErrEvidenceReadLimitExceeded) {
		t.Fatalf("display control error = %v", err)
	}

	entries, err := ReadHistoryEntries(path)
	if err != nil || len(entries) != MaxEvidenceReadEntries+3 {
		t.Fatalf("ReadHistoryEntries: %d entries, err=%v", len(entries), err)
	}
	if _, err := ReadHistoryEntries(filepath.Join(dir, "missing.jsonl")); err == nil {
		t.Fatal("missing file accepted")
	}
	entries, err = ReadHistoryEntriesFromReader(bytes.NewReader(raw))
	if err != nil || len(entries) != MaxEvidenceReadEntries+3 {
		t.Fatalf("ReadHistoryEntriesFromReader: %d entries, err=%v", len(entries), err)
	}
	if _, err := ReadHistoryEntriesFromReader(strings.NewReader("{bad}\n")); err == nil {
		t.Fatal("malformed reader accepted")
	}

	var tee bytes.Buffer
	count := 0
	if _, err := WalkEvidenceFile(path, &tee, func(Entry) error { count++; return nil }); err != nil || count != MaxEvidenceReadEntries+3 {
		t.Fatalf("WalkEvidenceFile: count=%d err=%v", count, err)
	}
	if !bytes.Equal(tee.Bytes(), raw) {
		t.Fatal("WalkEvidenceFile raw copy differs from the file")
	}

	torn := filepath.Join(dir, "evidence-torn-0.jsonl")
	if err := os.WriteFile(torn, append(historyLines(t, historyEntries(t, "torn", 0, 1, "s")), []byte(`{"v"`)...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := WalkEvidenceFile(torn, nil, func(Entry) error { return nil }); !errors.Is(err, ErrTornTail) {
		t.Fatalf("torn WalkEvidenceFile error = %v", err)
	}
	f, err := os.Open(filepath.Clean(torn))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if err := WalkHistoryEntriesFromReader(f, func(Entry) error { return nil }); !errors.Is(err, ErrTornTail) {
		t.Fatalf("torn reader error = %v", err)
	}
}
