// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// SessionWriteEnd names the file and offset a session had written up to; the
// prefix tail reader reads only bytes before that offset, so a later append
// cannot move what it returns.
func TestSessionWriteEndBoundsThePrefixTail(t *testing.T) {
	var none *Recorder
	if _, _, ok, err := none.SessionWriteEnd(""); ok || err != nil {
		t.Fatalf("nil recorder write end ok=%v err=%v", ok, err)
	}
	if none.DurabilityFailed() {
		t.Fatal("nil recorder reports a durability failure")
	}

	rec := newDurableTestRecorder(t, Config{})
	dir := rec.cfg.Dir
	if _, _, ok, err := rec.SessionWriteEnd("not-a-member"); ok || err != nil {
		t.Fatalf("unknown session write end ok=%v err=%v", ok, err)
	}
	for _, summary := range []string{"first", "second"} {
		if err := rec.Record(Entry{SessionID: durableTestSession, Type: "request", Summary: summary}); err != nil {
			t.Fatal(err)
		}
	}
	name, end, ok, err := rec.SessionWriteEnd("")
	if err != nil || !ok || name == "" || end <= 0 {
		t.Fatalf("open file write end = %q %d ok=%v err=%v", name, end, ok, err)
	}
	if err := rec.Record(Entry{SessionID: durableTestSession, Type: "request", Summary: "after the bound"}); err != nil {
		t.Fatal(err)
	}

	location := EvidenceLocation{Root: dir, Dir: dir}
	whole, truncated, err := ReadEvidenceLocationFilePrefixTail(location, name, end, end+100)
	if err != nil || truncated || int64(len(whole)) != end {
		t.Fatalf("whole prefix = %d bytes truncated=%v err=%v, want %d", len(whole), truncated, err, end)
	}
	tail, truncated, err := ReadEvidenceLocationFilePrefixTail(location, name, end, 10)
	if err != nil || !truncated || string(tail) != string(whole[end-10:]) {
		t.Fatalf("bounded prefix tail = %q truncated=%v err=%v", tail, truncated, err)
	}
	for _, bad := range []struct{ end, max int64 }{{end, 0}, {-1, 10}} {
		if _, _, err := ReadEvidenceLocationFilePrefixTail(location, name, bad.end, bad.max); err == nil {
			t.Fatalf("invalid bounds end=%d max=%d accepted", bad.end, bad.max)
		}
	}
	if _, _, err := ReadEvidenceLocationFilePrefixTail(location, name, 1<<40, 10); !errors.Is(err, ErrEvidenceFileChanged) {
		t.Fatalf("bound past the file end = %v, want ErrEvidenceFileChanged", err)
	}

	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	closedName, closedEnd, ok, err := rec.SessionWriteEnd("")
	if err != nil || !ok || closedName != name {
		t.Fatalf("closed write end = %q %d ok=%v err=%v, want the last file", closedName, closedEnd, ok, err)
	}
	info, err := os.Stat(filepath.Join(dir, name))
	if err != nil || closedEnd != info.Size() {
		t.Fatalf("closed write end %d, file size %v err=%v", closedEnd, info, err)
	}
}

// A failed sync is reported for the bound stream until a fresh run binds.
func TestDurabilityFailedReportsTheBoundStream(t *testing.T) {
	rec := newDurableTestRecorder(t, Config{})
	if rec.DurabilityFailed() {
		t.Fatal("fresh recorder reports a durability failure")
	}
	rec.SetSyncForTest(func(*os.File) error { return errors.New("injected sync failure") })
	if err := rec.RecordDurable(Entry{SessionID: durableTestSession, Type: "request", Summary: "fails"}); !errors.Is(err, ErrDurability) {
		t.Fatalf("durable record = %v, want ErrDurability", err)
	}
	if !rec.DurabilityFailed() {
		t.Fatal("failed sync not reported")
	}
}
