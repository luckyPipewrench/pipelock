// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder_test

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

const dirTestPermissions = os.FileMode(0o750)

// writeResumeShard writes one shard for session at seqStart. When empty is
// true the file is created with no entries, which is what a process that
// crashed between shard creation and its first write leaves behind.
func writeResumeShard(t *testing.T, dir, session string, seqStart uint64, empty bool) {
	t.Helper()
	path := filepath.Join(dir, fmt.Sprintf("evidence-%s-%d.jsonl", session, seqStart))
	if empty {
		if err := os.WriteFile(path, []byte(""), filePermissions); err != nil {
			t.Fatalf("WriteFile(%q): %v", path, err)
		}
		return
	}
	entry := recorder.Entry{
		Version:   recorder.EntryVersion,
		Sequence:  seqStart,
		Timestamp: time.Unix(1712345678, 0).UTC(),
		SessionID: session,
		Type:      testType,
		Transport: testTransport,
		Summary:   "resume fixture",
		Detail:    map[string]string{"safe": "value"},
		PrevHash:  recorder.GenesisHash,
		Hash:      fmt.Sprintf("tail-hash-%d", seqStart),
	}
	line, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("Marshal entry: %v", err)
	}
	if err := os.WriteFile(path, append(line, '\n'), filePermissions); err != nil {
		t.Fatalf("WriteFile(%q): %v", path, err)
	}
}

func newResumeRecorder(t *testing.T, dir string) *recorder.Recorder {
	t.Helper()
	rec, err := recorder.New(recorder.Config{
		Enabled:            true,
		Dir:                dir,
		CheckpointInterval: 100,
	}, nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	return rec
}

// A directory past MaxEvidenceReadDirectoryEntries must still emit. This is the
// live defect: two production recorder directories crossed the cap and stopped
// writing receipts permanently while enforcement kept working.
//
// Neutralization: restore the old count ceiling in sessionResumeCandidates and
// this fails with ErrEvidenceReadLimitExceeded.
func TestRecorder_ResumeSucceedsPastDirectoryCap(t *testing.T) {
	dir := t.TempDir()
	const session = "overcap"

	for i := 0; i <= recorder.MaxEvidenceReadDirectoryEntries+25; i++ {
		writeResumeShard(t, dir, session, uint64(i)*10, false)
	}

	rec := newResumeRecorder(t, dir)
	if err := rec.Record(recorder.Entry{
		SessionID: session,
		Type:      testType,
		Transport: testTransport,
		Summary:   "must write past the directory cap",
		Detail:    map[string]string{"safe": "value"},
	}); err != nil {
		t.Fatalf("Record past directory cap: %v", err)
	}
}

// Legacy releases could write shards larger than the current 8 MiB rotation
// ceiling. Upgrade resume needs only the final entry, so a valid historical
// shard above the whole-file reader cap must not disable all future receipts.
//
// Neutralization: restore the whole-file ReadEvidenceFileBounded call in
// readEntriesForResume and this fails with ErrEvidenceReadLimitExceeded.
func TestRecorder_ResumeSucceedsFromLegacyShardAboveReadCap(t *testing.T) {
	dir := t.TempDir()
	const session = "legacy-large"
	path := filepath.Join(dir, "evidence-"+session+"-0.jsonl")
	file, err := os.OpenFile(filepath.Clean(path), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, filePermissions)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	encoder := json.NewEncoder(file)
	detail := map[string]string{"padding": strings.Repeat("x", 2048)}
	var lastSeq uint64
	for seq := uint64(0); ; seq++ {
		entry := recorder.Entry{
			Version:   recorder.EntryVersion,
			Sequence:  seq,
			Timestamp: time.Unix(1712345678, 0).UTC(),
			SessionID: session,
			Type:      testType,
			Transport: testTransport,
			Summary:   "legacy oversized shard fixture",
			Detail:    detail,
			PrevHash:  fmt.Sprintf("prev-%d", seq),
			Hash:      fmt.Sprintf("hash-%d", seq),
		}
		if err := encoder.Encode(entry); err != nil {
			_ = file.Close()
			t.Fatalf("Encode seq %d: %v", seq, err)
		}
		lastSeq = seq
		if seq%128 == 0 {
			info, statErr := file.Stat()
			if statErr != nil {
				_ = file.Close()
				t.Fatalf("Stat: %v", statErr)
			}
			if info.Size() > recorder.MaxEvidenceReadFileBytes+(1<<20) {
				break
			}
		}
	}
	if err := file.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	rec := newResumeRecorder(t, dir)
	if err := rec.Record(recorder.Entry{
		SessionID: session,
		Type:      testType,
		Transport: testTransport,
		Summary:   "must resume from a legacy oversized shard",
		Detail:    map[string]string{"safe": "value"},
	}); err != nil {
		t.Fatalf("Record after legacy oversized shard: %v", err)
	}
	nextPath := filepath.Join(dir, fmt.Sprintf("evidence-%s-%d.jsonl", session, lastSeq+1))
	if _, err := os.Stat(nextPath); err != nil {
		t.Fatalf("next resumed shard %q: %v", filepath.Base(nextPath), err)
	}
}

func TestRecorder_ResumeRejectsMalformedAndOverlongTail(t *testing.T) {
	tests := []struct {
		name string
		tail []byte
	}{
		{name: "truncated json", tail: []byte(`{"v":2,"seq":9`)},
		{name: "overlong line", tail: []byte(strings.Repeat("x", recorder.MaxEntryLineBytes+1))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "evidence-bad-tail-0.jsonl")
			if err := os.WriteFile(path, tt.tail, filePermissions); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			rec := newResumeRecorder(t, dir)
			err := rec.Record(recorder.Entry{
				SessionID: "bad-tail",
				Type:      testType,
				Transport: testTransport,
				Summary:   "malformed tail must fail closed",
				Detail:    map[string]string{"safe": "value"},
			})
			if err == nil {
				t.Fatal("Record succeeded; want malformed tail refusal")
			}
		})
	}
}

// Resume must keep walking down past empty newest shards. A one-shot "highest
// few names" scan would hand resume only the empty files, fall through to
// genesis, and fork the chain from sequence 0.
//
// Neutralization: stop after the first empty candidate, or fall back to
// genesis, and this fails.
func TestRecorder_ResumeFindsTailBelowEmptyNewestShards(t *testing.T) {
	dir := t.TempDir()
	const session = "emptytop"

	writeResumeShard(t, dir, session, 42, false)
	for seq := uint64(100); seq <= 130; seq++ {
		writeResumeShard(t, dir, session, seq, true)
	}

	rec := newResumeRecorder(t, dir)
	if err := rec.Record(recorder.Entry{
		SessionID: session,
		Type:      testType,
		Transport: testTransport,
		Summary:   "must resume from the tail below the empty shards",
		Detail:    map[string]string{"safe": "value"},
	}); err != nil {
		t.Fatalf("Record: %v", err)
	}

	// The tail entry was sequence 42, so the next record must be 43. A genesis
	// fallback would have produced 0 and started a second chain root.
	entries := readAllEntriesForSession(t, dir, session)
	var maxSeq uint64
	for _, e := range entries {
		if e.Sequence > maxSeq {
			maxSeq = e.Sequence
		}
	}
	if maxSeq != 43 {
		t.Fatalf("highest sequence after resume = %d, want 43 (genesis fallback would give 0)", maxSeq)
	}
}

// Empty shards mean no chain entries were ever written. This is a legitimate
// crash-before-first-write state, so genesis is still correct.
//
// Neutralization: restore the no-resumable-tail refusal for all-empty shards and
// this fails, because Record refuses forever.
func TestRecorder_ResumeStartsAtGenesisWhenOnlyEmptyShardsExist(t *testing.T) {
	dir := t.TempDir()
	const session = "emptycrash"

	for seq := uint64(0); seq < 5; seq++ {
		writeResumeShard(t, dir, session, seq, true)
	}

	rec := newResumeRecorder(t, dir)
	if err := rec.Record(recorder.Entry{
		SessionID: session,
		Type:      testType,
		Transport: testTransport,
		Summary:   "empty shards should not brick a first write",
		Detail:    map[string]string{"safe": "value"},
	}); err != nil {
		t.Fatalf("Record with only empty shards: %v", err)
	}

	entries := readAllEntriesForSession(t, dir, session)
	if len(entries) != 1 {
		t.Fatalf("entry count after first write = %d, want 1", len(entries))
	}
	if entries[0].Sequence != 0 || entries[0].PrevHash != recorder.GenesisHash {
		t.Fatalf("first entry sequence/prevHash = %d/%q, want 0/genesis", entries[0].Sequence, entries[0].PrevHash)
	}
}

// A genuinely empty directory is the only case where genesis is correct.
func TestRecorder_ResumeStartsAtGenesisWhenNoShardsExist(t *testing.T) {
	dir := t.TempDir()
	rec := newResumeRecorder(t, dir)
	if err := rec.Record(recorder.Entry{
		SessionID: "fresh",
		Type:      testType,
		Transport: testTransport,
		Summary:   "first write of a new session",
		Detail:    map[string]string{"safe": "value"},
	}); err != nil {
		t.Fatalf("Record on empty directory: %v", err)
	}
}

// Session membership is parsed equality, not an "evidence-<session>-" prefix.
// For session "s", the file evidence-s-evil-999.jsonl satisfies the prefix but
// belongs to session "s-evil", and adopting its tail would take the chain head
// from another session.
//
// Neutralization: restore prefix matching and this fails, because the
// higher-numbered foreign shard is adopted and the next sequence becomes 1000.
func TestRecorder_ResumeIgnoresForeignSessionSharingPrefix(t *testing.T) {
	dir := t.TempDir()

	writeResumeShard(t, dir, "s", 5, false)
	writeResumeShard(t, dir, "s-evil", 999, false)

	rec := newResumeRecorder(t, dir)
	if err := rec.Record(recorder.Entry{
		SessionID: "s",
		Type:      testType,
		Transport: testTransport,
		Summary:   "must not adopt another session's shard",
		Detail:    map[string]string{"safe": "value"},
	}); err != nil {
		t.Fatalf("Record: %v", err)
	}

	entries := readAllEntriesForSession(t, dir, "s")
	var maxSeq uint64
	for _, e := range entries {
		if e.Sequence > maxSeq {
			maxSeq = e.Sequence
		}
	}
	if maxSeq != 6 {
		t.Fatalf("highest sequence for session s = %d, want 6; prefix matching would adopt s-evil and give 1000", maxSeq)
	}
}

// Two distinct names cannot legitimately share a seqStart, because the writer
// derives the name from session plus sequence. If they do, refuse rather than
// let directory order decide the chain head.
func TestRecorder_ResumeRefusesDuplicateSeqStart(t *testing.T) {
	dir := t.TempDir()

	writeResumeShard(t, dir, "dup", 7, false)
	// A second name parsing to the same session and seqStart. Trailing zeros
	// keep the numeric value identical while the basename differs.
	twin := filepath.Join(dir, "evidence-dup-007.jsonl")
	if err := os.WriteFile(twin, []byte(""), filePermissions); err != nil {
		t.Fatalf("WriteFile(%q): %v", twin, err)
	}
	for _, name := range []string{"evidence-dup-7.jsonl", "evidence-dup-007.jsonl"} {
		parsedSession, seqStart, ok := recorder.ParseEvidenceFilename(name)
		if !ok || parsedSession != "dup" || seqStart != 7 {
			t.Fatalf("ParseEvidenceFilename(%q) = (%q, %d, %v), want (dup, 7, true)", name, parsedSession, seqStart, ok)
		}
	}

	rec := newResumeRecorder(t, dir)
	err := rec.Record(recorder.Entry{
		SessionID: "dup",
		Type:      testType,
		Transport: testTransport,
		Summary:   "must refuse an ambiguous chain head",
		Detail:    map[string]string{"safe": "value"},
	})
	if err == nil {
		t.Fatal("Record succeeded; want refusal on duplicate sequence start")
	}
	if !strings.Contains(err.Error(), "sequence start") {
		t.Fatalf("Record error = %v, want a duplicate sequence-start refusal", err)
	}
}

// readAllEntriesForSession reads every entry the recorder wrote for a session,
// across shards, so a test can assert the sequence the chain actually resumed
// to rather than trusting the absence of an error.
func readAllEntriesForSession(t *testing.T, dir, session string) []recorder.Entry {
	t.Helper()
	dirEntries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	all := make([]recorder.Entry, 0)
	for _, de := range dirEntries {
		if de.IsDir() || !strings.HasSuffix(de.Name(), ".jsonl") {
			continue
		}
		parsed, _, ok := recorder.ParseEvidenceFilename(de.Name())
		if !ok || parsed != session {
			continue
		}
		data, readErr := os.ReadFile(filepath.Clean(filepath.Join(dir, de.Name())))
		if readErr != nil {
			t.Fatalf("ReadFile(%q): %v", de.Name(), readErr)
		}
		for _, line := range strings.Split(string(data), "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			var e recorder.Entry
			if err := json.Unmarshal([]byte(line), &e); err != nil {
				t.Fatalf("Unmarshal entry in %q: %v", de.Name(), err)
			}
			all = append(all, e)
		}
	}
	return all
}

// Filtering candidates by filename settles WHICH shard to read, not what is
// inside it. A shard named for this session but containing another session's
// entries must not become this chain's head; a renamed, misplaced or tampered
// file reaches exactly this path.
//
// Neutralization: drop the last.SessionID check in resumeSessionLocked and this
// fails, because the foreign tail is adopted and Record succeeds.
func TestRecorder_ResumeRefusesShardWhoseEntriesBelongToAnotherSession(t *testing.T) {
	dir := t.TempDir()

	// Named for "mine", but its entry declares "theirs".
	writeResumeShard(t, dir, "theirs", 900, false)
	if err := os.Rename(
		filepath.Join(dir, "evidence-theirs-900.jsonl"),
		filepath.Join(dir, "evidence-mine-900.jsonl"),
	); err != nil {
		t.Fatalf("Rename: %v", err)
	}

	rec := newResumeRecorder(t, dir)
	err := rec.Record(recorder.Entry{
		SessionID: "mine",
		Type:      testType,
		Transport: testTransport,
		Summary:   "must refuse a foreign chain head",
		Detail:    map[string]string{"safe": "value"},
	})
	if err == nil {
		t.Fatal("Record succeeded; want refusal because the tail entry belongs to another session")
	}
	if !strings.Contains(err.Error(), "foreign chain head") {
		t.Fatalf("Record error = %v, want a foreign-chain-head refusal", err)
	}
}

// The candidate scan has two I/O error branches. Both must surface the wrapped
// directory-read context rather than being mistaken for an empty directory,
// which would resume at genesis and fork the chain.
func TestRecorder_ResumeSurfacesDirectoryScanErrors(t *testing.T) {
	// chmod cannot make a directory unreadable on Windows, and Geteuid
	// returns -1 there so the root skip below never fires. The Windows CI job
	// filters to -run "TestWindows" so this does not execute there today, but
	// the skip keeps the test honest if that filter ever widens.
	if runtime.GOOS == "windows" {
		t.Skip("directory permissions are not enforced this way on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root can open a mode-0000 directory, so the unreadable case cannot be staged")
	}
	dir := t.TempDir()
	evidenceDir := filepath.Join(dir, "evidence")
	if err := os.Mkdir(evidenceDir, dirTestPermissions); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	writeResumeShard(t, evidenceDir, "locked", 1, false)

	rec := newResumeRecorder(t, evidenceDir)
	// Remove read permission only after the recorder exists, so the failure
	// lands on the scan rather than on construction.
	if err := os.Chmod(evidenceDir, 0o000); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	// Restore via the same mode used to create it; a bare octal literal here
	// trips the file-permission linter even though this is a directory.
	t.Cleanup(func() { _ = os.Chmod(evidenceDir, dirTestPermissions) })

	err := rec.Record(recorder.Entry{
		SessionID: "locked",
		Type:      testType,
		Transport: testTransport,
		Summary:   "unreadable directory must surface, not look empty",
		Detail:    map[string]string{"safe": "value"},
	})
	if err == nil {
		t.Fatal("Record succeeded against an unreadable evidence directory")
	}
	if !strings.Contains(err.Error(), "evidence directory") {
		t.Fatalf("Record error = %v, want the wrapped evidence-directory context", err)
	}
}

// A uint64 at its maximum wraps to zero on increment, which would restart the
// sequence and reuse numbers already present in the chain. Refuse instead.
//
// Neutralization: drop the math.MaxUint64 guard and this fails, because Record
// succeeds and writes a wrapped sequence.
func TestRecorder_ResumeRefusesExhaustedSequence(t *testing.T) {
	dir := t.TempDir()
	const session = "exhausted"
	writeResumeShard(t, dir, session, math.MaxUint64, false)

	rec := newResumeRecorder(t, dir)
	err := rec.Record(recorder.Entry{
		SessionID: session,
		Type:      testType,
		Transport: testTransport,
		Summary:   "must refuse rather than wrap the sequence to zero",
		Detail:    map[string]string{"safe": "value"},
	})
	if err == nil {
		t.Fatal("Record succeeded; want refusal on an exhausted sequence space")
	}
	if !strings.Contains(err.Error(), "sequence space exhausted") {
		t.Fatalf("Record error = %v, want a sequence-exhaustion refusal", err)
	}
}
