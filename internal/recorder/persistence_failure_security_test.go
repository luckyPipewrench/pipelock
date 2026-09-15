// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/testwait"
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

func TestRecorderFinalCheckpointOpenFailureDoesNotAdvanceChain(t *testing.T) {
	dir := t.TempDir()
	rec := newPersistenceTestRecorder(t, dir)
	t.Cleanup(func() { _ = rec.Close() })
	rec.cfg.MaxEntriesPerFile = 1
	if err := rec.Record(openSSFCoverageEntry("checkpoint-open-failure", "persisted")); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if rec.file != nil {
		t.Fatal("record did not close the full shard")
	}
	sequenceBefore := rec.seq
	hashBefore := rec.prevHash
	countBefore := rec.sinceCheckpoint
	blockedPath := filepath.Join(dir, "evidence-checkpoint-open-failure-1.jsonl")
	if err := os.Mkdir(blockedPath, 0o750); err != nil {
		t.Fatal(err)
	}
	closeErr := rec.Close()
	if closeErr == nil || !strings.Contains(closeErr.Error(), "final checkpoint") || !strings.Contains(closeErr.Error(), "opening evidence file") {
		t.Fatalf("Close = %v, want final checkpoint opening error", closeErr)
	}
	if err := os.Rename(blockedPath, blockedPath+".blocked"); err != nil {
		t.Fatal(err)
	}
	var callers sync.WaitGroup
	for range 4 {
		callers.Go(func() {
			if err := rec.Close(); !errors.Is(err, closeErr) {
				t.Errorf("repeated Close = %v, want original failure %v", err, closeErr)
			}
		})
	}
	callers.Wait()
	if err := rec.Record(openSSFCoverageEntry("checkpoint-open-failure", "after close")); err == nil || !strings.Contains(err.Error(), "recorder is closed") {
		t.Fatalf("Record after failed Close = %v, want closed recorder error", err)
	}
	if rec.ceremonyLock != nil || rec.file != nil {
		t.Fatal("failed Close retained a writer handle")
	}
	if _, err := os.Stat(blockedPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("closed recorder created a new shard: %v", err)
	}
	if rec.seq != sequenceBefore || rec.prevHash != hashBefore || rec.sinceCheckpoint != countBefore {
		t.Fatal("failed checkpoint advanced chain state")
	}
	entries, err := ReadEntries(filepath.Join(dir, "evidence-checkpoint-open-failure-0.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Hash != hashBefore {
		t.Fatal("failed checkpoint changed the persisted entry")
	}
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

func TestRecorderCloseRetainsCleanupErrors(t *testing.T) {
	for _, testCase := range []struct {
		name          string
		closeFile     bool
		closeCeremony bool
	}{
		{name: "healthy_control"},
		{name: "evidence_file", closeFile: true},
		{name: "ceremony_lock", closeCeremony: true},
		{name: "both", closeFile: true, closeCeremony: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			rec := newPersistenceTestRecorder(t, t.TempDir())
			t.Cleanup(func() { _ = rec.Close() })
			if err := rec.Record(openSSFCoverageEntry("close-result", "persisted")); err != nil {
				t.Fatal(err)
			}
			if testCase.closeFile {
				if err := rec.file.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if testCase.closeCeremony {
				if err := rec.ceremonyLock.Close(); err != nil {
					t.Fatal(err)
				}
			}
			firstErr := rec.Close()
			if testCase.closeFile || testCase.closeCeremony {
				if !errors.Is(firstErr, os.ErrClosed) {
					t.Fatalf("Close = %v, want closed-handle error", firstErr)
				}
			} else if firstErr != nil {
				t.Fatalf("healthy Close = %v", firstErr)
			}
			if secondErr := rec.Close(); !errors.Is(secondErr, firstErr) {
				t.Fatalf("repeated Close = %v, want original result %v", secondErr, firstErr)
			}
			if rec.file != nil || rec.ceremonyLock != nil || !rec.closed {
				t.Fatal("Close did not release and seal the writer")
			}
		})
	}
}

func TestRecorderClosePreservesCheckpointAndFlushErrors(t *testing.T) {
	for _, testCase := range []struct {
		name          string
		cleanupWriter io.Writer
		cleanupErr    error
	}{
		{name: "cleanup_succeeds", cleanupWriter: io.Discard},
		{name: "cleanup_fails", cleanupWriter: shortWriteSink{}, cleanupErr: io.ErrShortWrite},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			rec := newPersistenceTestRecorder(t, t.TempDir())
			t.Cleanup(func() { _ = rec.Close() })
			if err := rec.Record(openSSFCoverageEntry("close-errors", "persisted")); err != nil {
				t.Fatal(err)
			}
			sequenceBefore, hashBefore := rec.seq, rec.prevHash
			// A closed file makes the checkpoint stat fail. The buffered writer
			// independently succeeds or fails when shutdown flushes it afterward.
			if err := rec.file.Close(); err != nil {
				t.Fatal(err)
			}
			rec.writer = bufio.NewWriter(testCase.cleanupWriter)
			if _, err := rec.writer.WriteString("pending cleanup bytes"); err != nil {
				t.Fatal(err)
			}
			firstErr := rec.Close()
			if !errors.Is(firstErr, os.ErrClosed) || !strings.Contains(firstErr.Error(), "final checkpoint") {
				t.Fatalf("Close = %v, want final checkpoint error", firstErr)
			}
			if testCase.cleanupErr != nil && !errors.Is(firstErr, testCase.cleanupErr) {
				t.Errorf("Close = %v, lost independent cleanup error %v", firstErr, testCase.cleanupErr)
			}
			if secondErr := rec.Close(); !errors.Is(secondErr, firstErr) {
				t.Fatalf("repeated Close = %v, want original result %v", secondErr, firstErr)
			}
			if rec.file != nil || rec.writer != nil || rec.ceremonyLock != nil {
				t.Fatal("Close retained a writer handle")
			}
			if rec.seq != sequenceBefore || rec.prevHash != hashBefore {
				t.Fatal("failed checkpoint advanced chain state")
			}
		})
	}
}

func TestRecorderConcurrentCloseWaitsForFinalResult(t *testing.T) {
	for _, testCase := range []struct {
		name          string
		closeFile     bool
		closeCeremony bool
	}{
		{name: "healthy_control"},
		{name: "checkpoint_error", closeFile: true},
		{name: "cleanup_error", closeCeremony: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			rec := newPersistenceTestRecorder(t, t.TempDir())
			syncEntered := make(chan struct{})
			releaseSync := make(chan struct{})
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(releaseSync) }) }
			t.Cleanup(func() {
				release()
				_ = rec.Close()
			})
			rec.SetSyncForTest(func(file *os.File) error {
				err := file.Sync()
				close(syncEntered)
				<-releaseSync
				return err
			})
			recordDone := make(chan error, 1)
			go func() {
				recordDone <- rec.RecordDurable(openSSFCoverageEntry("overlapping-close", "persisted"))
			}()
			waitForDone(t, syncEntered, "durability confirmation")
			if testCase.closeFile {
				if err := rec.file.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if testCase.closeCeremony {
				if err := rec.ceremonyLock.Close(); err != nil {
					t.Fatal(err)
				}
			}
			firstDone := make(chan error, 1)
			go func() { firstDone <- rec.Close() }()
			testwait.For(t, 5*time.Second, func() bool {
				rec.mu.Lock()
				defer rec.mu.Unlock()
				return rec.closed
			}, "first Close waiting for durability")

			secondStarted := make(chan struct{})
			secondDone := make(chan error, 1)
			go func() {
				close(secondStarted)
				secondDone <- rec.Close()
			}()
			waitForDone(t, secondStarted, "overlapping Close start")
			var secondErr error
			returnedEarly := false
			select {
			case secondErr = <-secondDone:
				returnedEarly = true
				t.Errorf("overlapping Close returned before durability completed: %v", secondErr)
			case <-time.After(testwait.Deadline(25 * time.Millisecond)):
			}
			release()
			if err := waitForDone(t, recordDone, "durable record completion"); err != nil {
				t.Fatalf("RecordDurable: %v", err)
			}
			firstErr := waitForDone(t, firstDone, "first Close completion")
			if !returnedEarly {
				secondErr = waitForDone(t, secondDone, "overlapping Close completion")
			}
			if testCase.closeFile || testCase.closeCeremony {
				if !errors.Is(firstErr, os.ErrClosed) {
					t.Fatalf("Close = %v, want closed-handle error", firstErr)
				}
			} else if firstErr != nil {
				t.Fatalf("healthy Close = %v", firstErr)
			}
			if !errors.Is(secondErr, firstErr) {
				t.Fatalf("overlapping Close = %v, want completed result %v", secondErr, firstErr)
			}
			if rec.file != nil || rec.ceremonyLock != nil {
				t.Fatal("Close returned before releasing writer handles")
			}
		})
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
