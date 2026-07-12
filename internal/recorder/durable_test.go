// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type durableTestObserver struct {
	mu      sync.Mutex
	entries []Entry
	seen    chan Entry
}

func newDurableTestObserver() *durableTestObserver {
	return &durableTestObserver{seen: make(chan Entry, 16)}
}

func (o *durableTestObserver) ObserveRecorderEntry(e Entry) {
	o.mu.Lock()
	o.entries = append(o.entries, e)
	o.mu.Unlock()
	o.seen <- e
}

func (o *durableTestObserver) count() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.entries)
}

func newDurableTestRecorder(t *testing.T, cfg Config) *Recorder {
	t.Helper()
	if cfg.Dir == "" {
		cfg.Dir = t.TempDir()
	}
	cfg.Enabled = true
	if cfg.CheckpointInterval == 0 {
		cfg.CheckpointInterval = 1000
	}
	rec, err := New(cfg, nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return rec
}

func waitForDone[T any](t *testing.T, ch <-chan T, label string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-timeAfterTest():
		t.Fatalf("timed out waiting for %s", label)
		var zero T
		return zero
	}
}

func timeAfterTest() <-chan time.Time {
	return time.After(5 * time.Second)
}

func TestRecordDurable_WaitsForSyncBeforeSuccessAndObserver(t *testing.T) {
	rec := newDurableTestRecorder(t, Config{})
	defer func() { _ = rec.Close() }()

	syncEntered := make(chan struct{})
	releaseSync := make(chan struct{})
	var once sync.Once
	rec.SetObserver(newDurableTestObserver())
	rec.SetSyncForTest(func(*os.File) error {
		once.Do(func() { close(syncEntered) })
		<-releaseSync
		return nil
	})

	done := make(chan error, 1)
	go func() {
		done <- rec.RecordDurable(Entry{
			SessionID: "durable-session",
			Type:      "request",
			Summary:   "durable wait",
		})
	}()

	waitForDone(t, syncEntered, "sync entry")
	select {
	case err := <-done:
		t.Fatalf("RecordDurable returned before sync release: %v", err)
	default:
	}
	if got := rec.observer.(*durableTestObserver).count(); got != 0 {
		t.Fatalf("observer fired before sync success: got %d entries", got)
	}

	close(releaseSync)
	if err := waitForDone(t, done, "RecordDurable completion"); err != nil {
		t.Fatalf("RecordDurable: %v", err)
	}
	if got := rec.observer.(*durableTestObserver).count(); got != 1 {
		t.Fatalf("observer count after durable success = %d, want 1", got)
	}
}

func TestRecordDurable_SyncFailureDoesNotRollBackChainState(t *testing.T) {
	dir := t.TempDir()
	rec := newDurableTestRecorder(t, Config{Dir: dir})
	defer func() { _ = rec.Close() }()

	syncErr := errors.New("injected sync failure")
	var calls int
	rec.SetSyncForTest(func(*os.File) error {
		calls++
		if calls == 1 {
			return syncErr
		}
		return nil
	})

	err := rec.RecordDurable(Entry{
		SessionID: "durable-session",
		Type:      "request",
		Summary:   "first fails sync",
	})
	if !errors.Is(err, ErrDurability) {
		t.Fatalf("RecordDurable first error = %v, want ErrDurability", err)
	}
	if !errors.Is(err, syncErr) {
		t.Fatalf("RecordDurable first error = %v, want injected sync error", err)
	}
	if err := rec.RecordDurable(Entry{
		SessionID: "durable-session",
		Type:      "request",
		Summary:   "second succeeds",
	}); err != nil {
		t.Fatalf("RecordDurable second: %v", err)
	}

	entries := readEntriesForSession(t, dir, "durable-session")
	if len(entries) < 2 {
		t.Fatalf("entries = %d, want at least 2", len(entries))
	}
	if entries[0].Sequence != 0 || entries[1].Sequence != 1 {
		t.Fatalf("sequences after sync failure = %d,%d; rollback would have duplicated seq 0", entries[0].Sequence, entries[1].Sequence)
	}
	if entries[1].PrevHash != entries[0].Hash {
		t.Fatalf("second PrevHash = %q, want first hash %q", entries[1].PrevHash, entries[0].Hash)
	}
}

func TestRecordDurable_BatchSyncCoversJoinedFollowers(t *testing.T) {
	dir := t.TempDir()
	rec := newDurableTestRecorder(t, Config{Dir: dir, CheckpointInterval: 1000, MaxEntriesPerFile: 1000})
	defer func() { _ = rec.Close() }()

	var (
		hookErr  error
		syncSeqs []uint64
		diskSeqs = make(map[uint64]bool)
	)
	rec.SetSyncForTest(func(f *os.File) error {
		rec.mu.Lock()
		defer rec.mu.Unlock()

		if rec.durableBatch == nil || !rec.durableBatch.syncing {
			hookErr = errors.New("sync hook ran without an active syncing batch")
			return hookErr
		}
		for _, entry := range rec.durableBatch.entries {
			syncSeqs = append(syncSeqs, entry.seq)
		}
		entries, err := ReadEntries(f.Name())
		if err != nil {
			hookErr = fmt.Errorf("read entries during sync: %w", err)
			return hookErr
		}
		for _, entry := range entries {
			diskSeqs[entry.Sequence] = true
		}
		return nil
	})

	leader, leaderWritten := reserveDurableEntryForTest(t, rec, "leader")
	follower, followerWritten := reserveDurableEntryForTest(t, rec, "follower")
	if !leader.leader {
		t.Fatal("first reservation was not the batch leader")
	}
	if follower.leader {
		t.Fatal("second reservation unexpectedly became a new batch leader")
	}
	if leader.batch != follower.batch {
		t.Fatal("follower did not join the leader batch")
	}

	rec.runDurabilitySync(leader.batch)
	if err := rec.waitDurability(leader.batch, leader.batch.generation, leaderWritten.Sequence); err != nil {
		t.Fatalf("leader waitDurability: %v", err)
	}
	if err := rec.waitDurability(follower.batch, follower.batch.generation, followerWritten.Sequence); err != nil {
		t.Fatalf("follower waitDurability: %v", err)
	}
	if hookErr != nil {
		t.Fatalf("sync hook: %v", hookErr)
	}

	wantSeqs := []uint64{leaderWritten.Sequence, followerWritten.Sequence}
	if fmt.Sprint(syncSeqs) != fmt.Sprint(wantSeqs) {
		t.Fatalf("batch seqs at sync = %v, want %v", syncSeqs, wantSeqs)
	}
	for _, seq := range wantSeqs {
		if !diskSeqs[seq] {
			t.Fatalf("seq %d was in the durable batch but not readable from disk at sync time", seq)
		}
	}
}

func TestRecordDurable_BatchSyncFailurePropagatesToFollowersAndKeepsGap(t *testing.T) {
	dir := t.TempDir()
	rec := newDurableTestRecorder(t, Config{Dir: dir, CheckpointInterval: 1000, MaxEntriesPerFile: 1000})
	defer func() { _ = rec.Close() }()

	syncErr := errors.New("injected sync failure")
	var calls int
	rec.SetSyncForTest(func(*os.File) error {
		calls++
		if calls == 1 {
			return syncErr
		}
		return nil
	})

	leader, leaderWritten := reserveDurableEntryForTest(t, rec, "leader fails")
	follower, followerWritten := reserveDurableEntryForTest(t, rec, "follower fails")
	if leader.batch != follower.batch {
		t.Fatal("follower did not join the leader batch")
	}

	rec.runDurabilitySync(leader.batch)
	if got := rec.FsyncErrorsGated(); got != 1 {
		t.Fatalf("FsyncErrorsGated after one failed batch = %d, want 1", got)
	}
	for _, tt := range []struct {
		name       string
		batch      *durableBatch
		generation uint64
		seq        uint64
	}{
		{name: "leader", batch: leader.batch, generation: leader.batch.generation, seq: leaderWritten.Sequence},
		{name: "follower", batch: follower.batch, generation: follower.batch.generation, seq: followerWritten.Sequence},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := rec.waitDurability(tt.batch, tt.generation, tt.seq)
			if !errors.Is(err, ErrDurability) {
				t.Fatalf("waitDurability error = %v, want ErrDurability", err)
			}
			if !errors.Is(err, syncErr) {
				t.Fatalf("waitDurability error = %v, want injected sync error", err)
			}
		})
	}

	if err := rec.RecordDurable(Entry{
		SessionID: "durable-session",
		Type:      "request",
		Summary:   "later succeeds",
	}); err != nil {
		t.Fatalf("later RecordDurable: %v", err)
	}

	entries := readEntriesForSession(t, dir, "durable-session")
	if len(entries) < 3 {
		t.Fatalf("entries = %d, want at least 3", len(entries))
	}
	for i := range 3 {
		if entries[i].Sequence != uint64(i) {
			t.Fatalf("entry %d sequence = %d, want %d", i, entries[i].Sequence, i)
		}
	}
	if entries[2].PrevHash != entries[1].Hash {
		t.Fatalf("later PrevHash = %q, want failed follower hash %q", entries[2].PrevHash, entries[1].Hash)
	}
	if got := rec.FsyncErrorsGated(); got != 1 {
		t.Fatalf("FsyncErrorsGated after later success = %d, want 1", got)
	}
}

func TestRecorder_FsyncErrorsGatedNilAndNop(t *testing.T) {
	t.Parallel()

	var nilRecorder *Recorder
	if got := nilRecorder.FsyncErrorsGated(); got != 0 {
		t.Fatalf("nil FsyncErrorsGated = %d, want 0", got)
	}
	nop, err := New(Config{Enabled: false}, nil, nil)
	if err != nil {
		t.Fatalf("New nop: %v", err)
	}
	if got := nop.FsyncErrorsGated(); got != 0 {
		t.Fatalf("nop FsyncErrorsGated = %d, want 0", got)
	}
}

func TestRecordDurable_SyncPanicReturnsDurabilityErrorAndDoesNotPoisonRecorder(t *testing.T) {
	rec := newDurableTestRecorder(t, Config{})
	defer func() { _ = rec.Close() }()

	rec.SetSyncForTest(func(*os.File) error {
		panic("injected sync panic")
	})
	done := make(chan error, 1)
	go func() {
		done <- rec.RecordDurable(Entry{
			SessionID: "durable-session",
			Type:      "request",
			Summary:   "panic becomes durability error",
		})
	}()

	err := waitForDone(t, done, "RecordDurable panic recovery")
	if !errors.Is(err, ErrDurability) {
		t.Fatalf("RecordDurable error = %v, want ErrDurability", err)
	}
	if !strings.Contains(err.Error(), "injected sync panic") {
		t.Fatalf("RecordDurable error = %v, want injected panic detail", err)
	}

	rec.SetSyncForTest(nil)
	if err := rec.RecordDurable(Entry{
		SessionID: "durable-session",
		Type:      "request",
		Summary:   "recorder still usable",
	}); err != nil {
		t.Fatalf("RecordDurable after panic: %v", err)
	}
}

func TestRecordDurable_ConcurrentReservationsKeepUniqueValidChain(t *testing.T) {
	dir := t.TempDir()
	rec := newDurableTestRecorder(t, Config{Dir: dir, CheckpointInterval: 1000, MaxEntriesPerFile: 1000})

	const goroutines = 32
	errs := make(chan error, goroutines)
	var wg sync.WaitGroup
	for i := range goroutines {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			errs <- rec.RecordDurable(Entry{
				SessionID: "durable-session",
				Type:      "request",
				Summary:   fmt.Sprintf("entry %d", id),
			})
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("RecordDurable concurrent error: %v", err)
		}
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	entries := readEntriesForSession(t, dir, "durable-session")
	dataEntries := make([]Entry, 0, len(entries))
	for _, e := range entries {
		if e.Type == "request" {
			dataEntries = append(dataEntries, e)
		}
	}
	if len(dataEntries) != goroutines {
		t.Fatalf("data entries = %d, want %d", len(dataEntries), goroutines)
	}
	prev := GenesisHash
	for i, e := range dataEntries {
		if e.Sequence != uint64(i) {
			t.Fatalf("entry %d sequence = %d, want %d", i, e.Sequence, i)
		}
		if e.PrevHash != prev {
			t.Fatalf("entry %d PrevHash = %q, want %q", i, e.PrevHash, prev)
		}
		prev = e.Hash
	}
}

type shortWriteSink struct{}

func (shortWriteSink) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return len(p) - 1, nil
}

func TestWriteEntryData_ReturnsShortWrite(t *testing.T) {
	rec := &Recorder{writer: bufio.NewWriterSize(shortWriteSink{}, 1)}
	entry := Entry{
		Version:   EntryVersion,
		Sequence:  0,
		SessionID: "durable-session",
		Type:      "request",
		Summary:   "short write",
		PrevHash:  GenesisHash,
	}
	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	err = rec.writeEntryData(data, entry, false)
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("writeEntryData error = %v, want io.ErrShortWrite", err)
	}
}

func TestRecordDurable_RotationWaitsForPendingSync(t *testing.T) {
	rec := newDurableTestRecorder(t, Config{MaxEntriesPerFile: 1, CheckpointInterval: 1000})
	defer func() { _ = rec.Close() }()

	observer := newDurableTestObserver()
	rec.SetObserver(observer)
	syncEntered := make(chan struct{})
	releaseSync := make(chan struct{})
	var once sync.Once
	rec.SetSyncForTest(func(*os.File) error {
		once.Do(func() { close(syncEntered) })
		<-releaseSync
		return nil
	})

	durableDone := make(chan error, 1)
	go func() {
		durableDone <- rec.RecordDurable(Entry{
			SessionID: "durable-session",
			Type:      "request",
			Summary:   "durable pending",
		})
	}()
	waitForDone(t, syncEntered, "durable sync entry")

	recordDone := make(chan error, 1)
	go func() {
		recordDone <- rec.Record(Entry{
			SessionID: "durable-session",
			Type:      "request",
			Summary:   "rotation waits",
		})
	}()
	observed := waitForDone(t, observer.seen, "non-durable observer")
	if observed.Summary != "rotation waits" {
		t.Fatalf("observed summary = %q, want rotation waits", observed.Summary)
	}
	select {
	case err := <-recordDone:
		t.Fatalf("Record completed before durable sync released: %v", err)
	default:
	}

	close(releaseSync)
	if err := waitForDone(t, durableDone, "durable completion"); err != nil {
		t.Fatalf("RecordDurable: %v", err)
	}
	if err := waitForDone(t, recordDone, "record completion"); err != nil {
		t.Fatalf("Record: %v", err)
	}
}

func readEntriesForSession(t *testing.T, dir, sessionID string) []Entry {
	t.Helper()
	path := filepath.Join(filepath.Clean(dir), fmt.Sprintf("evidence-%s-0.jsonl", sessionID))
	entries, err := ReadEntries(path)
	if err != nil {
		t.Fatalf("ReadEntries(%q): %v", path, err)
	}
	return entries
}

func reserveDurableEntryForTest(t *testing.T, rec *Recorder, summary string) (durableReservation, Entry) {
	t.Helper()

	rec.mu.Lock()
	defer rec.mu.Unlock()

	written, err := rec.prepareAndWriteEntryLocked(Entry{
		SessionID: "durable-session",
		Type:      "request",
		Summary:   summary,
	}, false)
	if err != nil {
		t.Fatalf("prepareAndWriteEntryLocked(%q): %v", summary, err)
	}
	rec.prevHash = written.Hash
	rec.seq++
	rec.sinceCheckpoint++
	rec.fileEntryCount++

	return rec.enqueueDurabilityLocked(rec.fileGeneration, written.Sequence, rec.lastEntryOffsetLocked(written)), written
}
