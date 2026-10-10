// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const durableTestSession = "durable-session"

func appendTestTicket(t *testing.T, rec *Recorder, summary string) *DurableTicket {
	t.Helper()
	ticket, err := rec.AppendDurableWithReceiptScanPreAdvance(Entry{SessionID: durableTestSession, Type: "request", Summary: summary}, nil, nil)
	if err != nil {
		t.Fatalf("append %q: %v", summary, err)
	}
	return ticket
}

// The append returns once the bytes are written; only Wait observes the sync.
func TestAppendDurableReturnsBeforeSyncAndWaitConfirms(t *testing.T) {
	rec := newDurableTestRecorder(t, Config{})
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

	ticket := appendTestTicket(t, rec, "deferred")
	waited := make(chan error, 1)
	go func() { waited <- ticket.Wait() }()
	waitForDone(t, syncEntered, "sync entry")
	select {
	case err := <-waited:
		t.Fatalf("Wait returned before the sync completed: %v", err)
	default:
	}
	if observer.count() != 0 {
		t.Fatal("observer saw an entry before its sync completed")
	}
	close(releaseSync)
	if err := waitForDone(t, waited, "ticket wait"); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if observer.count() != 1 {
		t.Fatalf("observer count = %d, want 1", observer.count())
	}
	if err := ticket.Wait(); err != nil {
		t.Fatalf("second Wait = %v, want the first result", err)
	}
}

// Tickets confirmed out of order still finish (observer, maintenance) in
// append order.
func TestDurableTicketsFinishInAppendOrder(t *testing.T) {
	rec := newDurableTestRecorder(t, Config{})
	defer func() { _ = rec.Close() }()
	observer := newDurableTestObserver()
	rec.SetObserver(observer)
	gate := make(chan struct{})
	rec.SetSyncForTest(func(*os.File) error { <-gate; return nil })

	const n = 6
	tickets := make([]*DurableTicket, n)
	for i := range tickets {
		tickets[i] = appendTestTicket(t, rec, fmt.Sprintf("entry-%d", i))
	}
	var wg sync.WaitGroup
	for i := n - 1; i >= 0; i-- {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := tickets[i].Wait(); err != nil {
				t.Errorf("ticket %d: %v", i, err)
			}
		}(i)
	}
	close(gate)
	wg.Wait()
	observer.mu.Lock()
	defer observer.mu.Unlock()
	if len(observer.entries) != n {
		t.Fatalf("observed %d entries, want %d", len(observer.entries), n)
	}
	for i, e := range observer.entries {
		if e.Summary != fmt.Sprintf("entry-%d", i) {
			t.Fatalf("observer entry %d = %q, want entry-%d", i, e.Summary, i)
		}
	}
}

// A batch appended before an earlier batch's failure is known is failed as
// inherited: it is never synced, is not counted as a storage failure, and does
// not report ErrDurability.
func TestDurableBatchAfterFailureIsInheritedAndNotSynced(t *testing.T) {
	rec := newDurableTestRecorder(t, Config{})
	defer func() { _ = rec.Close() }()
	syncErr := errors.New("injected sync failure")
	var calls atomic.Int32
	firstEntered := make(chan struct{})
	releaseFirst := make(chan struct{})
	rec.SetSyncForTest(func(*os.File) error {
		if calls.Add(1) == 1 {
			close(firstEntered)
			<-releaseFirst
			return syncErr
		}
		return nil
	})

	first := appendTestTicket(t, rec, "fails")
	firstDone := make(chan error, 1)
	go func() { firstDone <- first.Wait() }()
	waitForDone(t, firstEntered, "first sync")
	// The first batch is syncing, so this append opens a second batch.
	second := appendTestTicket(t, rec, "behind the failure")
	close(releaseFirst)

	if err := waitForDone(t, firstDone, "first wait"); !errors.Is(err, ErrDurability) {
		t.Fatalf("first = %v, want ErrDurability", err)
	}
	err := second.Wait()
	if !errors.Is(err, ErrDurabilityInherited) || errors.Is(err, ErrDurability) {
		t.Fatalf("second = %v, want ErrDurabilityInherited and not ErrDurability", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("sync calls = %d, want 1; an inherited batch must not be synced", got)
	}
	if got := rec.FsyncErrorsGated(); got != 1 {
		t.Fatalf("FsyncErrorsGated = %d, want 1", got)
	}
}

func TestCloseRefusesCheckpointAfterSyncFailure(t *testing.T) {
	dir := t.TempDir()
	rec := newDurableTestRecorder(t, Config{Dir: dir})
	rec.SetSyncForTest(func(*os.File) error { return errors.New("injected sync failure") })
	if err := rec.RecordDurable(Entry{SessionID: "durable-session", Type: "request", Summary: "fails"}); !errors.Is(err, ErrDurability) {
		t.Fatalf("RecordDurable = %v, want ErrDurability", err)
	}
	if err := rec.Close(); !errors.Is(err, ErrDurabilityInherited) {
		t.Fatalf("Close = %v, want a refusal naming the earlier failure", err)
	}
	for _, e := range readEntriesForSession(t, dir, "durable-session") {
		if e.Type == checkpointType {
			t.Fatalf("close wrote a checkpoint over a failed sync: %+v", e)
		}
	}
}

// Close waits for an outstanding ticket's post-record step (checkpoint,
// rotation, observer), not only its sync, and refuses appends while it waits.
// Without the drain Close would seal the file between a ticket's confirmation
// and its maintenance, and that maintenance would then fail on a closed file.
func TestCloseDrainsOutstandingTicket(t *testing.T) {
	rec := newDurableTestRecorder(t, Config{CheckpointInterval: 1})
	ticket := appendTestTicket(t, rec, "outstanding")

	confirmed := make(chan struct{})
	release := make(chan struct{})
	restore := afterDurableConfirm
	afterDurableConfirm = func() { close(confirmed); <-release }
	t.Cleanup(func() { afterDurableConfirm = restore })
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })

	waited := make(chan error, 1)
	go func() { waited <- ticket.Wait() }()
	waitForDone(t, confirmed, "ticket confirmation")

	closed := make(chan error, 1)
	go func() { closed <- rec.Close() }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		rec.mu.Lock()
		isClosed := rec.closed
		rec.mu.Unlock()
		if isClosed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Close did not refuse new appends while draining")
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := rec.AppendDurableWithReceiptScanPreAdvance(Entry{SessionID: "durable-session", Type: "request", Summary: "late"}, nil, nil); err == nil {
		t.Fatal("append during close drain succeeded")
	}
	select {
	case err := <-closed:
		t.Fatalf("Close returned before the outstanding ticket finished: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	releaseOnce.Do(func() { close(release) })
	if err := waitForDone(t, waited, "ticket"); err != nil {
		t.Fatalf("ticket after drain: %v", err)
	}
	if err := waitForDone(t, closed, "close"); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// A failed sync on one shard fails only that shard's stream, and finalizing
// the group then refuses to seal it as complete.
func TestGroupShardSyncFailureIsShardLocalAndBlocksFinalize(t *testing.T) {
	r, _, _ := newGroupRecorder(t)
	sessions := groupSessionIDs(t, 2)
	if err := r.AcquireGroupSessions(sessions); err != nil {
		t.Fatal(err)
	}
	// The failure target is fixed before any append: the first reservation
	// starts its sync at once, so it can run before the append returns.
	r.SetSyncForTest(func(f *os.File) error {
		if strings.Contains(filepath.Base(f.Name()), sessions[1]) {
			return errors.New("injected shard sync failure")
		}
		return f.Sync()
	})
	if err := r.RecordDurable(Entry{SessionID: sessions[0], Type: "test", Summary: "shard 0 ok"}); err != nil {
		t.Fatal(err)
	}
	ticket, err := r.AppendDurableWithReceiptScanPreAdvance(Entry{SessionID: sessions[1], Type: "test", Summary: "shard 1 fails"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ticket.Wait(); !errors.Is(err, ErrDurability) {
		t.Fatalf("shard 1 = %v, want ErrDurability", err)
	}
	if err := r.RecordDurable(Entry{SessionID: sessions[0], Type: "test", Summary: "shard 0 still ok"}); err != nil {
		t.Fatalf("healthy shard after another shard failed: %v", err)
	}
	if err := r.RecordDurable(Entry{SessionID: sessions[1], Type: "test", Summary: "shard 1 refused"}); !errors.Is(err, ErrDurabilityInherited) {
		t.Fatalf("failed shard append = %v, want ErrDurabilityInherited", err)
	}
	if err := r.FinalizeGroupSessions(); !errors.Is(err, ErrDurabilityInherited) {
		t.Fatalf("FinalizeGroupSessions = %v, want refusal for the failed shard", err)
	}
}

// Single-run recovery refuses a receipt group before touching any of its
// state: a standalone run would not be a member the group can write.
func TestRecoverTornRunSessionRefusesGroups(t *testing.T) {
	r, _, _ := newGroupRecorder(t)
	sessions := groupSessionIDs(t, 2)
	if err := r.AcquireGroupSessions(sessions); err != nil {
		t.Fatal(err)
	}
	r.SetSyncForTest(func(*os.File) error { return errors.New("injected sync failure") })
	if err := r.RecordDurable(Entry{SessionID: sessions[0], Type: "test", Summary: "fails"}); !errors.Is(err, ErrDurability) {
		t.Fatalf("shard sync = %v, want ErrDurability", err)
	}
	r.SetSyncForTest(nil)
	before := r.SessionID()
	if _, err := r.RecoverTornRunSession("proxy"); err == nil {
		t.Fatal("single-run recovery accepted a receipt group")
	}
	if r.SessionID() != before {
		t.Fatalf("refused recovery moved the recorder from %q to %q", before, r.SessionID())
	}
}

// A failed stream refuses non-durable writes too, and no path signs a
// checkpoint over it: neither the maintenance a later write would trigger nor
// a non-finalizing group close.
func TestFailedStreamRefusesEveryWriteAndCheckpoint(t *testing.T) {
	t.Run("single session", func(t *testing.T) {
		dir := t.TempDir()
		rec := newDurableTestRecorder(t, Config{Dir: dir, CheckpointInterval: 2})
		rec.SetSyncForTest(func(*os.File) error { return errors.New("injected sync failure") })
		if err := rec.RecordDurable(Entry{SessionID: "durable-session", Type: "request", Summary: "fails"}); !errors.Is(err, ErrDurability) {
			t.Fatalf("RecordDurable = %v, want ErrDurability", err)
		}
		if err := rec.Record(Entry{SessionID: "durable-session", Type: "request", Summary: "best effort"}); !errors.Is(err, ErrDurabilityInherited) {
			t.Fatalf("non-durable Record on a failed stream = %v, want ErrDurabilityInherited", err)
		}
		_ = rec.Close()
		for _, e := range readEntriesForSession(t, dir, "durable-session") {
			if e.Type == checkpointType {
				t.Fatalf("a checkpoint was signed over a failed sync: %+v", e)
			}
			if e.Summary == "best effort" {
				t.Fatal("a non-durable entry was appended to a failed stream")
			}
		}
	})
	t.Run("group close", func(t *testing.T) {
		r, _, _ := newGroupRecorder(t)
		sessions := groupSessionIDs(t, 2)
		if err := r.AcquireGroupSessions(sessions); err != nil {
			t.Fatal(err)
		}
		r.SetSyncForTest(func(*os.File) error { return errors.New("injected sync failure") })
		if err := r.RecordDurable(Entry{SessionID: sessions[1], Type: "test", Summary: "fails"}); !errors.Is(err, ErrDurability) {
			t.Fatalf("shard sync = %v, want ErrDurability", err)
		}
		r.SetSyncForTest(nil)
		if err := r.Close(); !errors.Is(err, ErrDurabilityInherited) {
			t.Fatalf("group Close = %v, want the failed shard's checkpoint refused", err)
		}
		entries, err := ReadEntries(filepath.Join(r.cfg.Dir, fmt.Sprintf("evidence-%s-0.jsonl", sessions[1])))
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if e.Type == checkpointType {
				t.Fatalf("group close signed a checkpoint over the failed shard: %+v", e)
			}
		}
	})
}

// Waiting for tickets one at a time, in append order, completes even when the
// first ticket's maintenance runs a checkpoint: storage retires each settled
// batch itself, so maintenance never waits for a caller that has not started
// waiting yet.
func TestSequentialTicketWaitsCrossACheckpoint(t *testing.T) {
	rec := newDurableTestRecorder(t, Config{CheckpointInterval: 2})
	defer func() { _ = rec.Close() }()
	first := appendTestTicket(t, rec, "first")
	second := appendTestTicket(t, rec, "second")
	done := make(chan error, 1)
	go func() {
		if err := first.Wait(); err != nil {
			done <- err
			return
		}
		done <- second.Wait()
	}()
	if err := waitForDone(t, done, "sequential ticket waits"); err != nil {
		t.Fatal(err)
	}
}

// Concurrent writers that share no outer lock still get tickets that finish,
// and notify observers, in the order their entries were appended.
func TestTicketsFinishInAppendOrderAcrossWriters(t *testing.T) {
	rec := newDurableTestRecorder(t, Config{CheckpointInterval: 10_000, MaxEntriesPerFile: 10_000})
	defer func() { _ = rec.Close() }()
	observer := &durableTestObserver{seen: make(chan Entry, 256)}
	rec.SetObserver(observer)
	const writers = 64
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := rec.RecordDurable(Entry{SessionID: "durable-session", Type: "request", Summary: fmt.Sprintf("w%d", i)}); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	observer.mu.Lock()
	defer observer.mu.Unlock()
	if len(observer.entries) != writers {
		t.Fatalf("observed %d entries, want %d", len(observer.entries), writers)
	}
	for i, e := range observer.entries {
		if e.Sequence != uint64(i) {
			t.Fatalf("observer sequence order broken at %d: got seq %d", i, e.Sequence)
		}
	}
}
