//go:build (unix && !aix) || windows

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

// heldRotation is a size rotation stopped inside its wait for the old file's
// syncs: the rotating write holds its sequence and the append lock.
type heldRotation struct {
	rec         *Recorder
	session     string
	pending     *DurableTicket
	rotating    chan error
	gateEntered chan struct{}
	unblock     func()
}

// startHeldRotation fills a file, holds the sync of one pending entry on it
// (failing that sync with syncErr when set), and starts the write that must
// rotate. It returns once the rotating write holds the append lock.
func startHeldRotation(t *testing.T, syncErr error) *heldRotation {
	t.Helper()
	rec := newTestRecorderForAcquire(t)
	session, err := AcquireRunSession(rec, "proxy")
	if err != nil {
		t.Fatal(err)
	}
	pad := map[string]string{"pad": strings.Repeat("a", 900_000)}
	big := func() Entry { return Entry{SessionID: session, Type: "test", Detail: pad} }

	// Fill the first file until one more padded entry cannot fit.
	if err := rec.RecordDurable(big()); err != nil {
		t.Fatal(err)
	}
	line := currentFileSize(t, rec)
	for currentFileSize(t, rec)+line <= MaxEvidenceReadFileBytes {
		if err := rec.RecordDurable(big()); err != nil {
			t.Fatal(err)
		}
	}

	h := &heldRotation{rec: rec, session: session, rotating: make(chan error, 1), gateEntered: make(chan struct{}, 1)}
	release := make(chan struct{})
	released := false
	h.unblock = func() {
		if !released {
			released = true
			close(release)
		}
	}
	t.Cleanup(h.unblock)
	syncStarted := make(chan struct{}, 1)
	rec.mu.Lock()
	oldFile := rec.file
	rec.fileSync = func(f *os.File) error {
		if f == oldFile {
			select {
			case syncStarted <- struct{}{}:
			default:
			}
			<-release
			if syncErr != nil {
				return syncErr
			}
		}
		return f.Sync()
	}
	rec.rotationWaitHook = func() {
		select {
		case h.gateEntered <- struct{}{}:
		default:
		}
	}
	rec.mu.Unlock()

	h.pending, err = rec.AppendDurableWithReceiptScanPreAdvance(Entry{SessionID: session, Type: "test", Summary: "pending"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-syncStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("old file sync never started")
	}
	go func() { h.rotating <- rec.RecordDurable(big()) }()
	probe, err := os.OpenFile(filepath.Join(rec.Dir(), AppendLockFileName), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = probe.Close() })
	testwait.For(t, 5*time.Second, func() bool {
		lockErr := lockEvidenceAppend(probe)
		if lockErr == nil {
			_ = unlockEvidenceAppend(probe)
			return false
		}
		return errors.Is(lockErr, errAppendLockBusy)
	}, "the rotating write never held the append lock while waiting for the old file")
	return h
}

// startArriving starts a write during the held rotation and returns once it
// is waiting at the rotation gate. A write that finishes first took a
// sequence during the rotation.
func (h *heldRotation) startArriving(t *testing.T) chan error {
	t.Helper()
	arriving := make(chan error, 1)
	go func() {
		arriving <- h.rec.RecordDurable(Entry{SessionID: h.session, Type: "test", Summary: "after rotation"})
	}()
	select {
	case <-h.gateEntered:
	case err := <-arriving:
		// Tickets complete in append order, so the pending one is waited first.
		h.unblock()
		_ = h.pending.Wait()
		<-h.rotating
		t.Fatalf("a write arriving during the rotation finished before it: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("a write arriving during the rotation neither waited nor finished")
	}
	return arriving
}

// A size rotation waits for the old file's syncs while holding the append
// lock, and the wait releases r.mu. A write that arrives then must wait for the
// rotation before it takes a sequence: otherwise it takes the rotating entry's
// sequence and fails at the bounded append lock after its caller advanced.
func TestSizeRotationHoldsArrivingWritesBeforeTheyTakeASequence(t *testing.T) {
	h := startHeldRotation(t, nil)
	arriving := h.startArriving(t)
	h.unblock()
	if err := h.pending.Wait(); err != nil {
		t.Fatalf("pending entry: %v", err)
	}
	if err := <-h.rotating; err != nil {
		t.Fatalf("rotating entry: %v", err)
	}
	if err := <-arriving; err != nil {
		t.Fatalf("arriving entry: %v", err)
	}

	entries, files := readSessionFiles(t, h.rec.Dir(), h.session)
	if files < 2 {
		t.Fatalf("expected a size rotation, found %d file(s)", files)
	}
	if err := VerifyChain(entries); err != nil {
		t.Fatalf("chain: %v", err)
	}
	if last := entries[len(entries)-1]; last.Summary != "after rotation" {
		t.Fatalf("last entry = %q, want the write that arrived during the rotation", last.Summary)
	}
}

// When the old file's sync fails during the rotation, a write waiting at the
// gate wakes and refuses with the inherited durability failure instead of
// hanging or chaining onto the unconfirmed prefix.
func TestFailedRotationSyncReleasesWaitingWritesWithAnError(t *testing.T) {
	h := startHeldRotation(t, errors.New("injected sync failure"))
	arriving := h.startArriving(t)
	h.unblock()
	if err := h.pending.Wait(); !errors.Is(err, ErrDurability) {
		t.Fatalf("pending entry: %v, want ErrDurability", err)
	}
	// The rotating write was appended before the failure surfaced, so it can
	// never be confirmed either.
	if err := <-h.rotating; !errors.Is(err, ErrDurability) && !errors.Is(err, ErrDurabilityInherited) {
		t.Fatalf("rotating entry: %v, want a durability failure", err)
	}
	if err := <-arriving; !errors.Is(err, ErrDurabilityInherited) {
		t.Fatalf("arriving entry: %v, want ErrDurabilityInherited", err)
	}
	entries, _ := readSessionFiles(t, h.rec.Dir(), h.session)
	for _, e := range entries {
		if e.Summary == "after rotation" {
			t.Fatal("a write was recorded after the stream's sync failed")
		}
	}
}

// A checkpoint takes a sequence too, so it waits for a rotation in progress.
func TestCheckpointWaitsForRotationInProgress(t *testing.T) {
	rec := newTestRecorderForAcquire(t)
	session, err := AcquireRunSession(rec, "proxy")
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Record(Entry{SessionID: session, Type: "test", Summary: "first"}); err != nil {
		t.Fatal(err)
	}
	gateEntered := make(chan struct{}, 1)
	endRotationOnCleanup(t, rec)
	rec.mu.Lock()
	rec.rotating = true
	rec.rotationWaitHook = func() {
		select {
		case gateEntered <- struct{}{}:
		default:
		}
	}
	rec.mu.Unlock()
	done := make(chan error, 1)
	go func() {
		rec.mu.Lock()
		defer rec.mu.Unlock()
		done <- rec.checkpointLocked()
	}()
	select {
	case <-gateEntered:
	case err := <-done:
		t.Fatalf("checkpoint ran during a rotation: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("checkpoint neither waited nor finished")
	}
	rec.mu.Lock()
	rec.rotating = false
	rec.durableCond.Broadcast()
	rec.mu.Unlock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	entries, _ := readSessionFiles(t, rec.Dir(), session)
	if err := VerifyChain(entries); err != nil {
		t.Fatalf("chain: %v", err)
	}
}

// The entry-count rotation after a write waits for a size rotation in
// progress, and does not rotate the file that rotation just opened.
func TestEntryCountRotationWaitsForSizeRotation(t *testing.T) {
	rec := newTestRecorderForAcquire(t)
	session, err := AcquireRunSession(rec, "proxy")
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Record(Entry{SessionID: session, Type: "test", Summary: "first"}); err != nil {
		t.Fatal(err)
	}
	gateEntered := make(chan struct{}, 1)
	endRotationOnCleanup(t, rec)
	rec.mu.Lock()
	file := rec.file
	rec.fileEntryCount = rec.cfg.MaxEntriesPerFile
	rec.rotating = true
	rec.rotationWaitHook = func() {
		select {
		case gateEntered <- struct{}{}:
		default:
		}
	}
	rec.mu.Unlock()
	done := make(chan error, 1)
	go func() {
		rec.mu.Lock()
		defer rec.mu.Unlock()
		done <- rec.runPostRecordMaintenanceLocked()
	}()
	select {
	case <-gateEntered:
	case err := <-done:
		t.Fatalf("entry-count rotation ran during a size rotation: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("entry-count rotation neither waited nor finished")
	}
	// The size rotation finishes and its new file has one entry.
	rec.mu.Lock()
	rec.fileEntryCount = 1
	rec.rotating = false
	rec.durableCond.Broadcast()
	rec.mu.Unlock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.file != file {
		t.Fatal("entry-count rotation rotated the file the size rotation left open")
	}
}

// closeFile waits for the file's syncs and that wait releases mu. A second
// caller that closed the file meanwhile leaves nothing for the first to close.
func TestCloseFileSkipsAFileClosedDuringItsWait(t *testing.T) {
	rec := newTestRecorderForAcquire(t)
	session, err := AcquireRunSession(rec, "proxy")
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.RecordDurable(Entry{SessionID: session, Type: "test", Summary: "first"}); err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	syncStarted := make(chan struct{}, 1)
	rec.mu.Lock()
	rec.fileSync = func(f *os.File) error {
		select {
		case syncStarted <- struct{}{}:
		default:
		}
		<-release
		return f.Sync()
	}
	rec.mu.Unlock()
	ticket, err := rec.AppendDurableWithReceiptScanPreAdvance(Entry{SessionID: session, Type: "test", Summary: "pending"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-syncStarted:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("sync never started")
	}
	closers := make(chan error, 2)
	for i := 0; i < 2; i++ {
		entered := make(chan struct{})
		go func() {
			rec.mu.Lock()
			close(entered)
			err := rec.closeFile()
			rec.mu.Unlock()
			closers <- err
		}()
		<-entered
		// The closer holds mu until its wait for the pending sync releases it.
		testwait.For(t, 5*time.Second, func() bool {
			if rec.mu.TryLock() {
				rec.mu.Unlock()
				return true
			}
			return false
		}, "closer never started waiting for the pending sync")
	}
	close(release)
	if err := ticket.Wait(); err != nil {
		t.Fatalf("pending entry: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := <-closers; err != nil {
			t.Fatalf("closer: %v", err)
		}
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.file != nil {
		t.Fatal("file still open after both closers returned")
	}
}

// endRotationOnCleanup clears a simulated rotation before the recorder's own
// cleanup closes it, so a failing test cannot leave Close waiting at the gate.
func endRotationOnCleanup(t *testing.T, rec *Recorder) {
	t.Helper()
	t.Cleanup(func() {
		rec.mu.Lock()
		rec.rotating = false
		rec.durableCond.Broadcast()
		rec.mu.Unlock()
	})
}

func currentFileSize(t *testing.T, rec *Recorder) int64 {
	t.Helper()
	rec.mu.Lock()
	defer rec.mu.Unlock()
	info, err := rec.file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	return info.Size()
}

// readSessionFiles reads every evidence file of session in sequence order.
func readSessionFiles(t *testing.T, dir, session string) ([]Entry, int) {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(dir, "evidence-"+session+"-*.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	start := func(p string) int {
		n, _ := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(filepath.Base(p), "evidence-"+session+"-"), ".jsonl"))
		return n
	}
	sort.Slice(paths, func(i, j int) bool { return start(paths[i]) < start(paths[j]) })
	var all []Entry
	for _, p := range paths {
		entries, err := ReadEntries(p)
		if err != nil {
			t.Fatalf("ReadEntries(%q): %v", p, err)
		}
		all = append(all, entries...)
	}
	return all, len(paths)
}
