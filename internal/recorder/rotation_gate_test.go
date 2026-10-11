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

// A size rotation waits for the old file's syncs while holding the append
// lock, and the wait releases r.mu. A write that arrives then must wait for the
// rotation before it takes a sequence: otherwise it takes the rotating entry's
// sequence and fails at the bounded append lock after its caller advanced.
func TestSizeRotationHoldsArrivingWritesBeforeTheyTakeASequence(t *testing.T) {
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

	// Hold the sync of one small entry on the old file, so the rotation that
	// the next padded entry needs has to wait for it.
	rec.mu.Lock()
	oldFile := rec.file
	rec.mu.Unlock()
	release := make(chan struct{})
	released := false
	unblock := func() {
		if !released {
			released = true
			close(release)
		}
	}
	defer unblock()
	syncStarted := make(chan struct{}, 1)
	rec.mu.Lock()
	rec.fileSync = func(f *os.File) error {
		if f == oldFile {
			select {
			case syncStarted <- struct{}{}:
			default:
			}
			<-release
		}
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
		t.Fatal("old file sync never started")
	}

	rotating := make(chan error, 1)
	go func() { rotating <- rec.RecordDurable(big()) }()
	probe, err := os.OpenFile(filepath.Join(rec.Dir(), AppendLockFileName), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = probe.Close() }()
	testwait.For(t, 5*time.Second, func() bool {
		lockErr := lockEvidenceAppend(probe)
		if lockErr == nil {
			_ = unlockEvidenceAppend(probe)
			return false
		}
		return errors.Is(lockErr, errAppendLockBusy)
	}, "the rotating write never held the append lock while waiting for the old file")

	arriving := make(chan error, 1)
	go func() {
		arriving <- rec.RecordDurable(Entry{SessionID: session, Type: "test", Summary: "after rotation"})
	}()
	// The append lock gives up after one second. A write that is still waiting
	// past that bound is waiting for the rotation, not for the lock.
	bound := time.NewTimer(1500 * time.Millisecond)
	defer bound.Stop()
	select {
	case err := <-arriving:
		// Tickets complete in append order, so the pending one is waited first.
		unblock()
		_ = ticket.Wait()
		<-rotating
		t.Fatalf("a write arriving during the rotation finished before it: %v", err)
	case <-bound.C:
	}
	unblock()
	if err := ticket.Wait(); err != nil {
		t.Fatalf("pending entry: %v", err)
	}
	if err := <-rotating; err != nil {
		t.Fatalf("rotating entry: %v", err)
	}
	if err := <-arriving; err != nil {
		t.Fatalf("arriving entry: %v", err)
	}

	entries, files := readSessionFiles(t, rec.Dir(), session)
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
	rec.mu.Lock()
	rec.rotating = true
	rec.mu.Unlock()
	done := make(chan error, 1)
	go func() {
		rec.mu.Lock()
		defer rec.mu.Unlock()
		done <- rec.checkpointLocked()
	}()
	select {
	case err := <-done:
		t.Fatalf("checkpoint ran during a rotation: %v", err)
	case <-time.After(200 * time.Millisecond):
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
