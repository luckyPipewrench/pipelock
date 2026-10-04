// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"path/filepath"
	"sync"
	"testing"
)

type signalUnlockLocker struct {
	mu       *sync.Mutex
	unlocked chan struct{}
	once     sync.Once
}

func (l *signalUnlockLocker) Lock() { l.mu.Lock() }

func (l *signalUnlockLocker) Unlock() {
	l.mu.Unlock()
	l.once.Do(func() { close(l.unlocked) })
}

func TestCheckpointMaintenanceRechecksAfterDurableWait(t *testing.T) {
	dir := t.TempDir()
	rec := newDurableTestRecorder(t, Config{Dir: dir, CheckpointInterval: 1000})
	defer func() { _ = rec.Close() }()
	if err := rec.Record(Entry{SessionID: "checkpoint-wait", Type: "request", Summary: "first"}); err != nil {
		t.Fatalf("Record: %v", err)
	}

	rec.mu.Lock()
	rec.checkpointThreshold = 1
	generation := rec.fileGeneration
	rec.durablePending[generation] = 1
	locker := &signalUnlockLocker{mu: &rec.mu, unlocked: make(chan struct{})}
	rec.durableCond = sync.NewCond(locker)
	rec.mu.Unlock()

	done := make(chan error, 1)
	go func() {
		rec.mu.Lock()
		defer rec.mu.Unlock()
		done <- rec.runPostRecordMaintenanceLocked()
	}()
	// The Cond's unlock proves maintenance already observed the threshold
	// and is waiting; another writer can now satisfy it first.
	waitForDone(t, locker.unlocked, "maintenance durable wait")
	rec.mu.Lock()
	delete(rec.durablePending, generation)
	if err := rec.checkpointLocked(); err != nil {
		rec.mu.Unlock()
		t.Fatalf("checkpoint by other writer: %v", err)
	}
	rec.durableCond.Broadcast()
	rec.mu.Unlock()
	if err := waitForDone(t, done, "maintenance completion"); err != nil {
		t.Fatalf("runPostRecordMaintenanceLocked: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	entries, err := ReadEntries(filepath.Join(dir, "evidence-checkpoint-wait-0.jsonl"))
	if err != nil {
		t.Fatalf("ReadEntries: %v", err)
	}
	if err := VerifyChain(entries); err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	var checkpoints int
	for _, entry := range entries {
		if entry.Type == checkpointType {
			checkpoints++
			if detail, ok := entry.Detail.(map[string]any); !ok || detail["entry_count"] != float64(1) {
				t.Fatalf("checkpoint detail = %+v, want one entry", entry.Detail)
			}
		}
	}
	if checkpoints != 1 {
		t.Fatalf("checkpoints = %d, want one", checkpoints)
	}
}
