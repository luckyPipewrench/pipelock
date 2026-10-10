// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package ael

import (
	"errors"
	"fmt"
	"os"
)

type durabilityBatch struct {
	file    *os.File
	syncing bool
	done    chan struct{}
	err     error
}

// ReserveDurability returns a confirmation covering every record already
// written to this stream. Records written after a batch starts syncing join a
// successor batch, never that batch's promise. A failed sync is sticky
// (lastErr), so a later reservation never confirms over an unconfirmed prefix.
// The owning receipt emitter waits on the confirmation outside its chain lock
// and drains outstanding confirmations before any lifecycle record.
func (e *Emitter) ReserveDurability() (func() error, error) {
	if e == nil {
		return func() error { return nil }, nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.lastErr != nil {
		return nil, fmt.Errorf("native AEL emitter unhealthy: %w", e.lastErr)
	}
	if e.closed || e.file == nil {
		return nil, errors.New("native AEL run is closed")
	}
	batch := e.syncBatch
	if batch == nil || batch.syncing {
		batch = &durabilityBatch{file: e.file, done: make(chan struct{})}
		e.syncBatch = batch
		go e.syncDurabilityBatch(batch)
	}
	return func() error { <-batch.done; return batch.err }, nil
}

func (e *Emitter) syncDurabilityBatch(batch *durabilityBatch) {
	// One sync at a time per stream: a batch that starts after a failure must
	// observe it rather than race it.
	e.syncMu.Lock()
	defer e.syncMu.Unlock()
	e.mu.Lock()
	batch.syncing = true
	err := e.lastErr
	e.mu.Unlock()
	if err == nil {
		err = e.syncFile(batch.file)
		if err != nil {
			err = fmt.Errorf("persist native AEL activity: %w", err)
		}
	} else {
		err = fmt.Errorf("native AEL emitter unhealthy: %w", err)
	}
	e.mu.Lock()
	batch.err = err
	if err != nil && e.lastErr == nil {
		e.lastErr = err
	}
	if e.syncBatch == batch {
		e.syncBatch = nil
	}
	close(batch.done)
	e.mu.Unlock()
}

// SetSyncForTest installs a durability-failure seam. It is never driven by
// configuration or request input; nil restores File.Sync.
func (e *Emitter) SetSyncForTest(fn func(*os.File) error) {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.fileSync = fn
}

// syncFile reads the seam without e.mu so a sync never holds the emitter lock.
func (e *Emitter) syncFile(f *os.File) error {
	e.mu.Lock()
	fn := e.fileSync
	e.mu.Unlock()
	if fn != nil {
		return fn(f)
	}
	return f.Sync()
}
