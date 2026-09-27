// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows && !darwin

package directorysync

import (
	"errors"
	"path/filepath"
	"testing"
)

type fakeDirectorySyncer struct {
	syncErr  error
	closeErr error
	closed   bool
}

func (f *fakeDirectorySyncer) Sync() error { return f.syncErr }

func (f *fakeDirectorySyncer) Close() error {
	f.closed = true
	return f.closeErr
}

func TestSyncDirectoryRejectsMissingPath(t *testing.T) {
	t.Parallel()
	if err := Sync(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("Sync accepted a missing path")
	}
}

func TestSyncDirectoryReturnsSyncErrorAndCloses(t *testing.T) {
	t.Parallel()
	wantErr := errors.New("sync failed")
	dir := &fakeDirectorySyncer{syncErr: wantErr}
	err := syncWithOpen("directory", func(string) (directorySyncer, error) {
		return dir, nil
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("syncWithOpen error = %v, want %v", err, wantErr)
	}
	if !dir.closed {
		t.Fatal("syncWithOpen did not close directory after sync failure")
	}
}

func TestSyncDirectoryReturnsCloseError(t *testing.T) {
	t.Parallel()
	wantErr := errors.New("close failed")
	dir := &fakeDirectorySyncer{closeErr: wantErr}
	err := syncWithOpen("directory", func(string) (directorySyncer, error) {
		return dir, nil
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("syncWithOpen error = %v, want %v", err, wantErr)
	}
}
