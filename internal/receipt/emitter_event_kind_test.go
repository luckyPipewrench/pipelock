// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"net/http"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

const (
	ekTranscriptRoot = "transcript_root"
	ekActionWrite    = "write"
	ekActionRead     = "read"
)

// TestEmit_StampsEventKind_FromActionType verifies that the recorder envelope
// for an action_receipt entry carries event_kind equal to the receipt's
// ActionType (the verb). A POST request classifies as ActionWrite and must
// stamp event_kind="write" so downstream consumers can route by verb without
// re-classifying the inner ActionRecord.
func TestEmit_StampsEventKind_FromActionType(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	_, priv := generateTestKey(t)
	rec := newTestRecorder(t, dir, priv)

	e := NewEmitter(EmitterConfig{
		Recorder:   rec,
		PrivKey:    priv,
		ConfigHash: testConfigHash,
		Principal:  testPrincipal,
		Actor:      testActor,
	})
	if e == nil {
		t.Fatal("NewEmitter() returned nil")
	}

	if err := e.Emit(EmitOpts{
		ActionID:  NewActionID(),
		Target:    testTarget,
		Verdict:   config.ActionAllow,
		Transport: testTransport,
		Method:    http.MethodPost, // ClassifyHTTP(POST) -> ActionWrite
	}); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("recorder.Close: %v", err)
	}

	entries := readAllEntriesFromDir(t, dir)
	var found bool
	for _, entry := range entries {
		if entry.Type != recorderEntryType {
			continue
		}
		found = true
		if entry.EventKind != ekActionWrite {
			t.Errorf("EventKind for POST receipt: got %q, want %q",
				entry.EventKind, ekActionWrite)
		}
	}
	if !found {
		t.Fatal("no action_receipt entries in recorder output")
	}
}

// TestEmit_StampsEventKind_GETIsRead verifies the read-side classification:
// GET maps to ActionRead, and event_kind on the envelope must be "read".
func TestEmit_StampsEventKind_GETIsRead(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	_, priv := generateTestKey(t)
	rec := newTestRecorder(t, dir, priv)

	e := NewEmitter(EmitterConfig{
		Recorder:   rec,
		PrivKey:    priv,
		ConfigHash: testConfigHash,
		Principal:  testPrincipal,
		Actor:      testActor,
	})
	if err := e.Emit(EmitOpts{
		ActionID:  NewActionID(),
		Target:    testTarget,
		Verdict:   config.ActionAllow,
		Transport: testTransport,
		Method:    http.MethodGet,
	}); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("recorder.Close: %v", err)
	}

	entries := readAllEntriesFromDir(t, dir)
	for _, entry := range entries {
		if entry.Type != recorderEntryType {
			continue
		}
		if entry.EventKind != ekActionRead {
			t.Errorf("EventKind for GET receipt: got %q, want %q",
				entry.EventKind, ekActionRead)
		}
		return
	}
	t.Fatal("no action_receipt entries found")
}

// TestEmitTranscriptRoot_StampsEventKind verifies that transcript_root entries
// stamp event_kind="transcript_root" — a fixed envelope label that signals to
// chain-walkers and downstream consumers that this row is the chain seal, not
// a per-action receipt.
func TestEmitTranscriptRoot_StampsEventKind(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	_, priv := generateTestKey(t)
	rec := newTestRecorder(t, dir, priv)

	e := NewEmitter(EmitterConfig{
		Recorder:   rec,
		PrivKey:    priv,
		ConfigHash: testConfigHash,
		Principal:  testPrincipal,
		Actor:      testActor,
	})

	// Need at least one receipt before EmitTranscriptRoot does anything.
	if err := e.Emit(EmitOpts{
		ActionID:  NewActionID(),
		Target:    testTarget,
		Verdict:   config.ActionAllow,
		Transport: testTransport,
		Method:    http.MethodGet,
	}); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	if err := e.EmitTranscriptRoot("session-eventkind"); err != nil {
		t.Fatalf("EmitTranscriptRoot: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("recorder.Close: %v", err)
	}

	entries := readAllEntriesFromDir(t, dir)
	var rootEntry *recorder.Entry
	for i := range entries {
		if entries[i].Type == transcriptRootEntryType {
			rootEntry = &entries[i]
			break
		}
	}
	if rootEntry == nil {
		t.Fatal("no transcript_root entry written")
	}
	if rootEntry.EventKind != ekTranscriptRoot {
		t.Errorf("EventKind: got %q, want %q", rootEntry.EventKind, ekTranscriptRoot)
	}
}
