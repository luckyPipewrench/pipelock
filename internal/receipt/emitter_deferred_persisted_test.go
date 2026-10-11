// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"errors"
	"net/http"
	"os"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// A durable receipt confirmed through a ticket is written like any other, so
// the evidence health audit's persisted tail must name it. Otherwise the audit
// compares the file's tail with a receipt the recorder wrote long ago and
// reports a healthy chain as diverged.
func TestEmitDurableAdvancesPersistedTail(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	_, priv := generateTestKey(t)
	rec := newTestRecorder(t, dir, priv)
	t.Cleanup(func() { _ = rec.Close() })

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
	for i := 0; i < 3; i++ {
		if err := e.EmitDurable(EmitOpts{
			ActionID:  NewActionID(),
			Target:    testTarget,
			Verdict:   config.ActionAllow,
			Transport: testTransport,
			Method:    http.MethodGet,
		}); err != nil {
			t.Fatalf("EmitDurable(%d): %v", i, err)
		}
	}

	obs, err := e.TailObservation()
	if err != nil {
		t.Fatalf("TailObservation(): %v", err)
	}
	if obs.ChainSeq != 3 {
		t.Fatalf("chain head = %d, want 3", obs.ChainSeq)
	}
	if obs.PersistedSeq != 2 || obs.PersistedHash != obs.PrevHash {
		t.Fatalf("persisted tail = seq %d hash %q, want seq 2 hash %q (the last confirmed receipt)", obs.PersistedSeq, obs.PersistedHash, obs.PrevHash)
	}
}

// A durable receipt whose sync fails after its write reached the file is
// reported unconfirmed, so the audit can tell a written-but-lost receipt from
// one that is merely still confirming.
func TestEmitDurableSyncFailureReportsUnconfirmed(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	_, priv := generateTestKey(t)
	rec := newTestRecorder(t, dir, priv)
	t.Cleanup(func() { _ = rec.Close() })

	e := NewEmitter(EmitterConfig{
		Recorder:   rec,
		PrivKey:    priv,
		ConfigHash: testConfigHash,
		Principal:  testPrincipal,
		Actor:      testActor,
	})
	emit := func() error {
		return e.EmitDurable(EmitOpts{
			ActionID:  NewActionID(),
			Target:    testTarget,
			Verdict:   config.ActionAllow,
			Transport: testTransport,
			Method:    http.MethodGet,
		})
	}
	if err := emit(); err != nil {
		t.Fatalf("first EmitDurable: %v", err)
	}
	if obs, err := e.TailObservation(); err != nil || obs.Unconfirmed {
		t.Fatalf("healthy chain: unconfirmed=%v err=%v", obs.Unconfirmed, err)
	}
	rec.SetSyncForTest(func(*os.File) error { return errors.New("injected sync failure") })
	if err := emit(); !errors.Is(err, ErrReceiptPostAdvance) {
		t.Fatalf("EmitDurable after sync failure = %v, want a post-advance failure", err)
	}
	obs, err := e.TailObservation()
	if err != nil {
		t.Fatalf("TailObservation(): %v", err)
	}
	if !obs.Unconfirmed || obs.UnconfirmedSeq != 1 {
		t.Fatalf("unconfirmed = %v seq %d, want true seq 1", obs.Unconfirmed, obs.UnconfirmedSeq)
	}
}
