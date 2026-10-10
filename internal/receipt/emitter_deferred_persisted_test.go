// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"net/http"
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
