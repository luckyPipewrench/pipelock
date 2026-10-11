// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"errors"
	"net/http"
	"os"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func TestEmitter_EmitDurable_HappyPath(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pub, priv := generateTestKey(t)
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
	if err := e.EmitDurable(EmitOpts{
		ActionID:  NewActionID(),
		Target:    testTarget,
		Verdict:   config.ActionAllow,
		Transport: testTransport,
		Method:    http.MethodGet,
	}); err != nil {
		t.Fatalf("EmitDurable(): %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("recorder.Close(): %v", err)
	}

	got := readReceiptFromDir(t, dir, pub)
	if got.ActionRecord.ChainSeq != 0 {
		t.Fatalf("chain_seq = %d, want 0", got.ActionRecord.ChainSeq)
	}
}

func TestEmitter_EmitDurable_SyncFailureLeavesReceiptGapNotFork(t *testing.T) {
	dir := t.TempDir()
	_, priv := generateTestKey(t)
	rec := newTestRecorder(t, dir, priv)
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

	metrics := &stubMetrics{}
	e := NewEmitter(EmitterConfig{
		Recorder:   rec,
		PrivKey:    priv,
		ConfigHash: testConfigHash,
		Principal:  testPrincipal,
		Actor:      testActor,
		Metrics:    metrics,
	})
	if e == nil {
		t.Fatal("NewEmitter() returned nil")
	}

	err := e.EmitDurable(EmitOpts{
		ActionID:  NewActionID(),
		Target:    testTarget,
		Verdict:   config.ActionAllow,
		Transport: testTransport,
		Method:    http.MethodGet,
	})
	if !errors.Is(err, recorder.ErrDurability) {
		t.Fatalf("first EmitDurable error = %v, want ErrDurability", err)
	}
	if !errors.Is(err, ErrReceiptPostAdvance) {
		t.Fatalf("first EmitDurable error = %v, want post-advance classification", err)
	}
	if got := metrics.snapshot(); len(got) != 1 || got[0] != FailReasonSync {
		t.Fatalf("emit failure reasons = %v, want [%q]", got, FailReasonSync)
	}

	// The stream stays failed: a later receipt is refused before it takes a
	// chain position, rather than confirmed over an unconfirmed prefix.
	err = e.EmitDurable(EmitOpts{
		ActionID:  NewActionID(),
		Target:    testTarget,
		Verdict:   config.ActionAllow,
		Transport: testTransport,
		Method:    http.MethodGet,
	})
	if !errors.Is(err, recorder.ErrDurabilityInherited) || errors.Is(err, recorder.ErrDurability) {
		t.Fatalf("second EmitDurable = %v, want ErrDurabilityInherited and not ErrDurability", err)
	}
	if got := metrics.snapshot(); len(got) != 2 || got[1] != FailReasonDurabilityInherited {
		t.Fatalf("emit failure reasons = %v, want [%q %q]", got, FailReasonSync, FailReasonDurabilityInherited)
	}
	if got := e.DurabilityBlocks(); got != 1 {
		t.Fatalf("durability blocks = %d, want 1; an inherited refusal is not a new storage failure", got)
	}

	receipts := allReceiptsRaw(t, dir)
	if len(receipts) != 1 || receipts[0].ActionRecord.ChainSeq != 0 {
		t.Fatalf("receipts = %d, want only the failed seq 0 receipt (gap kept, no fork, no reuse)", len(receipts))
	}
}
