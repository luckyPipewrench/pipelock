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
	if got := metrics.snapshot(); len(got) != 1 || got[0] != FailReasonSync {
		t.Fatalf("emit failure reasons = %v, want [%q]", got, FailReasonSync)
	}

	if err := e.EmitDurable(EmitOpts{
		ActionID:  NewActionID(),
		Target:    testTarget,
		Verdict:   config.ActionAllow,
		Transport: testTransport,
		Method:    http.MethodGet,
	}); err != nil {
		t.Fatalf("second EmitDurable: %v", err)
	}

	receipts := allReceiptsRaw(t, dir)
	if len(receipts) < 2 {
		t.Fatalf("receipts = %d, want at least 2", len(receipts))
	}
	if receipts[0].ActionRecord.ChainSeq != 0 || receipts[1].ActionRecord.ChainSeq != 1 {
		t.Fatalf("receipt chain seqs = %d,%d; rollback would have duplicated seq 0",
			receipts[0].ActionRecord.ChainSeq, receipts[1].ActionRecord.ChainSeq)
	}
	if receipts[1].ActionRecord.ChainPrevHash == GenesisHash {
		t.Fatal("second receipt linked to genesis; durable failure rolled back receipt state")
	}
}
