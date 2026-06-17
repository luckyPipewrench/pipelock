// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"net/http"
	"sync"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// TestEmitter_OnReceipt_FiresInChainOrder verifies the streaming observer is
// invoked once per Emit, in chain order, with the signed receipt. This is the
// seam the live playground stream depends on.
func TestEmitter_OnReceipt_FiresInChainOrder(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	_, priv := generateTestKey(t)
	rec := newTestRecorder(t, dir, priv)
	defer func() { _ = rec.Close() }()

	var observed []*Receipt
	e := NewEmitter(EmitterConfig{
		Recorder:   rec,
		PrivKey:    priv,
		ConfigHash: testConfigHash,
		Principal:  testPrincipal,
		Actor:      testActor,
		OnReceipt:  func(r *Receipt) { observed = append(observed, r) },
	})
	if e == nil {
		t.Fatal("NewEmitter() returned nil")
	}

	const n = 5
	for i := 0; i < n; i++ {
		if err := e.Emit(EmitOpts{
			ActionID:  NewActionID(),
			Target:    testTarget,
			Verdict:   config.ActionBlock,
			Transport: testTransport,
			Method:    http.MethodGet,
		}); err != nil {
			t.Fatalf("Emit() %d: %v", i, err)
		}
	}

	if len(observed) != n {
		t.Fatalf("observer fired %d times, want %d", len(observed), n)
	}
	for i, r := range observed {
		if r == nil {
			t.Fatalf("observed[%d] is nil", i)
		}
		if got := r.ActionRecord.ChainSeq; got != uint64(i) {
			t.Errorf("observed[%d] chain_seq = %d, want %d", i, got, i)
		}
		if r.Signature == "" {
			t.Errorf("observed[%d] has empty signature; observer must see signed receipts", i)
		}
		if r.ActionRecord.Verdict != "block" {
			t.Errorf("observed[%d] verdict = %q, want block", i, r.ActionRecord.Verdict)
		}
	}
}

// TestEmitter_OnReceipt_NilIsNoOp confirms the default (no observer) path still
// emits normally — the batch evidence path must be unchanged when OnReceipt is
// nil.
func TestEmitter_OnReceipt_NilIsNoOp(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pub, priv := generateTestKey(t)
	rec := newTestRecorder(t, dir, priv)

	e := NewEmitter(EmitterConfig{
		Recorder:  rec,
		PrivKey:   priv,
		Principal: testPrincipal,
		Actor:     testActor,
		// OnReceipt deliberately nil.
	})
	if e == nil {
		t.Fatal("NewEmitter() returned nil")
	}
	if err := e.Emit(EmitOpts{
		ActionID:  NewActionID(),
		Target:    testTarget,
		Verdict:   config.ActionBlock,
		Transport: testTransport,
		Method:    http.MethodGet,
	}); err != nil {
		t.Fatalf("Emit(): %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("recorder.Close(): %v", err)
	}
	// The durable receipt must still be on disk.
	got := readReceiptFromDir(t, dir, pub)
	if got.ActionRecord.Target != testTarget {
		t.Errorf("recorded target = %q, want %q", got.ActionRecord.Target, testTarget)
	}
}

// TestEmitter_OnReceipt_ObserverGetsCopy proves the observer receives a copy: a
// misbehaving observer that mutates the receipt cannot corrupt what is on disk.
func TestEmitter_OnReceipt_ObserverGetsCopy(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pub, priv := generateTestKey(t)
	rec := newTestRecorder(t, dir, priv)

	e := NewEmitter(EmitterConfig{
		Recorder:  rec,
		PrivKey:   priv,
		Principal: testPrincipal,
		Actor:     testActor,
		OnReceipt: func(r *Receipt) {
			// Hostile observer: scribble over the fields it was handed.
			r.Signature = "tampered"
			r.ActionRecord.Target = "evil.example"
			r.ActionRecord.ChainSeq = 9999
		},
	})
	if e == nil {
		t.Fatal("NewEmitter() returned nil")
	}
	if err := e.Emit(EmitOpts{
		ActionID:  NewActionID(),
		Target:    testTarget,
		Verdict:   config.ActionAllow,
		Transport: testTransport,
		Method:    http.MethodGet,
	}); err != nil {
		t.Fatalf("Emit(): %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("recorder.Close(): %v", err)
	}

	got := readReceiptFromDir(t, dir, pub)
	if got.ActionRecord.Target != testTarget {
		t.Errorf("on-disk target = %q, want %q (observer mutation leaked into the chain)", got.ActionRecord.Target, testTarget)
	}
	if got.ActionRecord.ChainSeq != 0 {
		t.Errorf("on-disk chain_seq = %d, want 0 (observer mutation leaked)", got.ActionRecord.ChainSeq)
	}
	if got.Signature == "tampered" {
		t.Error("on-disk signature was overwritten by the observer")
	}
}

// TestEmitter_OnReceipt_ConcurrentEmit verifies that under concurrent Emit calls
// every receipt is observed exactly once with a unique, contiguous chain_seq.
// Run with -race to catch unsynchronized observer access.
func TestEmitter_OnReceipt_ConcurrentEmit(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	_, priv := generateTestKey(t)
	rec := newTestRecorder(t, dir, priv)
	defer func() { _ = rec.Close() }()

	var mu sync.Mutex
	seqs := make(map[uint64]int)
	e := NewEmitter(EmitterConfig{
		Recorder:  rec,
		PrivKey:   priv,
		Principal: testPrincipal,
		Actor:     testActor,
		OnReceipt: func(r *Receipt) {
			mu.Lock()
			seqs[r.ActionRecord.ChainSeq]++
			mu.Unlock()
		},
	})
	if e == nil {
		t.Fatal("NewEmitter() returned nil")
	}

	const goroutines = 8
	const each = 6
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < each; i++ {
				_ = e.Emit(EmitOpts{
					ActionID:  NewActionID(),
					Target:    testTarget,
					Verdict:   config.ActionAllow,
					Transport: testTransport,
					Method:    http.MethodGet,
				})
			}
		}()
	}
	wg.Wait()

	total := goroutines * each
	if len(seqs) != total {
		t.Fatalf("observed %d distinct chain_seq values, want %d", len(seqs), total)
	}
	for seq := uint64(0); seq < uint64(total); seq++ {
		switch seqs[seq] {
		case 0:
			t.Errorf("chain_seq %d was never observed (gap)", seq)
		case 1: // exactly once, correct
		default:
			t.Errorf("chain_seq %d observed %d times (duplicate)", seq, seqs[seq])
		}
	}
}
