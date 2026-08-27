// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

type heartbeatFailureLog struct {
	mu      sync.Mutex
	entries []string
	seen    chan string
}

func newHeartbeatFailureLog() *heartbeatFailureLog {
	return &heartbeatFailureLog{seen: make(chan string, 4)}
}

func (l *heartbeatFailureLog) Write(p []byte) (int, error) {
	msg := string(p)
	l.mu.Lock()
	l.entries = append(l.entries, msg)
	l.mu.Unlock()
	select {
	case l.seen <- msg:
	default:
	}
	return len(p), nil
}

func TestReceiptHeartbeatTickerStopsBeforeSeal(t *testing.T) {
	dir := t.TempDir()
	pub, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	rec, err := recorder.New(recorder.Config{
		Enabled:            true,
		Dir:                dir,
		CheckpointInterval: 1000,
	}, nil, priv)
	if err != nil {
		t.Fatalf("recorder.New: %v", err)
	}
	defer func() { _ = rec.Close() }()

	seen := make(chan receipt.Receipt, 8)
	e := receipt.NewEmitter(receipt.EmitterConfig{
		Recorder: rec,
		PrivKey:  priv,
		OnReceipt: func(rcpt *receipt.Receipt) {
			select {
			case seen <- *rcpt:
			default:
			}
		},
	})
	if err := e.EmitSessionOpen(); err != nil {
		t.Fatalf("EmitSessionOpen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	var log bytes.Buffer
	// A one-hour cadence proves this is the immediate startup beat, not a
	// ticker event. The durable session_open above must still be first.
	startReceiptHeartbeat(ctx, &wg, time.Hour, func() *receipt.Emitter { return e }, &log, false, nil)
	waitForHeartbeatReceipt(t, seen)
	cancel()
	wg.Wait()

	if err := emitSessionCloseAndTranscriptRoot(e, transcriptRootSessionID, sessionCloseReasonGracefulShutdown); err != nil {
		t.Fatalf("emitSessionCloseAndTranscriptRoot: %v", err)
	}
	if log.Len() != 0 {
		t.Fatalf("heartbeat logged unexpected error: %s", log.String())
	}

	receipts := readRuntimeReceipts(t, dir, hex.EncodeToString(pub))
	if len(receipts) != 3 {
		t.Fatalf("receipts = %d, want exactly open heartbeat close", len(receipts))
	}
	wantKinds := []receipt.SessionControlKind{receipt.SessionControlOpen, receipt.SessionControlHeartbeat, receipt.SessionControlClose}
	for i, want := range wantKinds {
		if receipts[i].ActionRecord.SessionControl == nil || receipts[i].ActionRecord.SessionControl.Kind != want {
			t.Fatalf("receipt %d control = %#v, want %q", i, receipts[i].ActionRecord.SessionControl, want)
		}
	}
	last := receipts[len(receipts)-1].ActionRecord.SessionControl
	if last == nil || last.Close == nil {
		t.Fatalf("last receipt before root is not session_close: %#v", last)
	}
	root := readRuntimeTranscriptRoot(t, dir)
	closeHash, err := receipt.ReceiptHash(receipts[len(receipts)-1])
	if err != nil {
		t.Fatalf("ReceiptHash(close): %v", err)
	}
	if root.RootHash != closeHash {
		t.Fatalf("root hash = %s, want close hash %s", root.RootHash, closeHash)
	}
}

func TestReceiptHeartbeatCadenceStillBeatsAfterTheFirst(t *testing.T) {
	// The immediate-beat test above runs a one-hour cadence on purpose, so it
	// cannot exercise the ticker at all. Without this test the periodic path, the
	// ORIGINAL heartbeat mechanism, would have no coverage: proving the new beat
	// is immediate must not cost the proof that the old one repeats.
	dir := t.TempDir()
	pub, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	rec, err := recorder.New(recorder.Config{
		Enabled:            true,
		Dir:                dir,
		CheckpointInterval: 1000,
	}, nil, priv)
	if err != nil {
		t.Fatalf("recorder.New: %v", err)
	}
	defer func() { _ = rec.Close() }()

	seen := make(chan receipt.Receipt, 16)
	e := receipt.NewEmitter(receipt.EmitterConfig{
		Recorder: rec,
		PrivKey:  priv,
		OnReceipt: func(rcpt *receipt.Receipt) {
			select {
			case seen <- *rcpt:
			default:
			}
		},
	})
	if err := e.EmitSessionOpen(); err != nil {
		t.Fatalf("EmitSessionOpen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	var log bytes.Buffer
	startReceiptHeartbeat(ctx, &wg, time.Millisecond, func() *receipt.Emitter { return e }, &log, false, nil)

	// Two beats: the immediate one, then at least one from the ticker. Waiting for
	// the second is what proves the cadence loop ran.
	waitForHeartbeatReceipt(t, seen)
	waitForHeartbeatReceipt(t, seen)
	cancel()
	wg.Wait()

	receipts := readRuntimeReceipts(t, dir, hex.EncodeToString(pub))
	heartbeats := 0
	for _, r := range receipts {
		if sc := r.ActionRecord.SessionControl; sc != nil && sc.Heartbeat != nil {
			heartbeats++
		}
	}
	if heartbeats < 2 {
		t.Fatalf("heartbeat receipts = %d, want at least the immediate beat plus one cadence beat", heartbeats)
	}
}

func TestReceiptHeartbeatWithoutAnEmitterDoesNotPanic(t *testing.T) {
	// A nil emitter is the pre-session and post-teardown state. It must be a quiet
	// no-op rather than a panic or a logged failure, because the scheduler is
	// started and stopped around a lifecycle it does not own.
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	var log bytes.Buffer
	startReceiptHeartbeat(ctx, &wg, time.Millisecond, func() *receipt.Emitter { return nil }, &log, true, func(error) {
		t.Fatal("a nil emitter must not report a required-receipt failure")
	})
	cancel()
	wg.Wait()
	if log.Len() != 0 {
		t.Fatalf("log = %q, want nothing written for a nil emitter", log.String())
	}
}

func TestRequiredReceiptHeartbeatFailureMarksEmitterUnhealthy(t *testing.T) {
	dir := t.TempDir()
	_, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	rec, err := recorder.New(recorder.Config{
		Enabled:            true,
		Dir:                dir,
		CheckpointInterval: 1000,
	}, nil, priv)
	if err != nil {
		t.Fatalf("recorder.New: %v", err)
	}

	e := receipt.NewEmitter(receipt.EmitterConfig{
		Recorder: rec,
		PrivKey:  priv,
	})
	if err := e.EmitSessionOpen(); err != nil {
		t.Fatalf("EmitSessionOpen: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("recorder.Close: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	var log bytes.Buffer
	requiredFailure := make(chan error, 1)
	startReceiptHeartbeat(ctx, &wg, time.Millisecond, func() *receipt.Emitter { return e }, &log, true, func(err error) {
		requiredFailure <- err
		cancel()
	})
	defer wg.Wait()

	select {
	case err := <-requiredFailure:
		if err == nil {
			t.Fatal("required heartbeat failure callback received nil error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for required heartbeat failure")
	}
	if e.HealthError() == nil {
		t.Fatal("emitter health error was not marked after required heartbeat failure")
	}
	err = e.Emit(receipt.EmitOpts{
		ActionID:  receipt.NewActionID(),
		Verdict:   "allow",
		Transport: "fetch",
		Target:    "https://api.vendor.example/after-heartbeat-failure",
	})
	if err == nil || !strings.Contains(err.Error(), "receipt emitter unhealthy") {
		t.Fatalf("Emit after required heartbeat failure error = %v, want unhealthy", err)
	}
}

func TestRequiredCadenceHeartbeatFailureAfterAHealthyStartFailsClosed(t *testing.T) {
	// The sibling required-failure test closes the recorder BEFORE the scheduler
	// starts, so its failure now lands on the immediate beat and the cadence
	// branch it used to cover became unreachable from it. This covers the
	// remaining direction: a session that starts healthy and loses its recorder
	// later, which is what a full disk or a revoked key looks like in production.
	// It must fail closed there too, not just at startup.
	dir := t.TempDir()
	_, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	rec, err := recorder.New(recorder.Config{
		Enabled:            true,
		Dir:                dir,
		CheckpointInterval: 1000,
	}, nil, priv)
	if err != nil {
		t.Fatalf("recorder.New: %v", err)
	}

	beats := make(chan struct{}, 8)
	e := receipt.NewEmitter(receipt.EmitterConfig{
		Recorder: rec,
		PrivKey:  priv,
		OnReceipt: func(rcpt *receipt.Receipt) {
			if sc := rcpt.ActionRecord.SessionControl; sc != nil && sc.Heartbeat != nil {
				select {
				case beats <- struct{}{}:
				default:
				}
			}
		},
	})
	if err := e.EmitSessionOpen(); err != nil {
		t.Fatalf("EmitSessionOpen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	var log bytes.Buffer
	requiredFailure := make(chan error, 1)
	startReceiptHeartbeat(ctx, &wg, time.Millisecond, func() *receipt.Emitter { return e }, &log, true, func(err error) {
		select {
		case requiredFailure <- err:
		default:
		}
		cancel()
	})
	defer wg.Wait()

	// The immediate beat must land first: without it, closing the recorder below
	// would race the startup emission and this could pass on the wrong branch.
	select {
	case <-beats:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the immediate heartbeat")
	}

	if err := rec.Close(); err != nil {
		t.Fatalf("recorder.Close: %v", err)
	}

	select {
	case err := <-requiredFailure:
		if err == nil {
			t.Fatal("cadence heartbeat failure callback received nil error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for a required cadence heartbeat failure")
	}
	if e.HealthError() == nil {
		t.Fatal("emitter health error was not marked after a required cadence heartbeat failure")
	}
}

func TestOptionalReceiptHeartbeatFailureKeepsEmitterHealthy(t *testing.T) {
	dir := t.TempDir()
	_, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	rec, err := recorder.New(recorder.Config{
		Enabled:            true,
		Dir:                dir,
		CheckpointInterval: 1000,
	}, nil, priv)
	if err != nil {
		t.Fatalf("recorder.New: %v", err)
	}

	e := receipt.NewEmitter(receipt.EmitterConfig{
		Recorder: rec,
		PrivKey:  priv,
	})
	if err := e.EmitSessionOpen(); err != nil {
		t.Fatalf("EmitSessionOpen: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("recorder.Close: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	log := newHeartbeatFailureLog()
	requiredFailure := make(chan error, 1)
	startReceiptHeartbeat(ctx, &wg, time.Millisecond, func() *receipt.Emitter { return e }, log, false, func(err error) {
		requiredFailure <- err
	})
	defer wg.Wait()
	defer cancel()

	first := waitForHeartbeatFailureLog(t, log.seen)
	second := waitForHeartbeatFailureLog(t, log.seen)
	cancel()

	if !strings.Contains(first, "receipt heartbeat emit failed") || !strings.Contains(second, "receipt heartbeat emit failed") {
		t.Fatalf("heartbeat logs = %q, %q; want repeated failure logs", first, second)
	}
	if err := e.HealthError(); err != nil {
		t.Fatalf("HealthError() = %v, want nil for optional heartbeat failure", err)
	}
	select {
	case err := <-requiredFailure:
		t.Fatalf("required failure callback called for optional heartbeat failure: %v", err)
	default:
	}
}

func waitForHeartbeatReceipt(t *testing.T, seen <-chan receipt.Receipt) {
	t.Helper()
	for {
		select {
		case r := <-seen:
			sc := r.ActionRecord.SessionControl
			if sc != nil && sc.Heartbeat != nil {
				return
			}
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for heartbeat receipt")
		}
	}
}

func waitForHeartbeatFailureLog(t *testing.T, seen <-chan string) string {
	t.Helper()
	select {
	case msg := <-seen:
		return msg
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for heartbeat failure log")
		return ""
	}
}

func readRuntimeReceipts(t *testing.T, dir, expectedKey string) []receipt.Receipt {
	t.Helper()
	entries, err := recorder.ReadEntries(filepath.Join(dir, "evidence-proxy-0.jsonl"))
	if err != nil {
		t.Fatalf("ReadEntries: %v", err)
	}
	var out []receipt.Receipt
	for _, entry := range entries {
		if entry.Type != "action_receipt" {
			continue
		}
		raw, err := json.Marshal(entry.Detail)
		if err != nil {
			t.Fatalf("json.Marshal(receipt): %v", err)
		}
		r, err := receipt.Unmarshal(raw)
		if err != nil {
			t.Fatalf("receipt.Unmarshal: %v", err)
		}
		if err := receipt.VerifyWithKey(r, expectedKey); err != nil {
			t.Fatalf("VerifyWithKey: %v", err)
		}
		out = append(out, r)
	}
	return out
}

func readRuntimeTranscriptRoot(t *testing.T, dir string) receipt.TranscriptRoot {
	t.Helper()
	entries, err := recorder.ReadEntries(filepath.Join(dir, "evidence-proxy-0.jsonl"))
	if err != nil {
		t.Fatalf("ReadEntries: %v", err)
	}
	for _, entry := range entries {
		if entry.Type != "transcript_root" {
			continue
		}
		raw, err := json.Marshal(entry.Detail)
		if err != nil {
			t.Fatalf("json.Marshal(root): %v", err)
		}
		var root receipt.TranscriptRoot
		if err := json.Unmarshal(raw, &root); err != nil {
			t.Fatalf("json.Unmarshal(root): %v", err)
		}
		return root
	}
	t.Fatal("transcript root not found")
	return receipt.TranscriptRoot{}
}
