// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/deferred"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// crashDuringRelease holds one call and makes the process "die" while its
// allow receipt is being written, leaving the release pending in the journal.
func crashDuringRelease(t *testing.T, dir string) *deferred.Manager {
	t.Helper()
	cfg := config.Defaults()
	cfg.Defer.Enabled = true
	cfg.FlightRecorder.Dir = dir
	manager := buildDeferManager(cfg, nil)
	if manager == nil {
		t.Fatal("buildDeferManager returned nil")
	}
	if err := manager.Hold(deferred.HeldAction{
		DeferID: "d1", ActionID: "a1", Target: "dangerous_tool",
		Surface: deferred.SurfaceMCPStdio, Method: "tools/call", Reason: "policy", SizeBytes: 1,
		Authority:    deferred.AuthoritySnapshot{SessionID: "sess", SessionIDOriginal: "sess"},
		AfterJournal: func(deferred.Resolution) error { panic("simulated crash") },
		Resolve:      func(deferred.Resolution) { t.Fatal("held call was released") },
	}); err != nil {
		t.Fatalf("Hold: %v", err)
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("crash hook did not run")
			}
		}()
		_ = manager.Resolve("d1", config.ActionAllow, deferred.SourceOperator)
	}()
	return manager
}

func recoveryEmitter(t *testing.T, dir string, sync func(*os.File) error) *receipt.Emitter {
	t.Helper()
	_, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, CheckpointInterval: 1000}, nil, priv)
	if err != nil {
		t.Fatalf("recorder.New: %v", err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	if sync != nil {
		rec.SetSyncForTest(sync)
	}
	return receipt.NewEmitter(receipt.EmitterConfig{
		Recorder: rec, PrivKey: priv, ConfigHash: "config-hash", Principal: "local", Actor: "pipelock",
	})
}

// TestRecoverDeferredActionsClosesInterruptedRelease is the restart after a
// crash between journaling a release and writing its allow receipt: recovery
// writes a block resolution receipt linked to the held call and closes the hold.
func TestRecoverDeferredActionsClosesInterruptedRelease(t *testing.T) {
	dir := t.TempDir()
	manager := crashDuringRelease(t, dir)
	if pending, err := deferred.PendingJournal(manager.JournalPath()); err != nil || len(pending) != 1 {
		t.Fatalf("pending before recovery = %d err=%v, want 1", len(pending), err)
	}

	receiptsDir := filepath.Join(dir, "receipts")
	var log bytes.Buffer
	if err := recoverDeferredActions(manager, manager.JournalPath(), recoveryEmitter(t, receiptsDir, nil), nil, runtimeTestPolicyHash, &log); err != nil {
		t.Fatalf("recoverDeferredActions: %v", err)
	}
	if log.Len() != 0 {
		t.Fatalf("recovery log = %q, want empty", log.String())
	}
	if pending, err := deferred.PendingJournal(manager.JournalPath()); err != nil || len(pending) != 0 {
		t.Fatalf("pending after recovery = %d err=%v, want 0", len(pending), err)
	}
	records := readRuntimeActionRecords(t, receiptsDir)
	if len(records) != 1 {
		t.Fatalf("recovery receipts = %d, want 1", len(records))
	}
	r := records[0]
	if r.Verdict != config.ActionBlock || r.DecisionPhase != receipt.DecisionPhaseResolution ||
		r.ResolutionSource != deferred.SourceRestartRecovery || r.ParentActionID != "a1" || r.PolicyHash != runtimeTestPolicyHash {
		t.Fatalf("recovery receipt = %+v, want block restart_recovery resolution of a1", r)
	}
}

// TestRecoverDeferredActionsKeepsHoldWhenReceiptNotDurable checks the recovery
// receipt is synced before the journal closes the hold. If it cannot be synced,
// recovery fails and the hold stays pending for the next start, rather than a
// closed hold whose only receipt could still be lost.
func TestRecoverDeferredActionsKeepsHoldWhenReceiptNotDurable(t *testing.T) {
	dir := t.TempDir()
	manager := crashDuringRelease(t, dir)
	emitter := recoveryEmitter(t, filepath.Join(dir, "receipts"), func(*os.File) error {
		return errors.New("injected sync failure")
	})
	var log bytes.Buffer
	err := recoverDeferredActions(manager, manager.JournalPath(), emitter, nil, runtimeTestPolicyHash, &log)
	if err == nil {
		t.Fatal("recoverDeferredActions succeeded with an unsynced recovery receipt")
	}
	if pending, err := deferred.PendingJournal(manager.JournalPath()); err != nil || len(pending) != 1 {
		t.Fatalf("pending after failed recovery = %d err=%v, want the hold still pending", len(pending), err)
	}
}
