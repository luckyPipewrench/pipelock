// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"io"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/deferred"
)

func TestDeferredReleaseCorrectiveReceiptPrecedesTerminalJournal(t *testing.T) {
	h := newMCPDecisionReceiptHarness(t)
	opts := MCPProxyOpts{
		ReceiptEmitter: h.v1, V2ReceiptEmitter: h.v2,
		RequireReceipts: true, PolicyHash: mcpTestPolicyHash, Transport: deferred.SurfaceMCPStdio,
	}
	var settlement deferredReceiptSettlement
	writes := 0
	manager := deferred.NewManager(deferred.Config{
		Enabled: true, JournalPath: filepath.Join(t.TempDir(), "journal.jsonl"),
		JournalWriteGuard: func(write func() error) error {
			writes++
			if writes == 3 {
				return io.ErrClosedPipe
			}
			if writes == 4 && (!settlement.done || settlement.decision != config.ActionBlock) {
				t.Fatal("terminal block attempted before corrective receipt")
			}
			return write()
		},
	})
	if err := manager.Hold(deferred.HeldAction{
		DeferID: "held", ActionID: "held", Target: "tool", Method: "tools/call",
		AfterJournal: func(res deferred.Resolution) error { return settlement.commitAllow(opts, io.Discard, res) },
		Resolve: func(res deferred.Resolution) {
			if res.FinalDecision != config.ActionBlock {
				t.Fatalf("final = %s, want block", res.FinalDecision)
			}
			if err := settlement.ensure(opts, io.Discard, res); err != nil {
				t.Fatal(err)
			}
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := manager.Resolve("held", config.ActionAllow, deferred.SourceOperator); err != nil {
		t.Fatal(err)
	}
	if err := h.rec.Close(); err != nil {
		t.Fatal(err)
	}
	for i, r := range readActionReceipts(t, h.dir) {
		want := config.ActionAllow
		if i == 1 {
			want = config.ActionBlock
		}
		if i > 1 || r.ActionRecord.Verdict != want {
			t.Fatalf("receipt %d verdict = %s, want %s", i, r.ActionRecord.Verdict, want)
		}
	}
	if records := readActionReceipts(t, h.dir); len(records) != 2 {
		t.Fatalf("resolution receipts = %d, want 2 with no duplicate from Resolve", len(records))
	}
	if pending, err := deferred.PendingJournal(manager.JournalPath()); err != nil || len(pending) != 0 {
		t.Fatalf("pending = %d, err=%v; want 0", len(pending), err)
	}
}
