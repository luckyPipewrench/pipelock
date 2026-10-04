// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"context"
	"encoding/hex"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestEmitterReceiptScanRejectsDirtyDetailBeforeChainAdvance(t *testing.T) {
	for _, tc := range []struct {
		name    string
		durable bool
	}{
		{name: "best effort"},
		{name: "durable", durable: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var wholeReceiptScans atomic.Int64
			dlp := func(_ context.Context, text string) scanner.TextDLPResult {
				if strings.Contains(text, `"action_record"`) {
					wholeReceiptScans.Add(1)
				}
				return scanner.TextDLPResult{Clean: !strings.Contains(text, "test-sensitive-value")}
			}
			dir := t.TempDir()
			pub, priv := generateTestKey(t)
			rec := newRedactingRecorder(t, dir, priv, dlp)
			defer func() { _ = rec.Close() }()
			e := NewEmitter(EmitterConfig{
				Recorder: rec, PrivKey: priv, ConfigHash: testConfigHash,
				Principal: testPrincipal, Actor: testActor,
			})
			emit := e.Emit
			if tc.durable {
				emit = e.EmitDurable
			}
			opts := EmitOpts{
				ActionID: NewActionID(), Target: testTarget, Verdict: config.ActionAllow,
				Transport: testTransport, Method: http.MethodGet, Agent: "test-sensitive-value",
			}
			if err := emit(opts); err == nil || !strings.Contains(err.Error(), "refusing to record unverifiable redaction") {
				t.Fatalf("dirty receipt error = %v", err)
			}
			if state, ok := e.HealthSnapshot(); !ok || state.ChainSeq != 0 {
				t.Fatalf("chain advanced after dirty receipt: %+v, available=%t", state, ok)
			}
			opts.ActionID = NewActionID()
			opts.Agent = "safe-actor"
			if err := emit(opts); err != nil {
				t.Fatalf("clean receipt: %v", err)
			}
			if got := wholeReceiptScans.Load(); got != 2 {
				t.Fatalf("whole-receipt DLP scans = %d, want one per attempted receipt", got)
			}
			if err := rec.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			receipts := readReceiptsRaw(t, dir)
			if len(receipts) != 1 || receipts[0].ActionRecord.ChainSeq != 0 {
				t.Fatalf("recorded receipts = %+v, want one clean genesis receipt", receipts)
			}
			if err := VerifyWithKey(receipts[0], hex.EncodeToString(pub)); err != nil {
				t.Fatalf("VerifyWithKey: %v", err)
			}
		})
	}
}
