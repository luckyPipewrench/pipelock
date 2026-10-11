// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/receiptcontent"
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
			// The detector must never see signed material: the wedge came from
			// scanning Pipelock's own signature, key and chain hash.
			var signedMaterialScans atomic.Int64
			dlp := func(_ context.Context, text string) scanner.TextDLPResult {
				if strings.Contains(text, "ed25519:") || strings.Contains(text, "chain_prev_hash") {
					signedMaterialScans.Add(1)
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
				Transport: testTransport, Method: http.MethodGet, RequestID: "req-test-sensitive-value",
			}
			// An identity field is never redacted: a hit is a typed content
			// rejection that leaves the chain and the emitter's health intact.
			if err := emit(opts); !errors.Is(err, receiptcontent.ErrRejected) || !strings.Contains(err.Error(), "action_record.request_id") {
				t.Fatalf("dirty identity error = %v, want typed content rejection naming the field", err)
			}
			if state, ok := e.HealthSnapshot(); !ok || state.ChainSeq != 0 {
				t.Fatalf("chain advanced after dirty receipt: %+v, available=%t", state, ok)
			}
			if e.HealthError() != nil {
				t.Fatalf("content rejection poisoned the emitter: %v", e.HealthError())
			}
			opts.ActionID = NewActionID()
			opts.RequestID = "req-safe"
			if err := emit(opts); err != nil {
				t.Fatalf("clean receipt after content rejection: %v", err)
			}
			if got := signedMaterialScans.Load(); got != 0 {
				t.Fatalf("detector saw signed material %d times; want 0", got)
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
