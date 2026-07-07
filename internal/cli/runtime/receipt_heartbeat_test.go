// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

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
	startReceiptHeartbeat(ctx, &wg, time.Millisecond, func() *receipt.Emitter { return e }, &log)
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
	if len(receipts) < 3 {
		t.Fatalf("receipts = %d, want open heartbeat close", len(receipts))
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
