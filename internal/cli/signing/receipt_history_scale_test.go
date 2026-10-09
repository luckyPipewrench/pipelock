// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// writeUnrelatedSessions adds sessions, sidecars and empty files that belong
// to no verified chain.
func writeUnrelatedSessions(t *testing.T, dir string, count int) {
	t.Helper()
	for i := range count {
		other := fmt.Sprintf("unrelated%03d", i)
		for _, name := range []string{
			"evidence-" + other + "-0.jsonl",
			"chain-link-" + other + ".json",
			"stray-" + other,
		} {
			if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// writeLongSealedChain writes one sealed single-chain recorder whose session
// spans more shards than the display directory budget holds.
func writeLongSealedChain(t *testing.T, receipts int) (string, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := physicalTempDir(t)
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, SignCheckpoints: true, MaxEntriesPerFile: 1}, nil, priv)
	if err != nil {
		t.Fatalf("recorder.New: %v", err)
	}
	emitter := receipt.NewEmitter(receipt.EmitterConfig{Recorder: rec, PrivKey: priv, ConfigHash: "test-chain-hash", Principal: "test", Actor: "test"})
	if err := emitter.EmitSessionOpen(); err != nil {
		t.Fatalf("EmitSessionOpen: %v", err)
	}
	for range receipts {
		if err := emitter.Emit(receipt.EmitOpts{ActionID: receipt.NewActionID(), Verdict: "allow", Transport: "fetch", Method: "GET", Target: "https://api.vendor.example/data"}); err != nil {
			t.Fatalf("Emit: %v", err)
		}
	}
	if err := emitter.EmitTranscriptRoot("proxy"); err != nil {
		t.Fatalf("EmitTranscriptRoot: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return dir, hex.EncodeToString(pub)
}

// TestVerifyReceiptCmd_ChainPastDisplayBudgetVerifies reproduces a single
// chain that outgrew the display directory budget: whole-recorder and
// receipt-chain verification both read its complete history, and unrelated
// files beside it change nothing.
func TestVerifyReceiptCmd_ChainPastDisplayBudgetVerifies(t *testing.T) {
	if testing.Short() {
		t.Skip("writes a recorder with hundreds of shards")
	}
	t.Parallel()
	dir, key := writeLongSealedChain(t, 730)
	shards, err := filepath.Glob(filepath.Join(dir, "evidence-proxy-*.jsonl"))
	if err != nil || len(shards) < 730 {
		t.Fatalf("fixture has %d shards, want at least 730: %v", len(shards), err)
	}
	t.Logf("single-chain recorder has %d evidence files", len(shards))
	writeUnrelatedSessions(t, dir, 300)

	// Control: the bounded display reader cannot read this session.
	if result, err := recorder.QuerySession(dir, "proxy", nil); err == nil && !result.Truncated {
		t.Fatal("display control read the whole session; the fixture does not exercise the budget")
	}

	out, err := runVerifyReceipt(t, "--chain", dir, "--whole-recorder", "--require-seal", "--key", key)
	if err != nil || strings.Contains(out, "INCOMPLETE") {
		t.Fatalf("whole-recorder verification of a long chain failed: %v\n%s", err, out)
	}
	out, err = runVerifyReceipt(t, "--chain", dir, "--key", key)
	if err != nil || !strings.Contains(out, "CHAIN VALID") {
		t.Fatalf("receipt-chain verification of a long chain failed: %v\n%s", err, out)
	}
}
