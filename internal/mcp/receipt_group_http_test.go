// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/contract/proxydecision"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func TestMCPHTTPGroupAdmissionAndAsyncOutcomeStayOnShard(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, SignCheckpoints: true}, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	shards, err := receipt.OpenInitialReceiptShardSet(receipt.EmitterConfig{
		Recorder: rec, PrivKey: key, ConfigHash: mcpTestPolicyHash,
		Principal: "local", Actor: "pipelock",
	}, "proxy", 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	opening, _ := shards.Opening()
	group := &MCPReceiptGroup{Shards: shards, V2: make([]*proxydecision.Emitter, 2)}
	for i, shard := range opening.Shards {
		group.V2[i] = proxydecision.NewEmitter(proxydecision.EmitterConfig{
			Recorder: rec, Signer: proxydecision.NewKeyedSigner(key),
			Principal: "local", Actor: "pipelock", Session: shard.SessionID,
		})
	}
	opts := MCPProxyOpts{
		Scanner: testScannerForHTTP(t), ReceiptGroup: group,
		ReceiptEmitter: shards.ProcessEmitter(), V2ReceiptEmitter: group.V2[0],
		PolicyHash: mcpTestPolicyHash, RequireReceipts: true, Transport: "mcp_http",
	}
	for i := range 2 {
		msg := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fetch","arguments":{}}}`)
		decision := scanHTTPInputDecision(msg, io.Discard, "sess", "sess", opts)
		if decision.Blocked != nil || decision.Outcome.Receipt.ShardIndex != i || !decision.Outcome.Receipt.ShardSelected {
			t.Fatalf("request %d blocked=%+v outcome shard=%+v", i, decision.Blocked, decision.Outcome.Receipt)
		}
		emitMCPOutcomeReceipt(nil, nil, group, io.Discard, decision.Outcome.Receipt, "ok", 10, "complete", true)
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	for i, shard := range opening.Shards {
		paths, globErr := filepath.Glob(filepath.Join(dir, "evidence-"+shard.SessionID+"-*.jsonl"))
		if globErr != nil || len(paths) != 1 {
			t.Fatalf("shard %d paths=%v err=%v", i, paths, globErr)
		}
		entries, readErr := recorder.ReadEntries(paths[0])
		if readErr != nil {
			t.Fatal(readErr)
		}
		var v1, v2 int
		for _, entry := range entries {
			switch entry.Type {
			case "action_receipt":
				v1++
			case "evidence_receipt":
				v2++
			}
		}
		if v1 != 3 || v2 != 2 { // session_open, request and outcome
			t.Fatalf("shard %d v1=%d v2=%d, want 3/2", i, v1, v2)
		}
	}
}
