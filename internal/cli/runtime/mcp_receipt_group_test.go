// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func TestBuildMCPReceiptGroupPairsBothWritersPerShard(t *testing.T) {
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
	group, err := buildMCPReceiptGroup(receipt.EmitterConfig{
		Recorder: rec, PrivKey: key, ConfigHash: "mcp-group-config",
		Principal: "local", Actor: "pipelock",
	}, 2)
	if err != nil {
		t.Fatal(err)
	}
	opening, _ := group.Shards.Opening()
	for i, shard := range opening.Shards {
		opts := group.Shards.Admit(receipt.EmitOpts{
			ActionID: receipt.NewActionID(), Verdict: config.ActionAllow,
			Transport: "mcp_stdio", Target: "fetch", MCPMethod: "tools/call", ToolName: "fetch",
			PolicyHash: "sha256:" + strings.Repeat("a", 64),
		})
		if opts.ShardIndex != i || group.Shards.Emitters()[i].Session() != shard.SessionID {
			t.Fatalf("admission %d selected shard %d, session %q", i, opts.ShardIndex, group.Shards.Emitters()[i].Session())
		}
		if _, err := mcp.EmitMCPGroupDecision(*group, nil, mcp.MCPDecision{Receipt: opts, RequireReceipt: true}); err != nil {
			t.Fatalf("emit shard %d pair: %v", i, err)
		}
		paths, globErr := filepath.Glob(filepath.Join(dir, "evidence-"+shard.SessionID+"-*.jsonl"))
		if globErr != nil || len(paths) != 1 {
			t.Fatalf("shard %d evidence files=%v err=%v", i, paths, globErr)
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
		if v1 != 2 || v2 != 1 { // session_open plus paired decision
			t.Fatalf("shard %d v1=%d v2=%d, want 2/1", i, v1, v2)
		}
	}
	aelRuns, err := filepath.Glob(filepath.Join(dir, "ael", "*", "recorders", "pipelock.jsonl"))
	if err != nil || len(aelRuns) != 2 {
		t.Fatalf("native AEL shard streams=%v err=%v, want two", aelRuns, err)
	}
	for _, shard := range group.Shards.Emitters() {
		if err := emitSessionCloseAndTranscriptRoot(shard, shard.Session()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := group.Shards.PublishClose(); err != nil {
		t.Fatal(err)
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, SignCheckpoints: true}, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restarted.Close() })
	successor, err := buildMCPReceiptGroup(receipt.EmitterConfig{
		Recorder: restarted, PrivKey: key, ConfigHash: "mcp-group-config",
		Principal: "local", Actor: "pipelock",
	}, 2)
	if err != nil {
		t.Fatal(err)
	}
	successorOpen, _ := successor.Shards.Opening()
	if successorOpen.PreviousGroupID != opening.GroupID {
		t.Fatalf("MCP restart lost predecessor: %+v", successorOpen)
	}
}
