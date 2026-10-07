// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	guardfs "github.com/luckyPipewrench/pipelock/internal/guard"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

func TestBuildServerReceiptShardGroupPublishesBoundStartup(t *testing.T) {
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
	template := receipt.EmitterConfig{
		Recorder: rec, PrivKey: key, ConfigHash: strings.Repeat("a", 64),
		Principal: "local", Actor: "pipelock",
	}
	shards, opts, err := buildServerReceiptShardGroup(template, 2, filepath.Join(dir, "signer.key"), false)
	if err != nil {
		t.Fatalf("construct server receipt group: %v", err)
	}
	if len(opts) != 3 || shards.ProcessEmitter() == nil {
		t.Fatalf("startup options=%d process emitter=%v", len(opts), shards.ProcessEmitter())
	}
	opening, digest := shards.Opening()
	if opening.ShardCount != 2 || len(opening.Shards) != 2 || digest == "" {
		t.Fatalf("opening = %+v, digest = %q", opening, digest)
	}
	if opening.Shards[0].SessionID != shards.ProcessEmitter().Session() {
		t.Fatal("process emitter does not use the declared process shard")
	}
	for _, shard := range opening.Shards {
		paths, err := filepath.Glob(filepath.Join(dir, "evidence-"+shard.SessionID+"-*.jsonl"))
		if err != nil || len(paths) != 1 {
			t.Fatalf("shard %d evidence: %v, %v", shard.ShardIndex, paths, err)
		}
	}
	(&Server{receiptShardSet: shards}).sealTranscriptRoot()
	for _, shard := range opening.Shards {
		paths, _ := filepath.Glob(filepath.Join(dir, "evidence-"+shard.SessionID+"-*.jsonl"))
		entries, err := recorder.ReadEntries(paths[0])
		if err != nil {
			t.Fatal(err)
		}
		var closeSeen, rootSeen bool
		for _, entry := range entries {
			if entry.Type == "action_receipt" && strings.Contains(string(entry.RawDetail), "session_close") {
				closeSeen = true
			}
			if entry.Type == "transcript_root" {
				rootSeen = true
			}
		}
		if !closeSeen || !rootSeen {
			t.Fatalf("shard %d lifecycle close=%v root=%v", shard.ShardIndex, closeSeen, rootSeen)
		}
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, SignCheckpoints: true}, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restarted.Close() })
	template.Recorder = restarted
	successor, _, err := buildServerReceiptShardGroup(template, 2, filepath.Join(dir, "signer.key"), false)
	if err != nil {
		t.Fatalf("restart receipt group: %v", err)
	}
	successorOpen, _ := successor.Opening()
	if successorOpen.PreviousGroupID != opening.GroupID {
		t.Fatalf("restart lost predecessor binding: %+v", successorOpen)
	}
	(&Server{receiptShardSet: successor}).sealTranscriptRoot()
	if err := restarted.Close(); err != nil {
		t.Fatal(err)
	}
	if result := receipt.VerifyReceiptGroup(dir, successorOpen.GroupID, []string{successorOpen.SignerKey}); result.Verdict != receipt.GroupValid {
		t.Fatalf("restarted group verdict = %+v", result)
	}
}

func TestReceiptGroupKeyFileRotationClosesBeforeRestart(t *testing.T) {
	_, oldKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, newKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyPath := filepath.Join(t.TempDir(), "receipt.key")
	if err := signing.SavePrivateKey(oldKey, keyPath); err != nil {
		t.Fatal(err)
	}
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, SignCheckpoints: true}, nil, oldKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	template := receipt.EmitterConfig{Recorder: rec, PrivKey: oldKey, ConfigHash: strings.Repeat("a", 64), Principal: "local", Actor: "pipelock"}
	shards, _, err := buildServerReceiptShardGroup(template, 2, keyPath, false)
	if err != nil {
		t.Fatal(err)
	}
	oldOpen, _ := shards.Opening()
	s, log := newTestServer(t, nil)
	s.receiptShardSet = shards
	live := s.proxy.CurrentConfig()
	live.FlightRecorder.SigningKeyPath = keyPath
	live.FlightRecorder.ReceiptChains = 2
	ctx, cancel := context.WithCancel(context.Background())
	s.cancelMu.Lock()
	s.internalCancel = cancel
	s.cancelMu.Unlock()
	if err := signing.SavePrivateKey(newKey, keyPath); err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(live.Clone()); !errors.Is(err, errReceiptGroupKeyRotation) {
		t.Fatalf("rotation reload = %v", err)
	}
	if ctx.Err() == nil || !s.receiptRotationRequested.Load() || !strings.Contains(log.String(), "receipt_chains=2") {
		t.Fatalf("rotation did not cancel with named reason: ctx=%v log=%q", ctx.Err(), log.String())
	}
	s.sealTranscriptRoot()
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, SignCheckpoints: true}, nil, newKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restarted.Close() })
	template.Recorder, template.PrivKey = restarted, newKey
	successor, _, err := buildServerReceiptShardGroup(template, 2, keyPath, false)
	if err != nil {
		t.Fatal(err)
	}
	newOpen, _ := successor.Opening()
	if newOpen.PreviousGroupID != oldOpen.GroupID || newOpen.SignerKey == oldOpen.SignerKey {
		t.Fatalf("successor did not bind old group under new key: old=%+v new=%+v", oldOpen, newOpen)
	}
	(&Server{receiptShardSet: successor}).sealTranscriptRoot()
	if err := restarted.Close(); err != nil {
		t.Fatal(err)
	}
	if got := receipt.VerifyReceiptGroup(dir, newOpen.GroupID, []string{oldOpen.SignerKey, newOpen.SignerKey}).Verdict; got != receipt.GroupValid {
		t.Fatalf("successor verdict = %s", got)
	}
}

func TestReceiptGroupRotationCloseFailureLeavesIncomplete(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, nextKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyPath := filepath.Join(t.TempDir(), "receipt.key")
	if err := signing.SavePrivateKey(key, keyPath); err != nil {
		t.Fatal(err)
	}
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, SignCheckpoints: true}, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	shards, _, err := buildServerReceiptShardGroup(receipt.EmitterConfig{
		Recorder: rec, PrivKey: key, ConfigHash: strings.Repeat("a", 64), Principal: "local", Actor: "pipelock",
	}, 2, keyPath, false)
	if err != nil {
		t.Fatal(err)
	}
	opening, _ := shards.Opening()
	s, _ := newTestServer(t, nil)
	s.receiptShardSet = shards
	live := s.proxy.CurrentConfig()
	live.FlightRecorder.SigningKeyPath = keyPath
	live.FlightRecorder.ReceiptChains = 2
	ctx, cancel := context.WithCancel(context.Background())
	s.cancelMu.Lock()
	s.internalCancel = cancel
	s.cancelMu.Unlock()
	if err := signing.SavePrivateKey(nextKey, keyPath); err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(live.Clone()); !errors.Is(err, errReceiptGroupKeyRotation) || ctx.Err() == nil {
		t.Fatalf("close-failure rotation did not request process exit: err=%v ctx=%v", err, ctx.Err())
	}
	shards.Emitters()[0].MarkUnhealthy(errors.New("injected shard close failure"))
	s.sealTranscriptRoot()
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	if got := receipt.VerifyReceiptGroup(dir, opening.GroupID, []string{opening.SignerKey}).Verdict; got != receipt.GroupIncomplete {
		t.Fatalf("failed close verdict = %s, want %s", got, receipt.GroupIncomplete)
	}
}

func TestGuardReceiptGroupOpensAfterEnforcementProof(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyPath := filepath.Join(t.TempDir(), "signer.key")
	if err := signing.SavePrivateKey(key, keyPath); err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.FlightRecorder.Enabled = true
	cfg.FlightRecorder.Dir = dir
	cfg.FlightRecorder.SigningKeyPath = keyPath
	cfg.FlightRecorder.ReceiptChains = 2
	cfg.FlightRecorder.Redact = false
	cfg.FlightRecorder.RequireReceipts = true
	var log bytes.Buffer
	evidence, err := newGuardEvidence(context.Background(), cfg, nil, metrics.New(), &log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(evidence.close)
	if evidence.shards == nil || evidence.emitter == nil {
		t.Fatal("Guard did not prepare its receipt group")
	}
	evidence.onRequiredFailure = func(error) {}
	proof := guardfs.ExecutionProof{
		ConfigPolicyHash:    strings.Repeat("b", 64),
		EffectivePolicyHash: strings.Repeat("c", 64),
		Binary:              "/bin/true",
	}
	if err := evidence.activate(proof); err != nil {
		t.Fatalf("activate Guard receipts: %v", err)
	}
	for i := range 2 {
		opts := evidence.shards.Admit(receipt.EmitOpts{
			ActionID: receipt.NewActionID(), Verdict: config.ActionAllow,
			Transport: "guard", Target: "guard-session",
		})
		if opts.ShardIndex != i {
			t.Fatalf("Guard admission %d selected shard %d", i, opts.ShardIndex)
		}
		if err := evidence.shards.EmitDurable(opts); err != nil {
			t.Fatalf("Guard shard %d action: %v", i, err)
		}
	}
	evidence.close()
	opening, _ := evidence.shards.Opening()
	for _, shard := range opening.Shards {
		paths, _ := filepath.Glob(filepath.Join(dir, "evidence-"+shard.SessionID+"-*.jsonl"))
		if len(paths) != 1 {
			t.Fatalf("shard %d has %d files", shard.ShardIndex, len(paths))
		}
		entries, err := recorder.ReadEntries(paths[0])
		if err != nil {
			t.Fatal(err)
		}
		var opened, closed bool
		var actions int
		for _, entry := range entries {
			if entry.Type == "action_receipt" && strings.Contains(string(entry.RawDetail), "session_open") {
				opened = true
			}
			if entry.Type == "action_receipt" && strings.Contains(string(entry.RawDetail), "session_close") {
				closed = true
			}
			if entry.Type == "action_receipt" && strings.Contains(string(entry.RawDetail), "guard-session") {
				actions++
			}
		}
		if !opened || !closed || actions != 1 {
			t.Fatalf("Guard shard %d opened=%v closed=%v actions=%d", shard.ShardIndex, opened, closed, actions)
		}
	}
	aelRuns, err := filepath.Glob(filepath.Join(dir, "ael", "*", "recorders", "pipelock.jsonl"))
	if err != nil || len(aelRuns) != 2 {
		t.Fatalf("Guard native AEL shard streams=%v err=%v", aelRuns, err)
	}
}

func TestBuildServerReceiptShardGroupDefersGuardOpensUntilProof(t *testing.T) {
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
	shards, _, err := buildServerReceiptShardGroup(receipt.EmitterConfig{
		Recorder: rec, PrivKey: key, ConfigHash: strings.Repeat("a", 64),
		Principal: "local", Actor: "pipelock",
	}, 2, filepath.Join(dir, "signer.key"), true)
	if err != nil {
		t.Fatal(err)
	}
	opening, _ := shards.Opening()
	for _, shard := range opening.Shards {
		paths, _ := filepath.Glob(filepath.Join(dir, "evidence-"+shard.SessionID+"-*.jsonl"))
		entries, err := recorder.ReadEntries(paths[0])
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if entry.Type == "action_receipt" {
				t.Fatalf("shard %d opened before proof", shard.ShardIndex)
			}
		}
	}
	if err := shards.Activate(strings.Repeat("b", 64)); err != nil {
		t.Fatal(err)
	}
	for _, shard := range opening.Shards {
		paths, _ := filepath.Glob(filepath.Join(dir, "evidence-"+shard.SessionID+"-*.jsonl"))
		entries, err := recorder.ReadEntries(paths[0])
		if err != nil {
			t.Fatal(err)
		}
		var opens int
		for _, entry := range entries {
			if entry.Type == "action_receipt" && strings.Contains(string(entry.RawDetail), "session_open") {
				opens++
			}
		}
		if opens != 1 {
			t.Fatalf("shard %d has %d session opens after proof", shard.ShardIndex, opens)
		}
	}
}
