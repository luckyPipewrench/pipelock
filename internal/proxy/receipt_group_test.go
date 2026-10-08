// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/contract/proxydecision"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

type failingGroupDecisionRecorder struct{}

type sizeRejectGroupDecisionRecorder struct{ calls int }

func newReceiptFailureGroup(t *testing.T) (*recorder.Recorder, *receipt.ReceiptShardSet, *Proxy, *int) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: t.TempDir(), SignCheckpoints: true}, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	m := metrics.New()
	shards, err := receipt.OpenInitialReceiptShardSet(receipt.EmitterConfig{
		Recorder: rec, PrivKey: key, ConfigHash: strings.Repeat("a", 64),
		Principal: "local", Actor: "pipelock", Metrics: m,
	}, "proxy", 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	open, _ := shards.Opening()
	v2 := make([]*proxydecision.Emitter, len(open.Shards))
	for i, shard := range open.Shards {
		v2[i] = proxydecision.NewEmitter(proxydecision.EmitterConfig{
			Recorder: rec, Signer: proxydecision.NewKeyedSigner(key),
			Principal: "local", Actor: "pipelock", Session: shard.SessionID,
		})
	}
	cancels := 0
	option, err := WithReceiptShardSet(shards, v2, func(error) { cancels++ })
	if err != nil {
		t.Fatal(err)
	}
	p := &Proxy{logger: audit.NewNop(), metrics: m}
	option(p)
	return rec, shards, p, &cancels
}

func testReceiptFailureOpts() receipt.EmitOpts {
	return receipt.EmitOpts{
		ActionID: receipt.NewActionID(), Verdict: config.ActionAllow,
		Transport: "reverse", Method: http.MethodGet,
		Target:        "https://api.vendor.example/data",
		PolicyHash:    strings.Repeat("a", 64),
		ShardSelected: true, ShardIndex: 0,
	}
}

func TestReceiptGroupPreAdvanceRejectPreservesBestEffortHealth(t *testing.T) {
	_, shards, p, cancels := newReceiptFailureGroup(t)
	var emitter atomic.Pointer[receipt.Emitter]
	emitter.Store(shards.ProcessEmitter())
	rp := &ReverseProxyHandler{logger: audit.NewNop(), metrics: metrics.New(), receiptEmitterPtr: &emitter, owner: p}
	for _, emit := range []struct {
		name string
		call func(receipt.EmitOpts) error
	}{
		{"forward", func(opts receipt.EmitOpts) error { return p.emitReceiptWithEmitter(opts, emitter.Load()) }},
		{"reverse", func(opts receipt.EmitOpts) error { return rp.emitReceiptWithEmitter(opts, emitter.Load()) }},
	} {
		t.Run(emit.name, func(t *testing.T) {
			oversized := testReceiptFailureOpts()
			oversized.Target += strings.Repeat("x", recorder.MaxEntryLineBytes)
			if err := emit.call(oversized); err == nil {
				t.Fatal("oversized receipt accepted")
			}
			for i, shard := range shards.Emitters() {
				if err := shard.HealthError(); err != nil {
					t.Fatalf("shard %d unhealthy after pre-advance reject: %v", i, err)
				}
			}
			if *cancels != 0 {
				t.Fatalf("pre-advance reject cancelled group %d times", *cancels)
			}
			if err := emit.call(testReceiptFailureOpts()); err != nil {
				t.Fatalf("next receipt refused: %v", err)
			}
		})
	}
}

func TestReceiptGroupOutcomePreAdvanceRejectPreservesHealth(t *testing.T) {
	for _, direction := range []string{"forward", "reverse"} {
		t.Run(direction, func(t *testing.T) {
			_, shards, p, cancels := newReceiptFailureGroup(t)
			cfg := config.Defaults()
			cfg.FlightRecorder.RequireReceipts = true
			var cfgPtr atomic.Pointer[config.Config]
			cfgPtr.Store(cfg)
			var emitter atomic.Pointer[receipt.Emitter]
			emitter.Store(shards.ProcessEmitter())
			rp := &ReverseProxyHandler{logger: audit.NewNop(), metrics: metrics.New(), cfgPtr: &cfgPtr, receiptEmitterPtr: &emitter, owner: p}
			opts := testReceiptFailureOpts()
			before, ok := shards.Emitters()[opts.ShardIndex].HealthSnapshot()
			if !ok {
				t.Fatal("selected shard has no health snapshot")
			}
			emit := func(reason string) {
				if direction == "forward" {
					p.emitOutcomeReceipt(cfg, opts, "ok", 0, reason)
				} else {
					rp.emitOutcomeReceipt(cfg, opts, "ok", 0, reason)
				}
			}
			emit(strings.Repeat("x", recorder.MaxEntryLineBytes))
			afterReject, _ := shards.Emitters()[opts.ShardIndex].HealthSnapshot()
			if afterReject.ChainSeq != before.ChainSeq {
				t.Fatalf("size reject advanced chain from %d to %d", before.ChainSeq, afterReject.ChainSeq)
			}
			if *cancels != 0 {
				t.Fatalf("pre-advance outcome reject cancelled group %d times", *cancels)
			}
			for i, shard := range shards.Emitters() {
				if err := shard.HealthError(); err != nil {
					t.Fatalf("shard %d quarantined after size reject: %v", i, err)
				}
			}
			emit("complete")
			afterRetry, _ := shards.Emitters()[opts.ShardIndex].HealthSnapshot()
			if afterRetry.ChainSeq != before.ChainSeq+1 {
				t.Fatalf("healthy retry chain seq = %d, want %d", afterRetry.ChainSeq, before.ChainSeq+1)
			}
			if *cancels != 0 {
				t.Fatalf("healthy outcome cancelled group %d times", *cancels)
			}
		})
	}
}

func TestReceiptGroupBestEffortV2SizeRejectPreservesHealth(t *testing.T) {
	_, shards, p, cancels := newReceiptFailureGroup(t)
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sizeRecorder := &sizeRejectGroupDecisionRecorder{}
	group := p.receiptGroupPtr.Load()
	group.v2[0] = proxydecision.NewEmitter(proxydecision.EmitterConfig{
		Recorder: sizeRecorder, Signer: proxydecision.NewKeyedSigner(key),
		Principal: "local", Actor: "pipelock", Session: "proxy",
	})
	opts := testReceiptFailureOpts()
	if err := p.emitGroupV2Receipt(group, opts, false); !errors.Is(err, recorder.ErrSerializedEntryTooLarge) {
		t.Fatalf("v2 size reject = %v", err)
	}
	if *cancels != 0 || sizeRecorder.calls != 1 {
		t.Fatalf("best-effort v2 size reject cancelled=%d calls=%d", *cancels, sizeRecorder.calls)
	}
	for i, shard := range shards.Emitters() {
		if err := shard.HealthError(); err != nil {
			t.Fatalf("shard %d quarantined after v2 size reject: %v", i, err)
		}
	}
	if err := p.emitGroupV2Receipt(group, opts, false); err != nil {
		t.Fatalf("next v2 receipt refused: %v", err)
	}
}

func TestReverseReceiptGroupUnhealthyOrPostAdvanceFailureQuarantines(t *testing.T) {
	for _, outcome := range []bool{false, true} {
		t.Run(fmt.Sprintf("outcome=%t", outcome), func(t *testing.T) {
			rec, shards, p, cancels := newReceiptFailureGroup(t)
			cfg := config.Defaults()
			cfg.FlightRecorder.RequireReceipts = true
			var cfgPtr atomic.Pointer[config.Config]
			cfgPtr.Store(cfg)
			var emitter atomic.Pointer[receipt.Emitter]
			emitter.Store(shards.ProcessEmitter())
			rp := &ReverseProxyHandler{logger: audit.NewNop(), metrics: metrics.New(), cfgPtr: &cfgPtr, receiptEmitterPtr: &emitter, owner: p}
			if outcome {
				shards.Emitters()[0].MarkUnhealthy(errors.New("writer failed"))
				rp.emitOutcomeReceipt(cfg, testReceiptFailureOpts(), "ok", 4, "complete")
			} else {
				rec.SetSyncForTest(func(*os.File) error { return errors.New("injected sync failure") })
				if err := rp.emitRequiredReceiptWithEmitter(testReceiptFailureOpts(), emitter.Load()); !errors.Is(err, receipt.ErrReceiptPostAdvance) {
					t.Fatalf("intent error = %v, want post-advance failure", err)
				}
			}
			if *cancels != 1 {
				t.Fatalf("required failure cancelled group %d times, want 1", *cancels)
			}
			for i, shard := range shards.Emitters() {
				if shard.HealthError() == nil {
					t.Fatalf("shard %d remains healthy after required failure", i)
				}
			}
		})
	}
}

func (r *sizeRejectGroupDecisionRecorder) Record(recorder.Entry) error {
	r.calls++
	if r.calls == 1 {
		return recorder.ErrSerializedEntryTooLarge
	}
	return nil
}

func (r *sizeRejectGroupDecisionRecorder) RecordDurable(entry recorder.Entry) error {
	return r.Record(entry)
}

func (failingGroupDecisionRecorder) Record(recorder.Entry) error {
	return errors.New("decision write failed")
}

func (failingGroupDecisionRecorder) RecordDurable(recorder.Entry) error {
	return errors.New("decision durability failed")
}

func TestReceiptGroupPairsV1V2AndFailureMarkerOnAdmissionShard(t *testing.T) {
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
		Recorder: rec, PrivKey: key, ConfigHash: strings.Repeat("a", 64),
		Principal: "local", Actor: "pipelock",
	}, "proxy", 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	open, _ := shards.Opening()
	v2 := make([]*proxydecision.Emitter, 2)
	for i, shard := range open.Shards {
		v2[i] = proxydecision.NewEmitter(proxydecision.EmitterConfig{
			Recorder: rec, Signer: proxydecision.NewKeyedSigner(key),
			Principal: "local", Actor: "pipelock", Session: shard.SessionID,
		})
	}
	var requiredFailures int
	option, err := WithReceiptShardSet(shards, v2, func(error) { requiredFailures++ })
	if err != nil {
		t.Fatal(err)
	}
	p := &Proxy{logger: audit.NewNop(), metrics: metrics.New()}
	option(p)
	for i := range 2 {
		selected := p.admitReceiptShard()
		if !selected.ShardSelected || selected.ShardIndex != i {
			t.Fatalf("admission %d selected %+v", i, selected)
		}
		opts := withReceiptShard(receipt.EmitOpts{
			ActionID: receipt.NewActionID(), Verdict: config.ActionAllow,
			Transport: "forward", Method: "GET", Target: "https://api.vendor.example/data",
			PolicyHash: strings.Repeat("a", 64),
		}, selected)
		if err := p.emitRequiredReceiptWithEmitter(opts, p.receiptEmitterPtr.Load()); err != nil {
			t.Fatalf("shard %d required pair: %v", i, err)
		}
		if err := p.emitReceiptFailureMarker(p.receiptEmitterPtr.Load(), opts, "test failure", config.ActionBlock); err != nil {
			t.Fatalf("shard %d marker: %v", i, err)
		}
	}
	if err := p.emitRequiredReceiptWithEmitter(receipt.EmitOpts{Target: "https://api.vendor.example/data"}, p.receiptEmitterPtr.Load()); err == nil {
		t.Fatal("missing shard selection was accepted")
	}
	large := withReceiptShard(receipt.EmitOpts{
		ActionID: receipt.NewActionID(), Verdict: config.ActionAllow,
		Transport: "forward", Method: "GET", Target: "https://api.vendor.example/" + strings.Repeat("x", recorder.MaxEntryLineBytes),
		PolicyHash: strings.Repeat("a", 64),
	}, p.admitReceiptShard())
	if err := p.emitRequiredReceiptWithEmitter(large, p.receiptEmitterPtr.Load()); err == nil {
		t.Fatal("oversized pre-advance receipt was accepted")
	}
	if requiredFailures != 0 {
		t.Fatalf("pre-advance rejection cancelled required group %d times", requiredFailures)
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	for _, shard := range open.Shards {
		paths, err := filepath.Glob(filepath.Join(dir, "evidence-"+shard.SessionID+"-*.jsonl"))
		if err != nil || len(paths) != 1 {
			t.Fatalf("shard %d files: %v, %v", shard.ShardIndex, paths, err)
		}
		entries, err := recorder.ReadEntries(paths[0])
		if err != nil {
			t.Fatal(err)
		}
		var action, decision int
		for _, entry := range entries {
			if entry.Type == "action_receipt" {
				action++
			}
			if entry.Type == "evidence_receipt" {
				decision++
			}
		}
		if action != 3 || decision != 1 { // session_open, intent, marker; one v2 intent
			t.Fatalf("shard %d action=%d decision=%d", shard.ShardIndex, action, decision)
		}
	}
}

func TestRequiredReceiptGroupOutcomeFailureCancelsAfterResponse(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: t.TempDir(), SignCheckpoints: true}, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	shards, err := receipt.OpenInitialReceiptShardSet(receipt.EmitterConfig{
		Recorder: rec, PrivKey: key, ConfigHash: strings.Repeat("a", 64), Principal: "local", Actor: "pipelock",
	}, "proxy", 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	open, _ := shards.Opening()
	v2 := make([]*proxydecision.Emitter, 2)
	for i, shard := range open.Shards {
		v2[i] = proxydecision.NewEmitter(proxydecision.EmitterConfig{Recorder: rec, Signer: proxydecision.NewKeyedSigner(key), Principal: "local", Actor: "pipelock", Session: shard.SessionID})
	}
	var failures int
	option, err := WithReceiptShardSet(shards, v2, func(error) { failures++ })
	if err != nil {
		t.Fatal(err)
	}
	p := &Proxy{logger: audit.NewNop(), metrics: metrics.New()}
	option(p)
	cfg := config.Defaults()
	cfg.FlightRecorder.RequireReceipts = true
	p.cfgPtr.Store(cfg)
	shards.Emitters()[1].MarkUnhealthy(errors.New("writer failed"))
	p.emitOutcomeReceipt(cfg, receipt.EmitOpts{
		ActionID: receipt.NewActionID(), ShardSelected: true, ShardIndex: 1,
		Transport: "forward", Method: "GET", Target: "https://api.vendor.example/data",
	}, "200", 4, "complete")
	if failures != 1 {
		t.Fatalf("required outcome failure callback count = %d, want 1", failures)
	}
	for i, shard := range shards.Emitters() {
		if shard.HealthError() == nil {
			t.Fatalf("shard %d stayed healthy after missing outcome receipt", i)
		}
	}
}

func TestRequiredReceiptGroupStickyV2FailureCancels(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: t.TempDir(), SignCheckpoints: true}, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	shards, err := receipt.OpenInitialReceiptShardSet(receipt.EmitterConfig{
		Recorder: rec, PrivKey: key, ConfigHash: strings.Repeat("a", 64), Principal: "local", Actor: "pipelock",
	}, "proxy", 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	open, _ := shards.Opening()
	v2 := make([]*proxydecision.Emitter, 2)
	for i, shard := range open.Shards {
		var decisionRecorder proxydecision.Recorder = rec
		if i == 0 {
			decisionRecorder = failingGroupDecisionRecorder{}
		}
		v2[i] = proxydecision.NewEmitter(proxydecision.EmitterConfig{Recorder: decisionRecorder, Signer: proxydecision.NewKeyedSigner(key), Principal: "local", Actor: "pipelock", Session: shard.SessionID})
	}
	var failures int
	option, err := WithReceiptShardSet(shards, v2, func(error) { failures++ })
	if err != nil {
		t.Fatal(err)
	}
	p := &Proxy{logger: audit.NewNop(), metrics: metrics.New()}
	option(p)
	opts := receipt.EmitOpts{
		ActionID: receipt.NewActionID(), Verdict: config.ActionAllow,
		Transport: "forward", Method: "GET", Target: "https://api.vendor.example/data",
		PolicyHash: strings.Repeat("a", 64), ShardSelected: true, ShardIndex: 0,
	}
	if err := p.emitRequiredReceiptWithEmitter(opts, p.receiptEmitterPtr.Load()); err == nil {
		t.Fatal("sticky v2 receipt failure did not block request")
	}
	if failures != 1 || v2[0].HealthError() == nil {
		t.Fatalf("sticky v2 failure callback=%d health=%v", failures, v2[0].HealthError())
	}
	for i, shard := range shards.Emitters() {
		if shard.HealthError() == nil {
			t.Fatalf("shard %d stayed healthy after sticky v2 failure", i)
		}
	}
}

func TestRequiredReceiptGroupNativeAELFailureCancelsAllShards(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: t.TempDir(), SignCheckpoints: true}, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	shards, err := receipt.OpenInitialReceiptShardSet(receipt.EmitterConfig{
		Recorder: rec, PrivKey: key, ConfigHash: strings.Repeat("a", 64), Principal: "local", Actor: "pipelock",
	}, "proxy", 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	open, _ := shards.Opening()
	v2 := make([]*proxydecision.Emitter, 2)
	for i, shard := range open.Shards {
		v2[i] = proxydecision.NewEmitter(proxydecision.EmitterConfig{Recorder: rec, Signer: proxydecision.NewKeyedSigner(key), Principal: "local", Actor: "pipelock", Session: shard.SessionID})
	}
	var failures int
	option, err := WithReceiptShardSet(shards, v2, func(error) { failures++ })
	if err != nil {
		t.Fatal(err)
	}
	p := &Proxy{logger: audit.NewNop(), metrics: metrics.New()}
	option(p)
	if err := shards.Emitters()[0].AbortNativeAEL(); err != nil {
		t.Fatal(err)
	}
	opts := receipt.EmitOpts{
		ActionID: receipt.NewActionID(), Verdict: config.ActionAllow,
		Transport: "forward", Method: "GET", Target: "https://api.vendor.example/data",
		PolicyHash: strings.Repeat("a", 64), ShardSelected: true, ShardIndex: 0,
	}
	if err := p.emitRequiredReceiptWithEmitter(opts, p.receiptEmitterPtr.Load()); err == nil || !strings.Contains(err.Error(), "native AEL") {
		t.Fatalf("required native AEL failure did not block intent: %v", err)
	}
	if failures != 1 {
		t.Fatalf("required native AEL failure callback count = %d, want 1", failures)
	}
	for i, shard := range shards.Emitters() {
		if shard.HealthError() == nil {
			t.Fatalf("shard %d stayed healthy after native AEL failure", i)
		}
	}
}

func TestRequiredReceiptGroupV2SizeRejectKeepsGroupHealthy(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: t.TempDir(), SignCheckpoints: true}, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	shards, err := receipt.OpenInitialReceiptShardSet(receipt.EmitterConfig{
		Recorder: rec, PrivKey: key, ConfigHash: strings.Repeat("a", 64), Principal: "local", Actor: "pipelock",
	}, "proxy", 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	open, _ := shards.Opening()
	writer := &sizeRejectGroupDecisionRecorder{}
	v2 := make([]*proxydecision.Emitter, 2)
	for i, shard := range open.Shards {
		var decisionRecorder proxydecision.Recorder = rec
		if i == 0 {
			decisionRecorder = writer
		}
		v2[i] = proxydecision.NewEmitter(proxydecision.EmitterConfig{
			Recorder: decisionRecorder, Signer: proxydecision.NewKeyedSigner(key),
			Principal: "local", Actor: "pipelock", Session: shard.SessionID,
		})
	}
	var failures int
	option, err := WithReceiptShardSet(shards, v2, func(error) { failures++ })
	if err != nil {
		t.Fatal(err)
	}
	p := &Proxy{logger: audit.NewNop(), metrics: metrics.New()}
	option(p)
	opts := receipt.EmitOpts{
		ActionID: receipt.NewActionID(), Verdict: config.ActionAllow,
		Transport: "forward", Method: "GET", Target: "https://api.vendor.example/data",
		PolicyHash: strings.Repeat("a", 64), ShardSelected: true, ShardIndex: 0,
	}
	if err := p.emitRequiredReceiptWithEmitter(opts, p.receiptEmitterPtr.Load()); !errors.Is(err, recorder.ErrSerializedEntryTooLarge) {
		t.Fatalf("first intent = %v, want deterministic size reject", err)
	}
	if failures != 0 || v2[0].HealthError() != nil {
		t.Fatalf("size rejection cancelled group: failures=%d health=%v", failures, v2[0].HealthError())
	}
	opts.ActionID = receipt.NewActionID()
	if err := p.emitRequiredReceiptWithEmitter(opts, p.receiptEmitterPtr.Load()); err != nil {
		t.Fatalf("healthy group refused next intent: %v", err)
	}
	if writer.calls != 2 || failures != 0 {
		t.Fatalf("subsequent v2 write calls=%d failures=%d", writer.calls, failures)
	}
	for i, shard := range shards.Emitters() {
		if shard.HealthError() != nil {
			t.Fatalf("shard %d unhealthy after deterministic reject: %v", i, shard.HealthError())
		}
	}
}
