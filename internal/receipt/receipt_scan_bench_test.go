// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// BenchmarkReceiptDetailDLP profiles the exact JSON shape emitted by a normal
// signed receipt, including its signature and chain fields.
func BenchmarkReceiptDetailDLP(b *testing.B) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	dir := b.TempDir()
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, CheckpointInterval: 1000}, nil, key)
	if err != nil {
		b.Fatal(err)
	}
	emitter := NewEmitter(EmitterConfig{Recorder: rec, PrivKey: key, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor})
	if err := emitter.Emit(EmitOpts{ActionID: NewActionID(), Target: "http://api.vendor.example/ok?id=1", Verdict: config.ActionAllow, Transport: testTransport, Method: http.MethodGet}); err != nil {
		b.Fatal(err)
	}
	if err := rec.Close(); err != nil {
		b.Fatal(err)
	}
	entries, err := recorder.ReadEntries(filepath.Join(dir, "evidence-proxy-0.jsonl"))
	if err != nil {
		b.Fatal(err)
	}
	if len(entries) == 0 {
		b.Fatal("no receipt entries")
	}
	data, err := json.Marshal(entries[0].Detail)
	if err != nil {
		b.Fatal(err)
	}
	sc := scanner.MustNew(config.Defaults())
	b.Cleanup(sc.Close)
	if result := sc.ScanTextForDLP(context.Background(), string(data)); !result.Clean {
		b.Fatalf("representative receipt is not clean: %+v", result.Matches)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if result := sc.ScanTextForDLP(context.Background(), string(data)); !result.Clean {
			b.Fatal("receipt became dirty")
		}
	}
	b.ReportMetric(float64(len(data)), "detail-bytes")
}

// BenchmarkEmitterConcurrentReceipt records through one live chain with the
// same DLP callback used by production, exposing chain and recorder contention.
func BenchmarkEmitterConcurrentReceipt(b *testing.B) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	sc := scanner.MustNew(config.Defaults())
	b.Cleanup(sc.Close)
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: b.TempDir(), Redact: true, CheckpointInterval: 1000}, sc.ScanTextForDLP, key)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = rec.Close() })
	emitter := NewEmitter(EmitterConfig{Recorder: rec, PrivKey: key, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor})
	b.SetParallelism(32)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if err := emitter.Emit(EmitOpts{ActionID: NewActionID(), Target: "http://api.vendor.example/ok?id=1", Verdict: config.ActionAllow, Transport: testTransport, Method: http.MethodGet}); err != nil {
				b.Error(err)
				return
			}
		}
	})
}
