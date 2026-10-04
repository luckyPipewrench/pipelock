// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxydecision

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// BenchmarkEvidenceReceiptDetailDLP measures the recorder's write-boundary DLP
// scan over the exact signed evidence receipt bytes this emitter produces.
func BenchmarkEvidenceReceiptDetailDLP(b *testing.B) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	rec := &captureRecorder{}
	em := NewEmitter(EmitterConfig{Recorder: rec, Signer: NewKeyedSigner(priv), Principal: "local", Actor: "pipelock"})
	if em == nil {
		b.Fatal("NewEmitter returned nil")
	}
	if err := em.Emit(validDecision()); err != nil {
		b.Fatal(err)
	}
	if len(rec.entries) != 1 {
		b.Fatalf("recorded %d entries, want 1", len(rec.entries))
	}
	raw, ok := rec.entries[0].Detail.(json.RawMessage)
	if !ok {
		b.Fatalf("entry detail is %T, want json.RawMessage", rec.entries[0].Detail)
	}
	text := string(raw)
	sc := scanner.MustNew(config.Defaults())
	b.Cleanup(sc.Close)
	if result := sc.ScanTextForDLP(context.Background(), text); !result.Clean {
		b.Fatalf("representative evidence receipt is not clean: %+v", result.Matches)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if result := sc.ScanTextForDLP(context.Background(), text); !result.Clean {
			b.Fatal("evidence receipt became dirty")
		}
	}
	b.ReportMetric(float64(len(text)), "detail-bytes")
}
