// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func BenchmarkFragmentBuffer_Append(b *testing.B) {
	fb := NewFragmentBuffer(65536, 10000, 300) // 64KB cap, 10k sessions, 5min window
	b.Cleanup(fb.Close)

	payload := []byte("typical-query-parameter-value-1234567890")

	b.ResetTimer()
	for b.Loop() {
		fb.Append("session1", payload)
	}
}

func BenchmarkFragmentBuffer_AppendAndScan(b *testing.B) {
	cfg := config.Defaults()
	cfg.Internal = nil // disable SSRF (no DNS in benchmarks)
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	sc := New(cfg)
	b.Cleanup(sc.Close)

	fb := NewFragmentBuffer(65536, 10000, 300) // 64KB cap, 10k sessions, 5min window
	b.Cleanup(fb.Close)

	payload := []byte("typical-query-parameter-value-1234567890")

	b.ResetTimer()
	for b.Loop() {
		fb.Append("session1", payload)
		fb.ScanForSecrets(context.Background(), "session1", sc)
	}
}
