// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"strconv"
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
	sc := MustNew(cfg)
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

// BenchmarkFragmentBufferDeletePrefix measures the O(total sessions) scan that
// DeletePrefix performs under the write lock. It is documented as acceptable
// only because the sole caller is the rare operator reset path, never the
// per-request hot path. If this ever moves onto a hot path, add a prefix index.
func BenchmarkFragmentBufferDeletePrefix(b *testing.B) {
	const sessions = 10000
	build := func() *FragmentBuffer {
		fb := NewFragmentBuffer(65536, sessions, 300)
		for i := 0; i < sessions; i++ {
			key := "10.0.0.5|body-json|" + strconv.Itoa(i)
			fb.Append(key, []byte("value"))
		}
		return fb
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		fb := build()
		b.StartTimer()
		fb.DeletePrefix("10.0.0.5|body-json|")
		b.StopTimer()
		fb.Close()
	}
}
