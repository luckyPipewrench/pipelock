// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"fmt"
	"testing"
)

func BenchmarkEntropyTracker_Record(b *testing.B) {
	et := NewEntropyTracker(4096, 300) // 4096-bit budget, 5min window
	b.Cleanup(et.Close)

	payload := []byte("typical-query-parameter-value-1234567890")

	b.ResetTimer()
	for b.Loop() {
		et.Record("session1", payload)
	}
}

func BenchmarkEntropyTracker_RecordMultiSession(b *testing.B) {
	et := NewEntropyTracker(4096, 300) // 4096-bit budget, 5min window
	b.Cleanup(et.Close)

	payload := []byte("typical-query-parameter-value-1234567890")

	// 100 distinct session keys to exercise map growth and per-session bookkeeping.
	keys := make([]string, 100)
	for i := range keys {
		keys[i] = fmt.Sprintf("agent%d|10.0.0.%d", i, i)
	}

	b.ResetTimer()
	for i := 0; b.Loop(); i++ {
		et.Record(keys[i%len(keys)], payload)
	}
}
