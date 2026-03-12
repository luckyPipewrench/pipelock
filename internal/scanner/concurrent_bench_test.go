// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// --- Parallel benchmarks (b.RunParallel) ---
// These run across all available GOMAXPROCS goroutines simultaneously,
// proving true concurrent throughput scaling.

func BenchmarkParallel_URLScan(b *testing.B) {
	s := New(benchConfig())
	b.Cleanup(s.Close)

	const target = "https://api.example.com:8443/v2/search?q=golang+testing&page=3&limit=50"
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			s.Scan(context.Background(), target)
		}
	})
}

func BenchmarkParallel_DLPBlock(b *testing.B) {
	s := New(benchConfig())
	b.Cleanup(s.Close)

	key := "AKIA" + "IOSFODNN7" + "EXAMPLE"
	target := "https://example.com/api?key=" + key
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			s.Scan(context.Background(), target)
		}
	})
}

func BenchmarkParallel_ResponseScan(b *testing.B) {
	s := New(benchResponseConfig())
	b.Cleanup(s.Close)

	const content = "This is a normal web page with regular content about cooking recipes and golang tutorials."
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			s.ScanResponse(content)
		}
	})
}

func BenchmarkParallel_ResponseLarge(b *testing.B) {
	s := New(benchResponseConfig())
	b.Cleanup(s.Close)

	content := strings.Repeat("The quick brown fox jumps over the lazy dog. This is normal web content. ", 140)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			s.ScanResponse(content)
		}
	})
}

func BenchmarkParallel_Blocklist(b *testing.B) {
	s := New(benchConfig())
	b.Cleanup(s.Close)

	const target = "https://pastebin.com/raw/abc123"
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			s.Scan(context.Background(), target)
		}
	})
}

func BenchmarkParallel_Entropy(b *testing.B) {
	s := New(benchConfig())
	b.Cleanup(s.Close)

	entropy := "aB3xK9mQ7" + "pR2wE5tY8u" + "I0oL4hG6fD1sZ"
	target := "https://example.com/data/" + entropy
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			s.Scan(context.Background(), target)
		}
	})
}

// --- Concurrent throughput measurement ---
// Measures actual requests/sec at different goroutine counts to prove linear scaling.

func TestConcurrentThroughputScaling(t *testing.T) {
	if os.Getenv("PIPELOCK_BENCH_SCALING") == "" {
		t.Skip("skipping throughput test (set PIPELOCK_BENCH_SCALING=1 to run)")
	}

	s := New(benchConfig())
	t.Cleanup(s.Close)

	const (
		target   = "https://api.example.com:8443/v2/search?q=golang+testing&page=3&limit=50"
		duration = 2 * time.Second
	)

	goroutineCounts := []int{1, 2, 4, 8, 16, 32, 64}

	type result struct {
		goroutines int
		ops        int64
		elapsed    time.Duration
		opsPerSec  float64
	}

	var results []result

	for _, n := range goroutineCounts {
		var totalOps atomic.Int64
		var wg sync.WaitGroup

		start := time.Now()
		deadline := start.Add(duration)

		for range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				var local int64
				for time.Now().Before(deadline) {
					s.Scan(context.Background(), target)
					local++
				}
				totalOps.Add(local)
			}()
		}

		wg.Wait()
		elapsed := time.Since(start)
		ops := totalOps.Load()
		opsPerSec := float64(ops) / elapsed.Seconds()

		results = append(results, result{
			goroutines: n,
			ops:        ops,
			elapsed:    elapsed,
			opsPerSec:  opsPerSec,
		})
	}

	// Print scaling table
	t.Log("")
	t.Log("Concurrent URL Scan Throughput Scaling")
	t.Log("======================================")
	t.Logf("%-12s  %-12s  %-14s  %-10s", "Goroutines", "Total Ops", "Ops/sec", "Scaling")
	t.Log("----------------------------------------------------")

	baselineOps := results[0].opsPerSec
	for _, r := range results {
		scaling := r.opsPerSec / baselineOps
		t.Logf("%-12d  %-12d  %-14.0f  %.2fx", r.goroutines, r.ops, r.opsPerSec, scaling)
	}

	// Also test response scanning
	sResp := New(benchResponseConfig())
	t.Cleanup(sResp.Close)

	const content = "This is a normal web page with regular content about cooking recipes and golang tutorials."

	var respResults []result

	for _, n := range goroutineCounts {
		var totalOps atomic.Int64
		var wg sync.WaitGroup

		start := time.Now()
		deadline := start.Add(duration)

		for range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				var local int64
				for time.Now().Before(deadline) {
					sResp.ScanResponse(content)
					local++
				}
				totalOps.Add(local)
			}()
		}

		wg.Wait()
		elapsed := time.Since(start)
		ops := totalOps.Load()
		opsPerSec := float64(ops) / elapsed.Seconds()

		respResults = append(respResults, result{
			goroutines: n,
			ops:        ops,
			elapsed:    elapsed,
			opsPerSec:  opsPerSec,
		})
	}

	t.Log("")
	t.Log("Concurrent Response Scan Throughput Scaling")
	t.Log("============================================")
	t.Logf("%-12s  %-12s  %-14s  %-10s", "Goroutines", "Total Ops", "Ops/sec", "Scaling")
	t.Log("----------------------------------------------------")

	respBaseline := respResults[0].opsPerSec
	for _, r := range respResults {
		scaling := r.opsPerSec / respBaseline
		t.Logf("%-12d  %-12d  %-14.0f  %.2fx", r.goroutines, r.ops, r.opsPerSec, scaling)
	}

	// Verify near-linear scaling up to physical core count.
	// Skip assertion under race detector (adds ~10x overhead, distorts scaling).
	// 65% efficiency threshold accounts for runtime overhead (GC, scheduler, memory bandwidth).
	if baselineOps > 5000 { // race detector drops baseline below 5K ops/sec
		for _, r := range results {
			if r.goroutines <= 8 {
				expectedMin := baselineOps * float64(r.goroutines) * 0.65
				if r.opsPerSec < expectedMin {
					t.Errorf("goroutines=%d: expected at least %.0f ops/sec (65%% of linear), got %.0f",
						r.goroutines, expectedMin, r.opsPerSec)
				}
			}
		}
	} else {
		t.Log("Race detector detected (low baseline). Skipping scaling assertions.")
	}

	// Print summary
	peak := results[len(results)-1]
	t.Log("")
	t.Logf("Peak throughput: %.0f URL scans/sec at %d goroutines (%.1fx scaling)",
		peak.opsPerSec, peak.goroutines, peak.opsPerSec/baselineOps)
	respPeak := respResults[len(respResults)-1]
	t.Logf("Peak throughput: %.0f response scans/sec at %d goroutines (%.1fx scaling)",
		respPeak.opsPerSec, respPeak.goroutines, respPeak.opsPerSec/respBaseline)

	// Print machine-readable summary for docs
	t.Log("")
	t.Log("Machine-readable (for docs):")
	t.Logf("url_scan_1g=%.0f url_scan_8g=%.0f url_scan_64g=%.0f", results[0].opsPerSec, results[3].opsPerSec, results[6].opsPerSec)
	rr := respResults
	t.Logf("resp_scan_1g=%.0f resp_scan_8g=%.0f resp_scan_64g=%.0f", rr[0].opsPerSec, rr[3].opsPerSec, rr[6].opsPerSec)
	fmt.Println() // ensure flush
}
