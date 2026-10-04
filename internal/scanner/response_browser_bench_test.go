// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// BenchmarkResponseBrowserFixture uses the exact generated browser input for
// scanner-only attribution. The body benchmark deliberately varies the target
// to miss the existing verdict cache; warm measures that cache separately.
// Generate inputs with scripts/e2e/browser_repro/fixture.py, never a saved
// production browser response or profile.
func BenchmarkResponseBrowserFixture(b *testing.B) {
	dir := os.Getenv("PIPELOCK_BROWSER_REPRO_BENCH_DIR")
	if dir == "" {
		b.Skip("set PIPELOCK_BROWSER_REPRO_BENCH_DIR to generated fixture directory")
	}
	for _, name := range []string{"generated-js.js", "generated-js-marker.js"} {
		body, err := os.ReadFile(filepath.Clean(filepath.Join(dir, name)))
		if err != nil {
			b.Fatal(err)
		}
		b.Logf("%s: bytes=%d sha256=%x", name, len(body), sha256.Sum256(body))
		b.Run(name, func(b *testing.B) {
			cfg := config.Defaults()
			cfg.DLP.ScanEnv = false
			cfg.ResponseScanning.Patterns = append(cfg.ResponseScanning.Patterns, config.ResponseScanPattern{
				Name: "Browser Fixture Marker", Regex: "BROWSER_REPRO_RESPONSE_MARKER",
			})
			s := MustNew(cfg)
			defer s.Close()
			wantClean := name == "generated-js.js"
			verify := func(result ResponseScanResult) {
				b.Helper()
				if result.Clean != wantClean || result.Failed() {
					b.Fatalf("Clean=%t, want %t; error=%q matches=%v", result.Clean, wantClean, result.ScanError, result.Matches)
				}
				if !wantClean && (len(result.Matches) != 1 || result.Matches[0].PatternName != "Browser Fixture Marker") {
					b.Fatalf("expected only synthetic marker, got %v", result.Matches)
				}
			}
			nextTarget := 0
			b.Run("cold", func(b *testing.B) {
				b.SetBytes(int64(len(body)))
				b.ReportAllocs()
				for range b.N {
					verify(s.ScanResponseBodyWithSuppress(context.Background(), body, "fixture-"+strconv.Itoa(nextTarget), nil))
					nextTarget++
				}
			})
			if wantClean {
				b.Run("warm", func(b *testing.B) {
					verify(s.ScanResponseBodyWithSuppress(context.Background(), body, "warm", nil))
					b.SetBytes(int64(len(body)))
					b.ReportAllocs()
					b.ResetTimer()
					for range b.N {
						verify(s.ScanResponseBodyWithSuppress(context.Background(), body, "warm", nil))
					}
				})
			}
		})
	}
}
