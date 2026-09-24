// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func BenchmarkResponseBodyBundles(b *testing.B) {
	root := os.Getenv("RESPONSE_BENCH_DIR")
	if root == "" {
		b.Skip("set RESPONSE_BENCH_DIR")
	}
	for _, name := range []string{"echarts.js", "monaco.js"} {
		body, err := os.ReadFile(filepath.Clean(filepath.Join(root, name)))
		if err != nil {
			b.Fatal(err)
		}
		b.Run(name, func(b *testing.B) {
			s := MustNew(config.Defaults())
			defer s.Close()
			b.ResetTimer()
			for i := range b.N {
				// The target is part of the verdict-cache key, so a new one per
				// iteration measures a full scan rather than a cache hit.
				// BenchmarkResponseBodyEchartsRepeat measures the cached path.
				result := s.ScanResponseBodyWithSuppress(context.Background(), body, "bench-"+strconv.Itoa(i), nil)
				if !result.Clean {
					b.Fatal("fixture should be clean")
				}
			}
		})
	}
}

func BenchmarkResponseBodyEchartsRepeat(b *testing.B) {
	root := os.Getenv("RESPONSE_BENCH_DIR")
	if root == "" {
		b.Skip("set RESPONSE_BENCH_DIR")
	}
	body, err := os.ReadFile(filepath.Clean(filepath.Join(root, "echarts.js")))
	if err != nil {
		b.Fatal(err)
	}
	s := MustNew(config.Defaults())
	defer s.Close()
	if result := s.ScanResponseBodyWithSuppress(context.Background(), body, "", nil); !result.Clean {
		b.Fatal("fixture should be clean")
	}
	b.ResetTimer()
	for range b.N {
		if result := s.ScanResponseBodyWithSuppress(context.Background(), body, "", nil); !result.Clean {
			b.Fatal("fixture should be clean")
		}
	}
}
