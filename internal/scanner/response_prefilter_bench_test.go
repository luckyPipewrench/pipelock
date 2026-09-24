package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func BenchmarkResponseBodyBundles(b *testing.B) {
	root := os.Getenv("RESPONSE_BENCH_DIR")
	if root == "" {
		b.Skip("set RESPONSE_BENCH_DIR")
	}
	for _, name := range []string{"echarts.js", "monaco.js"} {
		body, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			b.Fatal(err)
		}
		b.Run(name, func(b *testing.B) {
			s := MustNew(config.Defaults())
			defer s.Close()
			b.ResetTimer()
			for range b.N {
				result := s.ScanResponseBodyWithSuppress(context.Background(), body, "", nil)
				if !result.Clean {
					b.Fatal("fixture should be clean")
				}
			}
		})
	}
}
