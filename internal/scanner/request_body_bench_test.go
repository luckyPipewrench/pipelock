// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"slices"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func BenchmarkRequestBodyDLP(b *testing.B) {
	benchmarkRequestBodyDLP(b, false)
}

func BenchmarkRequestBodyDLPWithEnvSecret(b *testing.B) {
	benchmarkRequestBodyDLP(b, true)
}

func benchmarkRequestBodyDLP(b *testing.B, withEnvSecret bool) {
	cfg := config.Defaults()
	cfg.Internal = nil
	secret := strings.Join([]string{"example", "benchmark", "secret", "value!!"}, " ")
	if withEnvSecret {
		b.Setenv("PIPELOCK_BENCH_SECRET", secret)
	} else {
		cfg.DLP.ScanEnv = false
	}
	sc := MustNew(cfg)
	b.Cleanup(sc.Close)
	if withEnvSecret {
		if !cfg.DLP.ScanEnv || sc.minEnvSecretLen != 16 || !slices.Contains(sc.envSecrets, secret) {
			b.Fatal("production-default env-secret scanning was not exercised")
		}
	}
	for _, size := range []int{2048, 65536} {
		name := "2KiB"
		if size == 65536 {
			name = "64KiB"
		}
		b.Run(name, func(b *testing.B) {
			prose := "The service processes ordinary status updates and returns a summary for the current request. "
			body := strings.Repeat(prose, size/len(prose)+1)[:size]
			if r := sc.ScanRequestBodyTextForDLP(b.Context(), body); !r.Clean {
				b.Fatal("benign body blocked")
			}
			b.SetBytes(int64(len(body)))
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				_ = sc.ScanRequestBodyTextForDLP(b.Context(), body)
			}
		})
	}
}
