// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receiptcontent

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// BenchmarkScanFragmentsAtPartCap measures the bounded fragment search on a
// receipt with the most atoms that still gets the full 2..SubsequenceMaxSize
// search, using the production default detector. It reports detector calls
// per scan so a change to the bound shows up beside the time.
func BenchmarkScanFragmentsAtPartCap(b *testing.B) {
	for _, width := range []int{4, 8, scanner.SubsequenceMaxParts - 1} {
		b.Run(fmt.Sprintf("atoms=%d", width+1), func(b *testing.B) {
			values := make([]string, width)
			for i := range values {
				values[i] = fmt.Sprintf("api.vendor.example/v1/items/%d?page=%d", i, i*3)
			}
			raw, err := json.Marshal(map[string]any{"list": values})
			if err != nil {
				b.Fatal(err)
			}
			p, err := ProjectUnproven(raw, nil)
			if err != nil {
				b.Fatal(err)
			}
			cfg := config.Defaults()
			cfg.Internal = nil
			sc := scanner.MustNew(cfg)
			b.Cleanup(sc.Close)
			calls := 0
			det := func(ctx context.Context, text string) scanner.TextDLPResult {
				calls++
				return sc.ScanTextForDLPQuiet(ctx, text)
			}
			ctx := context.Background()
			if rep, err := Scan(ctx, det, p); err != nil || !rep.Clean() {
				b.Fatalf("representative receipt: report %+v, err %v", rep.Findings, err)
			}
			perScan := calls
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if _, err := Scan(ctx, det, p); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(perScan), "detector-calls/op")
		})
	}
}

// BenchmarkScanMixedFragments measures the same total widths when all but
// two atoms are producer-fixed values. The full controlled-width benchmark
// above must keep its documented detection guarantee and cost ceiling.
func BenchmarkScanMixedFragments(b *testing.B) {
	for _, width := range []int{5, 9, scanner.SubsequenceMaxParts} {
		b.Run(fmt.Sprintf("atoms=%d", width), func(b *testing.B) {
			values := make([]string, width)
			for i := range values {
				values[i] = fmt.Sprintf("api.vendor.example/v1/items/%d?page=%d", i, i*3)
			}
			raw, err := json.Marshal(map[string]any{"list": values})
			if err != nil {
				b.Fatal(err)
			}
			producer := (&Producer{schema: &Schema{Kind: "bench.mixed", Fields: map[string]Class{"list": Content, "list[]": Content}}}).WithFixedValues(map[string][]string{"list[]": values[2:]})
			p, err := producer.Project(raw)
			if err != nil {
				b.Fatal(err)
			}
			cfg := config.Defaults()
			cfg.Internal = nil
			sc := scanner.MustNew(cfg)
			b.Cleanup(sc.Close)
			calls := 0
			det := func(ctx context.Context, text string) scanner.TextDLPResult {
				calls++
				return sc.ScanTextForDLPQuiet(ctx, text)
			}
			if rep, err := Scan(b.Context(), det, p); err != nil || !rep.Clean() {
				b.Fatalf("representative receipt: %+v %v", rep, err)
			}
			perScan := calls
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if _, err := Scan(b.Context(), det, p); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(perScan), "detector-calls/op")
		})
	}
}
