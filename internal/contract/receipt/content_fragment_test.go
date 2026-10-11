// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/receiptcontent"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestEvidenceClientFragmentsRemainCandidates(t *testing.T) {
	const whole = "reversedv2splitfixture"
	cfg := config.Defaults()
	cfg.CanaryTokens = config.CanaryTokens{Enabled: true, Tokens: []config.CanaryToken{{Name: "v2split", Value: whole}}}
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	if sc.ScanTextForDLPQuiet(t.Context(), whole).Clean {
		t.Fatal("positive control: whole canary must match")
	}
	for _, tc := range []struct {
		name   string
		actor  string
		target string
	}{
		{"actor remains externally influenced", whole[10:], whole[:10]},
		{"reversed payload fields", "operator", whole[:10]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rcpt := v2Receipt()
			rcpt.Actor = tc.actor
			payload := map[string]string{"target": tc.target, "transport": "forward", "verdict": "allow"}
			if tc.name == "reversed payload fields" {
				payload["rule_id"] = whole[10:]
			}
			var err error
			rcpt.Payload, err = json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(rcpt)
			if err != nil {
				t.Fatal(err)
			}
			p, err := evidenceReceiptProducer.Project(raw)
			if err != nil {
				t.Fatal(err)
			}
			rep, err := receiptcontent.Scan(t.Context(), sc.ScanTextForDLPQuiet, p)
			if err != nil || rep.Clean() || rep.Findings[0].View != receiptcontent.ViewFragments {
				t.Fatalf("v2 client split not reassembled: %+v %v", rep, err)
			}
		})
	}
}

// BenchmarkEvidenceContentFragments measures the v2 producer's content
// boundary, including its recorder mirrors, with the default detector.
func BenchmarkEvidenceContentFragments(b *testing.B) {
	rcpt := v2Receipt()
	cfg := config.Defaults()
	rcpt.PolicyHash = cfg.CanonicalPolicyHash()
	raw, err := json.Marshal(rcpt)
	if err != nil {
		b.Fatal(err)
	}
	p, err := evidenceReceiptProducer.Project(raw)
	if err != nil {
		b.Fatal(err)
	}
	sc := scanner.MustNew(cfg)
	b.Cleanup(sc.Close)
	calls := 0
	det := func(ctx context.Context, text string) scanner.TextDLPResult {
		calls++
		return sc.ScanTextForDLPQuiet(ctx, text)
	}
	if rep, err := receiptcontent.Scan(b.Context(), det, p); err != nil || !rep.Clean() {
		b.Fatalf("representative receipt: %+v %v", rep, err)
	}
	perScan := calls
	candidates := 0
	for _, a := range p.Atoms() {
		if !a.Fixed {
			candidates++
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := receiptcontent.Scan(b.Context(), det, p); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(perScan), "detector-calls/op")
	b.ReportMetric(float64(candidates), "fragment-atoms/op")
}
