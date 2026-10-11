// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/receiptcontent"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

// TestOrdinaryWideReceiptIsNotBudgetRefused is the round-2 reproduction for
// the fragment part cap. A session's recent taint list and a browser-shield
// summary are ordinary receipt content. With redaction on, the content
// boundary must record them. A part cap copied from query-string search must
// not turn that width into a standing receipt refusal.
func TestOrdinaryWideReceiptIsNotBudgetRefused(t *testing.T) {
	f := newBoundaryFixture(t)
	sources := make([]session.TaintSourceRef, 0, 4)
	for i := range 4 {
		sources = append(sources, session.TaintSourceRef{
			URL:         "https://cdn.vendor.example/asset/" + strings.Repeat("a", i),
			Kind:        "fetch",
			Level:       session.TaintExternalUntrusted,
			Timestamp:   time.Date(2026, 10, 9, 12, 0, i, 0, time.UTC),
			MatchReason: "external",
		})
	}
	opts := baseOpts()
	opts.Layer = "browser_shield"
	opts.Pattern = "browser_shield_rewrite"
	opts.Severity = config.SeverityInfo
	opts.RecentTaintSources = sources
	opts.Shield = &ShieldSummary{
		Pipeline:                 "html",
		TotalRewrites:            4,
		ExtensionProbes:          1,
		TrackingBeacons:          1,
		AgentTraps:               1,
		BodyBytes:                2048,
		ScannedBytes:             1024,
		AdaptiveSignalsRecorded:  1,
		AdaptiveSignalMaxPerBody: 8,
	}
	tmpl := Receipt{Version: ReceiptVersion, ActionRecord: f.em.contentRecord(opts, ActionRead, SideEffectExternalRead, ReversibilityFull, testConfigHash)}
	raw, err := json.Marshal(tmpl)
	if err != nil {
		t.Fatal(err)
	}
	proj, err := actionReceiptProducer.Project(raw)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(proj.Atoms()); n <= scanner.SubsequenceMaxParts {
		t.Fatalf("fixture has %d atoms, want more than %d so the part cap used to refuse it", n, scanner.SubsequenceMaxParts)
	}
	if err := f.em.Emit(opts); err != nil {
		t.Fatalf("ordinary wide receipt refused: %v", err)
	}
	if rs := f.receipts(t); len(rs) != 1 {
		t.Fatalf("recorded %d receipts, want 1", len(rs))
	}
}

// TestWideReceiptStillCatchesASplitCanary is the detection half of the width
// fix. A token broken across two taint URLs, with the source's other fields
// between them, has to refuse the receipt. Recording it would mean the wider
// search stopped looking.
func TestWideReceiptStillCatchesASplitCanary(t *testing.T) {
	f := newBoundaryFixture(t)
	sources := make([]session.TaintSourceRef, 0, 4)
	for i := range 4 {
		sources = append(sources, session.TaintSourceRef{
			URL:         "https://cdn.vendor.example/asset/" + strings.Repeat("b", i+1),
			Kind:        "fetch",
			Level:       session.TaintExternalUntrusted,
			Timestamp:   time.Date(2026, 10, 9, 12, 0, i, 0, time.UTC),
			MatchReason: "external",
		})
	}
	// The halves are whole atoms, with the other source fields between them, so
	// only a fragment pair reassembles the canary.
	sources[0].MatchReason = boundaryCanary[:11]
	sources[3].MatchReason = boundaryCanary[11:]
	opts := baseOpts()
	opts.Layer = "browser_shield"
	opts.Pattern = "browser_shield_rewrite"
	opts.Severity = config.SeverityInfo
	opts.RecentTaintSources = sources
	opts.Shield = &ShieldSummary{Pipeline: "html", TotalRewrites: 4, BodyBytes: 2048}
	err := f.em.Emit(opts)
	if !errors.Is(err, receiptcontent.ErrRejected) || !strings.Contains(err.Error(), "fragments view") {
		t.Fatalf("err = %v, want a fragment-view content rejection", err)
	}
	if err := f.em.Emit(baseOpts()); err != nil {
		t.Fatalf("clean receipt after rejection: %v", err)
	}
	if rs := f.receipts(t); len(rs) != 1 {
		t.Fatalf("recorded %d receipts, want the clean one only", len(rs))
	}
}
