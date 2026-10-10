// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/receiptcontent"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestClientFragmentsRemainCandidates(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*EmitOpts)
	}{
		{"reversed target and method", func(o *EmitOpts) { o.Target = boundaryCanary[:11]; o.Method = boundaryCanary[11:] }},
		{"agent override and target", func(o *EmitOpts) { o.Agent = boundaryCanary[11:]; o.Target = boundaryCanary[:11] }},
		{"nonconstant transport and method", func(o *EmitOpts) { o.Transport = boundaryCanary[:11]; o.Method = boundaryCanary[11:] }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newBoundaryFixture(t)
			o := baseOpts()
			tc.mutate(&o)
			if err := f.em.Emit(o); !errors.Is(err, receiptcontent.ErrRejected) {
				t.Fatalf("client-controlled split accepted: %v", err)
			}
			if err := f.em.Emit(baseOpts()); err != nil {
				t.Fatal(err)
			}
			if len(f.receipts(t)) != 1 {
				t.Fatal("refusal advanced or poisoned the receipt chain")
			}
		})
	}
}

func TestActionReceiptFragmentCandidates(t *testing.T) {
	f := newBoundaryFixture(t)
	raw, err := json.Marshal(Receipt{Version: ReceiptVersion, ActionRecord: f.em.contentRecord(baseOpts(), ActionRead, SideEffectExternalRead, ReversibilityFull, testConfigHash)})
	if err != nil {
		t.Fatal(err)
	}
	p, err := f.em.contentProducer().Project(raw)
	if err != nil {
		t.Fatal(err)
	}
	var candidates []string
	for _, a := range p.Atoms() {
		if !a.Fixed {
			candidates = append(candidates, a.Field)
		}
	}
	if len(candidates) != 3 {
		t.Fatalf("candidates = %v, want method, policy_hash override and target", candidates)
	}
}

func TestActionReceiptDetectorCallBudget(t *testing.T) {
	f := newBoundaryFixture(t)
	for _, tc := range []struct {
		name     string
		opts     EmitOpts
		maxCalls int
	}{
		{"plain GET", baseOpts(), 30},
		{"block GET", EmitOpts{ActionID: NewActionID(), Target: testTarget, Verdict: "block", Transport: testTransport, Method: "GET", Layer: "dlp", Pattern: "credential"}, 120},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(Receipt{Version: ReceiptVersion, ActionRecord: f.em.contentRecord(tc.opts, ActionRead, SideEffectExternalRead, ReversibilityFull, testConfigHash)})
			if err != nil {
				t.Fatal(err)
			}
			p, err := f.em.contentProducer().Project(raw)
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			det := func(ctx context.Context, text string) scanner.TextDLPResult {
				calls++
				return f.sc.ScanTextForDLPQuiet(ctx, text)
			}
			rep, err := receiptcontent.Scan(t.Context(), det, p)
			if err != nil || !rep.Clean() || calls > tc.maxCalls {
				t.Fatalf("calls=%d, max=%d: %+v %v", calls, tc.maxCalls, rep, err)
			}
			t.Logf("%d detector calls", calls)
		})
	}
}
