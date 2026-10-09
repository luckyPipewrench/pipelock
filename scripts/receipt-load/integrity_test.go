// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

func TestExpectedFor(t *testing.T) {
	tests := []struct {
		name    string
		mode    string
		blocked bool
		want    expectedReceipts
	}{
		{"off allowed", modeOff, false, expectedReceipts{}},
		{"off blocked", modeOff, true, expectedReceipts{}},
		{"best allowed", modeBest, false, expectedReceipts{kindV1Allow: 1, kindV2: 1, kindAEL: 1}},
		{"best blocked", modeBest, true, expectedReceipts{kindV1Block: 1, kindV2: 1, kindAEL: 1}},
		{"required allowed", modeRequired, false, expectedReceipts{kindV1Intent: 1, kindV1Outcome: 1, kindV2: 2, kindAEL: 2}},
		{"required blocked", modeRequired, true, expectedReceipts{kindV1Block: 1, kindV2: 1, kindAEL: 1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := expectedFor(tt.mode, tt.blocked); got != tt.want {
				t.Fatalf("expectedFor(%q, %v) = %v, want %v", tt.mode, tt.blocked, got, tt.want)
			}
		})
	}
}

func TestIntegrityPassesForCompleteReceipts(t *testing.T) {
	plan := newWorkload(1, 2, 40)
	for _, mode := range []string{modeBest, modeRequired} {
		t.Run(mode, func(t *testing.T) {
			rep := evaluateSynth(t, mode, perfectReceipts(plan, mode))
			if rep.Verdict != verdictPass || rep.ReceiptMissing != 0 || len(rep.Reasons) != 0 {
				t.Fatalf("complete receipts: verdict=%s missing=%d reasons=%v", rep.Verdict, rep.ReceiptMissing, rep.Reasons)
			}
			if rep.ControlReceipts == 0 {
				t.Fatal("session-control receipts were not recognized as control")
			}
		})
	}
}

func TestIntegrityOffExpectsNothing(t *testing.T) {
	plan := newWorkload(1, 2, 40)
	if rep := evaluateSynth(t, modeOff, nil); rep.Verdict != verdictPass {
		t.Fatalf("off with no receipts: %v", rep.Reasons)
	}
	// A recorder that holds request receipts while the mode is off is a defect.
	rep := evaluateSynth(t, modeOff, perfectReceipts(plan, modeBest))
	if rep.Verdict != verdictFail || rep.Kinds["v2"].Unexpected == 0 {
		t.Fatalf("off with receipts present: verdict=%s v2=%+v", rep.Verdict, rep.Kinds["v2"])
	}
}

// without drops every receipt matching keep==false.
func without(receipts []synthReceipt, drop func(synthReceipt) bool) []synthReceipt {
	var out []synthReceipt
	for _, r := range receipts {
		if !drop(r) {
			out = append(out, r)
		}
	}
	return out
}

func TestIntegrityDetectsMissingOutcomes(t *testing.T) {
	plan := newWorkload(1, 2, 40)
	// Drop the outcome (and its v2 and AEL siblings are kept) for one allowed
	// request. A harness that counted receipts per request would still see
	// "enough" receipts; identity accounting must not.
	var victim int
	for slot := range plan.total() {
		if !plan.blocked(slot) {
			victim = slot
			break
		}
	}
	dropped := false
	receipts := without(perfectReceipts(plan, modeRequired), func(r synthReceipt) bool {
		if r.kind == kindV1Outcome && r.slot == victim && !dropped {
			dropped = true
			return true
		}
		return false
	})
	rep := evaluateSynth(t, modeRequired, receipts)
	if rep.Verdict != verdictFail {
		t.Fatal("missing outcome receipt passed integrity")
	}
	got := rep.Kinds["v1_outcome"]
	if got.Missing != 1 || got.Status != statusFail || !strings.Contains(got.FirstProblem, plan.key(victim)) {
		t.Fatalf("v1_outcome = %+v, want one missing naming %s", got, plan.key(victim))
	}
	if rep.ReceiptMissing != 1 {
		t.Fatalf("receipt_missing = %d, want exactly 1 (terminal completeness)", rep.ReceiptMissing)
	}
	for _, kind := range []string{"v1_intent", "v2", "ael"} {
		if rep.Kinds[kind].Status != statusOK {
			t.Fatalf("%s should be unaffected, got %+v", kind, rep.Kinds[kind])
		}
	}
}

func TestIntegrityMissingOutcomeIsNotMaskedByDuplicateElsewhere(t *testing.T) {
	plan := newWorkload(1, 2, 40)
	// One request loses its outcome while another gains a second one: totals
	// match the expected count, identities do not.
	var allowed []int
	for slot := range plan.total() {
		if !plan.blocked(slot) {
			allowed = append(allowed, slot)
		}
	}
	lost, extra := allowed[0], allowed[1]
	receipts := without(perfectReceipts(plan, modeRequired), func(r synthReceipt) bool {
		return r.kind == kindV1Outcome && r.slot == lost
	})
	receipts = append(receipts, synthReceipt{kind: kindV1Outcome, slot: extra, actionID: actionIDFor(extra)})
	rep := evaluateSynth(t, modeRequired, receipts)
	got := rep.Kinds["v1_outcome"]
	if got.Expected != got.Observed {
		t.Fatalf("test setup: observed %d should equal expected %d", got.Observed, got.Expected)
	}
	if rep.Verdict != verdictFail || got.Missing != 1 || got.Duplicate != 1 {
		t.Fatalf("v1_outcome = %+v, want 1 missing and 1 duplicate", got)
	}
}

func TestIntegrityDetectsDuplicates(t *testing.T) {
	plan := newWorkload(1, 2, 40)
	for _, kind := range []receiptKind{kindV1Intent, kindV1Outcome, kindV2, kindAEL, kindV1Block} {
		t.Run(kind.String(), func(t *testing.T) {
			receipts := perfectReceipts(plan, modeRequired)
			var dup synthReceipt
			for _, r := range receipts {
				if r.kind == kind {
					dup = r
					break
				}
			}
			rep := evaluateSynth(t, modeRequired, append(receipts, dup))
			got := rep.Kinds[kind.String()]
			if rep.Verdict != verdictFail || got.Duplicate != 1 || got.Missing != 0 || got.Status != statusFail {
				t.Fatalf("%s = %+v, want exactly one duplicate", kind, got)
			}
		})
	}
}

func TestIntegrityDetectsUnexpectedKinds(t *testing.T) {
	plan := newWorkload(1, 2, 40)
	// An outcome receipt in best mode, where require_receipts is off, is not a
	// receipt the mode produces.
	receipts := append(perfectReceipts(plan, modeBest), synthReceipt{kind: kindV1Outcome, slot: 3, actionID: actionIDFor(3)})
	rep := evaluateSynth(t, modeBest, receipts)
	if got := rep.Kinds["v1_outcome"]; rep.Verdict != verdictFail || got.Unexpected != 1 {
		t.Fatalf("v1_outcome = %+v, want one unexpected", got)
	}
}

func TestIntegrityOrphansAndUncorrelatable(t *testing.T) {
	plan := newWorkload(1, 2, 40)
	tests := []struct {
		name   string
		target string
		kind   receiptKind
		check  func(kindReport) bool
	}{
		{"key from another run", sinkTarget(synthSink, "wk=s9-m000001"), kindV2, func(k kindReport) bool { return k.Orphan == 1 && k.Status == statusFail }},
		{"key index out of plan", sinkTarget(synthSink, "wk=s1-m999999"), kindV1Outcome, func(k kindReport) bool { return k.Orphan == 1 }},
		{"key redacted away", sinkTarget(synthSink, "wk=[redacted-value]"), kindV2, func(k kindReport) bool { return k.Uncorrelatable == 1 && k.Status == statusUnavailable }},
		{"target sanitized to a marker", "[redacted-target]", kindV2, func(k kindReport) bool { return k.Uncorrelatable == 1 && k.Status == statusUnavailable }},
		{"key missing from target", sinkTarget(synthSink, "id=3"), kindV1Intent, func(k kindReport) bool { return k.Uncorrelatable == 1 && k.Status == statusUnavailable }},
		{"duplicated key parameter", sinkTarget(synthSink, "wk=s1-m000001&wk=s1-m000002"), kindV2, func(k kindReport) bool { return k.Uncorrelatable == 1 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			receipts := append(perfectReceipts(plan, modeRequired), synthReceipt{kind: tt.kind, slot: 5, actionID: "stray", target: tt.target})
			rep := evaluateSynth(t, modeRequired, receipts)
			got := rep.Kinds[tt.kind.String()]
			if rep.Verdict != verdictFail || !tt.check(got) {
				t.Fatalf("%s = %+v (verdict %s), want orphan or UNAVAILABLE", tt.kind, got, rep.Verdict)
			}
		})
	}
}

// A v2 receipt whose key was sanitized away must not be matched to a request
// by position, by count, or because its neighbours are present.
func TestIntegrityUnavailableDoesNotGuess(t *testing.T) {
	plan := newWorkload(1, 2, 40)
	receipts := perfectReceipts(plan, modeBest)
	for i := range receipts {
		if receipts[i].kind == kindV2 {
			receipts[i].target = sinkTarget(synthSink, "wk=[redacted-value]")
		}
	}
	rep := evaluateSynth(t, modeBest, receipts)
	v2 := rep.Kinds["v2"]
	if rep.Verdict != verdictFail || v2.Status != statusUnavailable {
		t.Fatalf("v2 with every key redacted = %+v verdict %s, want UNAVAILABLE and fail", v2, rep.Verdict)
	}
	if v2.Observed != 0 || v2.Missing != v2.Expected {
		t.Fatalf("redacted v2 receipts were attributed to requests: %+v", v2)
	}
	if rep.Kinds["v1_allow"].Status != statusOK {
		t.Fatalf("v1 should be unaffected: %+v", rep.Kinds["v1_allow"])
	}
}

func TestIntegrityAmbiguousActionIDsMakeAELUnavailable(t *testing.T) {
	plan := newWorkload(1, 2, 40)
	receipts := perfectReceipts(plan, modeBest)
	// Two different ActionIDs claim the same request key.
	var victim int
	for slot := range plan.total() {
		if !plan.blocked(slot) {
			victim = slot
			break
		}
	}
	receipts = append(receipts, synthReceipt{kind: kindV1Allow, slot: victim, actionID: "second-action"})
	rep := evaluateSynth(t, modeBest, receipts)
	if rep.Verdict != verdictFail || rep.AmbiguousRequests != 1 || rep.Kinds["ael"].Status != statusUnavailable {
		t.Fatalf("ambiguous request: verdict=%s ambiguous=%d ael=%+v", rep.Verdict, rep.AmbiguousRequests, rep.Kinds["ael"])
	}
}

func TestIntegrityAELOrphan(t *testing.T) {
	plan := newWorkload(1, 2, 40)
	receipts := append(perfectReceipts(plan, modeBest), synthReceipt{kind: kindAEL, slot: 0, actionID: "no-such-action"})
	rep := evaluateSynth(t, modeBest, receipts)
	if got := rep.Kinds["ael"]; rep.Verdict != verdictFail || got.Orphan != 1 {
		t.Fatalf("ael = %+v, want one orphan", got)
	}
}

func TestIntegrityHeaderMismatch(t *testing.T) {
	plan := newWorkload(1, 2, 40)
	dir := t.TempDir()
	writeSynthRecorder(t, dir, plan, synthSink, perfectReceipts(plan, modeRequired))
	obs, err := scanRecorder(dir, plan, synthSink)
	if err != nil {
		t.Fatal(err)
	}
	outcomes := make([]requestOutcome, plan.total())
	hits := make([]int, plan.total())
	for slot := range outcomes {
		outcomes[slot] = requestOutcome{ran: true, status: 200, receiptHeader: actionIDFor(slot)}
		if plan.blocked(slot) {
			outcomes[slot].status = 403
		} else {
			hits[slot] = 1
		}
	}
	outcomes[4].receiptHeader = "someone-elses-action"
	outcomes[6].receiptHeader = ""
	rep := evaluateIntegrity(integrityInput{mode: modeRequired, plan: plan, obs: obs, outcomes: outcomes, sinkHits: hits})
	if rep.Verdict != verdictFail || rep.ReceiptHeader.Mismatch != 1 || rep.ReceiptHeader.Missing != 1 {
		t.Fatalf("receipt header = %+v verdict %s, want 1 mismatch and 1 missing", rep.ReceiptHeader, rep.Verdict)
	}
}

func TestIntegritySinkCorrelation(t *testing.T) {
	plan := newWorkload(1, 2, 40)
	dir := t.TempDir()
	writeSynthRecorder(t, dir, plan, synthSink, perfectReceipts(plan, modeBest))
	obs, err := scanRecorder(dir, plan, synthSink)
	if err != nil {
		t.Fatal(err)
	}
	build := func() ([]requestOutcome, []int) {
		outcomes := make([]requestOutcome, plan.total())
		hits := make([]int, plan.total())
		for slot := range outcomes {
			outcomes[slot] = requestOutcome{ran: true, status: 200}
			if plan.blocked(slot) {
				outcomes[slot].status = 403
				outcomes[slot].receiptHeader = actionIDFor(slot)
			} else {
				hits[slot] = 1
			}
		}
		return outcomes, hits
	}
	var allowed, blocked int
	for slot := range plan.total() {
		if plan.blocked(slot) && blocked == 0 {
			blocked = slot
		}
		if !plan.blocked(slot) && allowed == 0 {
			allowed = slot
		}
	}
	tests := []struct {
		name   string
		mutate func(hits []int)
		check  func(kindReport) bool
	}{
		{"blocked request reached the origin", func(h []int) { h[blocked] = 1 }, func(k kindReport) bool { return k.Unexpected == 1 }},
		{"allowed request never reached the origin", func(h []int) { h[allowed] = 0 }, func(k kindReport) bool { return k.Missing == 1 }},
		{"allowed request reached the origin twice", func(h []int) { h[allowed] = 2 }, func(k kindReport) bool { return k.Duplicate == 1 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outcomes, hits := build()
			tt.mutate(hits)
			rep := evaluateIntegrity(integrityInput{mode: modeBest, plan: plan, obs: obs, outcomes: outcomes, sinkHits: hits})
			if rep.Verdict != verdictFail || !tt.check(rep.Sink) {
				t.Fatalf("sink = %+v verdict %s", rep.Sink, rep.Verdict)
			}
		})
	}
	outcomes, hits := build()
	rep := evaluateIntegrity(integrityInput{mode: modeBest, plan: plan, obs: obs, outcomes: outcomes, sinkHits: hits, sinkUnknown: 2})
	if rep.Verdict != verdictFail || rep.Sink.Orphan != 2 {
		t.Fatalf("unknown sink keys: %+v", rep.Sink)
	}
}

// The production sanitizer keeps a DLP-clean query value and redacts a dirty
// one. The workload key must be clean, and the scanner must treat a redacted
// key as unusable.
func TestWorkloadKeySurvivesProductionSanitation(t *testing.T) {
	plan := newWorkload(1, 2, 40)
	clean := func(s string) bool { return !strings.Contains(s, fakeToken) }
	for slot := range plan.total() {
		target := "http://" + synthSink + plan.pathAndQuery(slot)
		got := receipt.SanitizeTarget(target, clean)
		key, ok := keyFromTarget(got)
		if !ok || key != plan.key(slot) {
			t.Fatalf("slot %d: key lost in sanitation: %q -> %q", slot, target, got)
		}
		if plan.blocked(slot) && strings.Contains(got, fakeToken) {
			t.Fatalf("slot %d: credential survived sanitation: %q", slot, got)
		}
	}
	dirty := receipt.SanitizeTarget("http://"+synthSink+"/ok?wk="+fakeToken, clean)
	if _, ok := keyFromTarget(dirty); !ok || !strings.Contains(dirty, "[redacted-value]") {
		t.Fatalf("expected a redacted placeholder, got %q", dirty)
	}
	s := &recorderScanner{plan: plan, sinkAddr: synthSink}
	if s.classify(dirty) != targetUncorrelatable {
		t.Fatal("a redacted workload key must be uncorrelatable")
	}
}
