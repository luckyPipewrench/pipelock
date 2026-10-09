// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"strings"
)

const (
	modeOff      = "off"
	modeBest     = "best"
	modeRequired = "required"

	verdictPass = "pass"
	verdictFail = "fail"

	statusOK          = "ok"
	statusFail        = "fail"
	statusUnavailable = "UNAVAILABLE"
)

// expectedReceipts is how many receipts of each kind one request must leave.
type expectedReceipts [kindCount]int32

// expectedFor derives the receipt set a request must leave behind from the
// flight recorder mode and the request class. These are the production
// semantics of the plain-HTTP forward path:
//
//   - off: the recorder is disabled, so no receipt of any kind exists.
//   - blocked, best or required: one phase-less block receipt, one v2
//     receipt, and one AEL activity.
//   - allowed, best: one phase-less allow receipt, one v2 receipt, and one
//     AEL activity. Outcome receipts exist only when require_receipts is on.
//   - allowed, required: an intent and an outcome receipt sharing one
//     ActionID, one v2 receipt per phase, and one AEL activity per phase.
//
// The v2 receipt drops ActionID and phase by design, so its expected count is
// the number of v1 receipts the request leaves, matched through the key only.
func expectedFor(mode string, blocked bool) expectedReceipts {
	var e expectedReceipts
	switch {
	case mode == modeOff:
	case blocked:
		e[kindV1Block], e[kindV2], e[kindAEL] = 1, 1, 1
	case mode == modeBest:
		e[kindV1Allow], e[kindV2], e[kindAEL] = 1, 1, 1
	case mode == modeRequired:
		e[kindV1Intent], e[kindV1Outcome], e[kindV2], e[kindAEL] = 1, 1, 2, 2
	}
	return e
}

// expectsReceiptHeader reports whether the proxy hands the recorded ActionID
// back to the caller: for every block, and for allowed requests only when
// require_receipts is on.
func expectsReceiptHeader(mode string, blocked bool) bool {
	switch mode {
	case modeRequired:
		return true
	case modeBest:
		return blocked
	}
	return false
}

// kindReport is the identity-based accounting for one receipt kind.
//
//   - missing: receipts a request must leave but did not.
//   - duplicate: receipts beyond what a request should leave of a kind it
//     should leave.
//   - unexpected: receipts of a kind the request should not leave at all.
//   - orphan: receipts aimed at the sink whose key is outside the plan.
//   - uncorrelatable: receipts aimed at the sink (or sanitized past
//     recognition) that carry no usable key, so no request can own them. Any
//     such receipt makes the kind UNAVAILABLE: completeness cannot be claimed
//     and nothing is guessed from adjacency or counts.
type kindReport struct {
	Expected       int    `json:"expected"`
	Observed       int    `json:"observed"`
	Missing        int    `json:"missing"`
	Duplicate      int    `json:"duplicate"`
	Unexpected     int    `json:"unexpected"`
	Orphan         int    `json:"orphan"`
	Uncorrelatable int    `json:"uncorrelatable"`
	Status         string `json:"status"`
	FirstProblem   string `json:"first_problem,omitempty"`
}

func (k *kindReport) finish(unavailable bool) {
	switch {
	case unavailable || k.Uncorrelatable > 0:
		k.Status = statusUnavailable
	case k.Missing > 0 || k.Duplicate > 0 || k.Unexpected > 0 || k.Orphan > 0:
		k.Status = statusFail
	default:
		k.Status = statusOK
	}
}

func (k *kindReport) noteProblem(text string) {
	if k.FirstProblem == "" {
		k.FirstProblem = text
	}
}

type headerReport struct {
	Expected     int    `json:"expected"`
	Missing      int    `json:"missing"`
	Mismatch     int    `json:"mismatch"`
	FirstProblem string `json:"first_problem,omitempty"`
}

func (h *headerReport) noteProblem(text string) {
	if h.FirstProblem == "" {
		h.FirstProblem = text
	}
}

// integrityReport is the integrity verdict and the accounting behind it.
type integrityReport struct {
	Verdict           string                `json:"verdict"`
	Reasons           []string              `json:"reasons"`
	Kinds             map[string]kindReport `json:"kinds"`
	Sink              kindReport            `json:"sink"`
	ReceiptHeader     headerReport          `json:"receipt_header"`
	ReceiptMissing    int                   `json:"receipt_missing"`
	AmbiguousRequests int                   `json:"ambiguous_requests"`
	ControlReceipts   int                   `json:"control_receipts"`
	RecorderFiles     int                   `json:"recorder_files"`
	AELFiles          int                   `json:"ael_files"`
	OrphanSamples     []string              `json:"orphan_samples,omitempty"`
	Shutdown          shutdownReport        `json:"shutdown"`
	Verify            verifyReport          `json:"verify"`
}

type shutdownReport struct {
	Clean bool   `json:"clean"`
	Error string `json:"error,omitempty"`
}

type verifyReport struct {
	Ran    bool   `json:"ran"`
	Exit   int    `json:"exit"`
	Output string `json:"output,omitempty"`
}

func (r *integrityReport) fail(reason string) {
	r.Verdict = verdictFail
	r.Reasons = append(r.Reasons, reason)
}

// integrityInput is everything evaluateIntegrity compares. outcomes and
// sinkHits are indexed by global slot.
type integrityInput struct {
	mode        string
	plan        workload
	obs         *recorderObservation
	outcomes    []requestOutcome
	sinkHits    []int
	sinkUnknown int64
}

// evaluateIntegrity compares what each planned request should have left
// behind with what the recorder and the sink actually hold, by identity.
func evaluateIntegrity(in integrityInput) integrityReport {
	rep := integrityReport{Verdict: verdictPass, Kinds: make(map[string]kindReport, kindCount), Reasons: []string{}}
	obs := in.obs
	if obs == nil {
		obs = newRecorderObservation(in.plan.total())
	}
	if in.mode == modeOff && (obs.controlReceipts > 0 || obs.recorderFiles > 0 || obs.aelFiles > 0) {
		rep.fail("off mode contains recorder evidence")
	}
	var kinds [kindCount]kindReport
	var sink kindReport
	ambiguous := 0

	for slot := range in.plan.total() {
		blocked := in.plan.blocked(slot)
		want := expectedFor(in.mode, blocked)
		got := &obs.slots[slot]
		key := in.plan.key(slot)
		for k := range kindCount {
			accountSlot(&kinds[k], int(want[k]), int(got.counts[k]), key)
		}
		if len(got.actionIDs) > 1 {
			ambiguous++
			kinds[kindAEL].noteProblem(fmt.Sprintf("%s maps to %d ActionIDs", key, len(got.actionIDs)))
		}
		accountHeader(&rep.ReceiptHeader, in.mode, blocked, in.outcomes[slot], got, key)
		accountSink(&sink, blocked, in.sinkHits[slot], key)
	}
	sink.Orphan += int(in.sinkUnknown)
	sink.finish(false)

	for k := range kindCount {
		kinds[k].Orphan += obs.orphans[k]
		kinds[k].Uncorrelatable += obs.uncorrelatable[k]
		// Several v1 ActionIDs for one key make ActionID-keyed AEL
		// attribution ambiguous, so AEL completeness cannot be claimed.
		kinds[k].finish(k == kindAEL && ambiguous > 0)
		rep.Kinds[k.String()] = kinds[k]
		rep.ReceiptMissing += kinds[k].Missing
	}
	rep.Sink = sink
	rep.AmbiguousRequests = ambiguous
	rep.ControlReceipts = obs.controlReceipts
	rep.RecorderFiles = obs.recorderFiles
	rep.AELFiles = obs.aelFiles
	rep.OrphanSamples = obs.orphanSamples

	for k := range kindCount {
		name := k.String()
		kr := rep.Kinds[name]
		if kr.Status != statusOK {
			rep.fail(describeKind(name, kr))
		}
	}
	if sink.Status != statusOK {
		rep.fail(describeKind("sink", sink))
	}
	if ambiguous > 0 {
		rep.fail(fmt.Sprintf("%d requests map to more than one ActionID; AEL attribution is UNAVAILABLE", ambiguous))
	}
	if rep.ReceiptHeader.Missing > 0 || rep.ReceiptHeader.Mismatch > 0 {
		rep.fail(fmt.Sprintf("receipt header: %d missing, %d disagree with the recorded ActionID, of %d expected (first: %s)", rep.ReceiptHeader.Missing, rep.ReceiptHeader.Mismatch, rep.ReceiptHeader.Expected, rep.ReceiptHeader.FirstProblem))
	}
	return rep
}

func accountSlot(k *kindReport, want, got int, key string) {
	k.Expected += want
	k.Observed += got
	switch {
	case got < want:
		k.Missing += want - got
		k.noteProblem(fmt.Sprintf("%s: want %d, found %d", key, want, got))
	case want == 0 && got > 0:
		k.Unexpected += got
		k.noteProblem(fmt.Sprintf("%s: want none, found %d", key, got))
	case got > want:
		k.Duplicate += got - want
		k.noteProblem(fmt.Sprintf("%s: want %d, found %d", key, want, got))
	}
}

// accountHeader cross-checks the response header against the ActionID the
// recorder holds for the same request, an identity link that does not depend
// on the workload key.
func accountHeader(h *headerReport, mode string, blocked bool, out requestOutcome, got *slotObservation, key string) {
	if !out.ran || out.transportErr || !expectsReceiptHeader(mode, blocked) {
		return
	}
	h.Expected++
	switch {
	case out.receiptHeader == "":
		h.Missing++
		h.noteProblem(key + ": response carried no receipt header")
	case len(got.actionIDs) != 1 || got.actionIDs[0] != out.receiptHeader:
		h.Mismatch++
		h.noteProblem(fmt.Sprintf("%s: header ActionID %q is not the recorded %v", key, out.receiptHeader, got.actionIDs))
	}
}

// accountSink compares the per-key sink hits with the plan: an allowed request
// reaches the origin exactly once and a blocked request never does.
func accountSink(k *kindReport, blocked bool, hits int, key string) {
	want := 1
	if blocked {
		want = 0
	}
	k.Expected += want
	k.Observed += hits
	switch {
	case hits < want:
		k.Missing += want - hits
		k.noteProblem(fmt.Sprintf("%s: origin saw %d, want %d", key, hits, want))
	case want == 0 && hits > 0:
		k.Unexpected += hits
		k.noteProblem(fmt.Sprintf("%s: blocked request reached the origin %d time(s)", key, hits))
	case hits > want:
		k.Duplicate += hits - want
		k.noteProblem(fmt.Sprintf("%s: origin saw %d, want %d", key, hits, want))
	}
}

func describeKind(name string, k kindReport) string {
	var parts []string
	for _, p := range []struct {
		label string
		n     int
	}{{"missing", k.Missing}, {"duplicate", k.Duplicate}, {"unexpected", k.Unexpected}, {"orphan", k.Orphan}, {"uncorrelatable", k.Uncorrelatable}} {
		if p.n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", p.n, p.label))
		}
	}
	text := fmt.Sprintf("%s %s", name, k.Status)
	if len(parts) > 0 {
		text += ": " + strings.Join(parts, ", ")
	}
	if k.FirstProblem != "" {
		text += " (first: " + k.FirstProblem + ")"
	}
	return text
}
