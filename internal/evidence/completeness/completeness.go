// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package completeness analyzes signed receipt chains for bounded lifecycle
// evidence. Its best result is LIMITED: mediated evidence can bound what
// Pipelock saw, but it cannot prove the agent had no other egress path.
package completeness

import "github.com/luckyPipewrench/pipelock/internal/receipt"

// Status is the top-level completeness status vocabulary.
type Status string

const (
	StatusLimited    Status = "LIMITED"
	StatusBroken     Status = "BROKEN"
	StatusUnverified Status = "UNVERIFIED"
)

// Reason is the structured explanation for a report or per-run status.
type Reason string

const (
	ReasonBoundedClosed    Reason = "bounded_closed"
	ReasonAbnormalEnd      Reason = "abnormal_end"
	ReasonOpenAction       Reason = "open_action"
	ReasonHeartbeatGap     Reason = "heartbeat_gap"
	ReasonNoOpen           Reason = "no_open"
	ReasonNoLifecycle      Reason = "no_lifecycle"
	ReasonRecorderDisabled Reason = "recorder_disabled"
	ReasonNoReceipts       Reason = "no_receipts"
	ReasonChainBroken      Reason = "chain_broken"
)

// Report is the completeness analysis result for one extracted chain.
type Report struct {
	Path               string      `json:"path,omitempty"`
	Status             Status      `json:"status"`
	Reason             Reason      `json:"reason"`
	ReceiptCount       uint64      `json:"receipt_count"`
	FinalSeq           uint64      `json:"final_seq,omitempty"`
	RootHash           string      `json:"root_hash,omitempty"`
	SignaturesVerified bool        `json:"signatures_verified,omitempty"`
	Unpinned           bool        `json:"unpinned,omitempty"`
	Error              string      `json:"error,omitempty"`
	BrokenAtSeq        uint64      `json:"broken_at_seq,omitempty"`
	BrokenAtIndex      int         `json:"broken_at_index,omitempty"`
	Runs               []RunReport `json:"runs,omitempty"`
}

// RunReport describes completeness evidence for one run_nonce.
type RunReport struct {
	RunNonce              string              `json:"run_nonce"`
	Status                Status              `json:"status"`
	Reason                Reason              `json:"reason"`
	Intents               int                 `json:"intents"`
	Outcomes              int                 `json:"outcomes"`
	MatchedPairs          int                 `json:"matched_pairs"`
	UnmatchedIntents      int                 `json:"unmatched_intents"`
	Heartbeats            int                 `json:"heartbeats"`
	Closed                bool                `json:"closed"`
	FsyncErrorsGated      uint64              `json:"fsync_errors_gated"`
	DurabilityBlocks      uint64              `json:"durability_blocks"`
	DurabilityMonotonic   bool                `json:"durability_monotonic"`
	LastHeartbeat         *DurabilitySnapshot `json:"last_heartbeat,omitempty"`
	Close                 *DurabilitySnapshot `json:"close,omitempty"`
	OpenNonce             string              `json:"open_nonce,omitempty"`
	ChainOpenSeq          uint64              `json:"chain_open_seq,omitempty"`
	CloseFinalSeq         uint64              `json:"close_final_seq,omitempty"`
	CloseRootHash         string              `json:"close_root_hash,omitempty"`
	CloseReceiptCount     uint64              `json:"close_receipt_count,omitempty"`
	HeartbeatGapDetected  bool                `json:"heartbeat_gap_detected,omitempty"`
	StructuralViolation   string              `json:"structural_violation,omitempty"`
	OutcomeWithoutIntent  int                 `json:"outcome_without_intent,omitempty"`
	DuplicateSessionOpen  bool                `json:"duplicate_session_open,omitempty"`
	ContradictOpenNonce   bool                `json:"contradict_open_nonce,omitempty"`
	DurabilityCounterDrop bool                `json:"durability_counter_drop,omitempty"`
}

// DurabilitySnapshot carries the cumulative durability counters surfaced by a
// heartbeat or session_close receipt.
type DurabilitySnapshot struct {
	FsyncErrorsGated uint64 `json:"fsync_errors_gated"`
	DurabilityBlocks uint64 `json:"durability_blocks"`
}

type runState struct {
	report RunReport

	hasOpen  bool
	intents  map[string]int
	outcomes map[string]int

	lastBeat uint64
	sawBeat  bool

	lastDurability *DurabilitySnapshot
}

type recordContext struct {
	prefixCount      uint64
	hasPreCloseTail  bool
	preCloseFinalSeq uint64
	preCloseRootHash string
}

type lifecycleState struct {
	opened map[string]bool
	closed map[string]bool
}

// Analyze inspects a receipt chain and its integrity result, returning a
// bounded completeness report. A cryptographically or structurally broken chain
// is BROKEN. A chain with no lifecycle evidence is UNVERIFIED. A clean lifecycle
// window is still LIMITED, never green.
func Analyze(chain []receipt.Receipt, chainResult receipt.ChainResult) Report {
	report := Report{
		ReceiptCount: uint64(len(chain)),
		FinalSeq:     chainResult.FinalSeq,
		RootHash:     chainResult.RootHash,
	}
	if len(chain) == 0 {
		report.Status = StatusUnverified
		report.Reason = ReasonNoReceipts
		return report
	}

	if !chainResult.Valid && !isLifecycleOnlyChainFailure(chainResult) {
		return brokenReport(report, chainResult)
	}

	if !hasSessionControl(chain) {
		report.Status = StatusUnverified
		report.Reason = ReasonNoLifecycle
		report.Error = chainResult.Error
		return report
	}

	states := make(map[string]*runState)
	lifecycle := lifecycleState{
		opened: make(map[string]bool),
		closed: make(map[string]bool),
	}
	var order []string
	getRun := func(runNonce string) *runState {
		if runNonce == "" {
			runNonce = "(missing)"
		}
		if st, ok := states[runNonce]; ok {
			return st
		}
		st := &runState{
			report: RunReport{
				RunNonce:            runNonce,
				Status:              StatusLimited,
				Reason:              ReasonBoundedClosed,
				DurabilityMonotonic: true,
			},
			intents:  make(map[string]int),
			outcomes: make(map[string]int),
		}
		states[runNonce] = st
		order = append(order, runNonce)
		return st
	}

	var previous receipt.ActionRecord
	hasPrevious := false
	var segmentPrefixCount uint64
	for i := range chain {
		ar := chain[i].ActionRecord
		// session_close carries the emitter's SEGMENT-LOCAL FinalSeq/ReceiptCount,
		// including the close receipt itself:
		// a key rotation reopens a segment at chain_seq 0, so the observed prefix
		// used to verify a close's claims must reset at each KeyTransition boundary.
		// Counting from the whole file would falsely BROKEN a legitimate rotated
		// chain's (correct, segment-local) close.
		if ar.KeyTransition != nil {
			segmentPrefixCount = 0
		}
		ctx := recordContext{
			prefixCount:      segmentPrefixCount,
			preCloseRootHash: ar.ChainPrevHash,
		}
		if hasPrevious && segmentPrefixCount > 0 {
			ctx.hasPreCloseTail = true
			ctx.preCloseFinalSeq = previous.ChainSeq
		}
		previous = ar
		hasPrevious = true

		runNonce := effectiveRunNonce(ar)
		if ar.SessionControl == nil {
			if violation := validateLifecycleAction(lifecycle, ar); violation != "" {
				st := getRun(runNonce)
				markStructuralViolation(st, violation)
				segmentPrefixCount++
				continue
			}
		}
		if runNonce != "" || ar.SessionControl != nil {
			st := getRun(runNonce)
			if violation := applyRecord(st, ar, ctx); violation != "" {
				markStructuralViolation(st, violation)
			}
			updateLifecycleState(lifecycle, ar)
		}
		segmentPrefixCount++
	}

	for _, runNonce := range order {
		if runNonce == "(missing)" || lifecycle.opened[runNonce] {
			continue
		}
		markStructuralViolation(states[runNonce], "receipt run_nonce has no matching session_open")
	}

	for _, runNonce := range order {
		st := states[runNonce]
		finalizeRun(st)
		report.Runs = append(report.Runs, st.report)
		report.Status, report.Reason = worse(report.Status, report.Reason, st.report.Status, st.report.Reason)
	}
	if report.Status == "" {
		report.Status = StatusUnverified
		report.Reason = ReasonNoLifecycle
	}
	if report.Status == StatusBroken {
		report.Error = firstBrokenRunError(report.Runs, chainResult.Error)
		if report.BrokenAtSeq == 0 {
			report.BrokenAtSeq = chainResult.BrokenAtSeq
		}
		report.BrokenAtIndex = chainResult.BrokenAtIndex
		return report
	}
	if !chainResult.Valid {
		report.Error = chainResult.Error
	}
	return report
}

func hasSessionControl(chain []receipt.Receipt) bool {
	for i := range chain {
		if chain[i].ActionRecord.SessionControl != nil {
			return true
		}
	}
	return false
}

func isLifecycleOnlyChainFailure(res receipt.ChainResult) bool {
	return res.FailureKind == receipt.ChainFailureLifecycleOpen && res.IntegrityVerified
}

func brokenReport(report Report, chainResult receipt.ChainResult) Report {
	report.Status = StatusBroken
	report.Reason = ReasonChainBroken
	report.Error = chainResult.Error
	report.BrokenAtSeq = chainResult.BrokenAtSeq
	report.BrokenAtIndex = chainResult.BrokenAtIndex
	return report
}

func effectiveRunNonce(ar receipt.ActionRecord) string {
	if ar.RunNonce != "" {
		return ar.RunNonce
	}
	if ar.SessionControl == nil {
		return ""
	}
	switch ar.SessionControl.Kind {
	case receipt.SessionControlOpen:
		if ar.SessionControl.Open != nil {
			return ar.SessionControl.Open.RunNonce
		}
	case receipt.SessionControlHeartbeat:
		if ar.SessionControl.Heartbeat != nil {
			return ar.SessionControl.Heartbeat.RunNonce
		}
	case receipt.SessionControlClose:
		if ar.SessionControl.Close != nil {
			return ar.SessionControl.Close.RunNonce
		}
	}
	return ""
}

func validateLifecycleAction(lifecycle lifecycleState, ar receipt.ActionRecord) string {
	if ar.RunNonce == "" {
		return "action receipt missing run_nonce in lifecycle chain"
	}
	if !lifecycle.opened[ar.RunNonce] {
		return "action observed before matching session_open"
	}
	if lifecycle.closed[ar.RunNonce] {
		return "action observed after session_close"
	}
	return ""
}

func updateLifecycleState(lifecycle lifecycleState, ar receipt.ActionRecord) {
	if ar.SessionControl == nil {
		return
	}
	runNonce := effectiveRunNonce(ar)
	if runNonce == "" {
		return
	}
	switch ar.SessionControl.Kind {
	case receipt.SessionControlOpen:
		lifecycle.opened[runNonce] = true
		lifecycle.closed[runNonce] = false
	case receipt.SessionControlClose:
		lifecycle.closed[runNonce] = true
	}
}

func markStructuralViolation(st *runState, violation string) {
	if st.report.StructuralViolation == "" {
		st.report.StructuralViolation = violation
	}
	st.report.Status = StatusBroken
	st.report.Reason = ReasonChainBroken
}

func applyRecord(st *runState, ar receipt.ActionRecord, ctx recordContext) string {
	if st.report.Closed {
		return "record observed after session_close"
	}

	switch ar.DecisionPhase {
	case receipt.DecisionPhaseIntent:
		st.report.Intents++
		st.intents[ar.ActionID]++
	case receipt.DecisionPhaseOutcome:
		st.report.Outcomes++
		st.outcomes[ar.ActionID]++
	}

	ctrl := ar.SessionControl
	if ctrl == nil {
		return ""
	}
	payloads := 0
	if ctrl.Open != nil {
		payloads++
	}
	if ctrl.Heartbeat != nil {
		payloads++
	}
	if ctrl.Close != nil {
		payloads++
	}
	if payloads != 1 {
		return "session_control must carry exactly one payload"
	}

	switch ctrl.Kind {
	case receipt.SessionControlOpen:
		return applyOpen(st, ar, ctrl.Open)
	case receipt.SessionControlHeartbeat:
		return applyHeartbeat(st, ar, ctrl.Heartbeat)
	case receipt.SessionControlClose:
		return applyClose(st, ar, ctrl.Close, ctx)
	default:
		return "unknown session_control kind"
	}
}

func applyOpen(st *runState, ar receipt.ActionRecord, open *receipt.SessionOpen) string {
	if open == nil {
		return "session_open kind missing open payload"
	}
	if ar.RunNonce == "" || open.RunNonce != ar.RunNonce {
		return "session_open run_nonce does not match receipt run_nonce"
	}
	if open.OpenNonce == "" {
		return "session_open open_nonce is empty"
	}
	if open.ChainOpenSeq != ar.ChainSeq {
		return "session_open chain_open_seq does not match receipt chain_seq"
	}
	if st.hasOpen {
		st.report.DuplicateSessionOpen = true
		return "duplicate session_open for run_nonce"
	}
	st.hasOpen = true
	st.report.OpenNonce = open.OpenNonce
	st.report.ChainOpenSeq = open.ChainOpenSeq
	return ""
}

func applyHeartbeat(st *runState, ar receipt.ActionRecord, heartbeat *receipt.SessionHeartbeat) string {
	if heartbeat == nil {
		return "heartbeat kind missing heartbeat payload"
	}
	if ar.RunNonce == "" || heartbeat.RunNonce != ar.RunNonce {
		return "heartbeat run_nonce does not match receipt run_nonce"
	}
	if !st.hasOpen {
		return "heartbeat observed before session_open"
	}
	if heartbeat.OpenNonce != st.report.OpenNonce {
		st.report.ContradictOpenNonce = true
		return "heartbeat open_nonce does not match session_open"
	}
	if heartbeat.ChainHead != ar.ChainPrevHash {
		return "heartbeat chain_head does not match observed pre-heartbeat chain hash"
	}
	if heartbeat.ChainSeqHead != ar.ChainSeq-1 {
		return "heartbeat chain_seq_head does not match observed pre-heartbeat chain seq"
	}
	st.report.Heartbeats++
	if st.sawBeat {
		if heartbeat.Beat != st.lastBeat+1 {
			st.report.HeartbeatGapDetected = true
		}
	} else if heartbeat.Beat != 1 {
		st.report.HeartbeatGapDetected = true
	}
	st.sawBeat = true
	st.lastBeat = heartbeat.Beat

	snapshot := DurabilitySnapshot{
		FsyncErrorsGated: heartbeat.FsyncErrorsGated,
		DurabilityBlocks: heartbeat.DurabilityBlocks,
	}
	st.report.LastHeartbeat = &snapshot
	return applyDurability(st, snapshot)
}

func applyClose(st *runState, ar receipt.ActionRecord, closeRecord *receipt.SessionClose, ctx recordContext) string {
	if closeRecord == nil {
		return "session_close kind missing close payload"
	}
	if ar.RunNonce == "" || closeRecord.RunNonce != ar.RunNonce {
		return "session_close run_nonce does not match receipt run_nonce"
	}
	if !st.hasOpen {
		return "session_close observed before session_open"
	}
	if closeRecord.OpenNonce != st.report.OpenNonce {
		st.report.ContradictOpenNonce = true
		return "session_close open_nonce does not match session_open"
	}
	st.report.Closed = true
	st.report.CloseFinalSeq = closeRecord.FinalSeq
	st.report.CloseRootHash = closeRecord.RootHash
	st.report.CloseReceiptCount = closeRecord.ReceiptCount
	if closeRecord.RootHash != ctx.preCloseRootHash {
		return "session_close root_hash does not match sealed pre-close tail hash"
	}
	if closeRecord.ReceiptCount != ctx.prefixCount+1 {
		return "session_close receipt_count does not match observed receipt count"
	}
	if closeRecord.FinalSeq != ar.ChainSeq {
		return "session_close final_seq mismatch"
	}
	snapshot := DurabilitySnapshot{
		FsyncErrorsGated: closeRecord.FsyncErrorsGated,
		DurabilityBlocks: closeRecord.DurabilityBlocks,
	}
	st.report.Close = &snapshot
	return applyDurability(st, snapshot)
}

func applyDurability(st *runState, snapshot DurabilitySnapshot) string {
	if st.lastDurability != nil {
		if snapshot.FsyncErrorsGated < st.lastDurability.FsyncErrorsGated ||
			snapshot.DurabilityBlocks < st.lastDurability.DurabilityBlocks {
			st.report.DurabilityCounterDrop = true
			st.report.DurabilityMonotonic = false
			return "durability counters decreased"
		}
	}
	st.lastDurability = &snapshot
	st.report.FsyncErrorsGated = snapshot.FsyncErrorsGated
	st.report.DurabilityBlocks = snapshot.DurabilityBlocks
	return ""
}

func finalizeRun(st *runState) {
	if st.report.Status == StatusBroken {
		return
	}
	for actionID, n := range st.intents {
		outcomes := st.outcomes[actionID]
		if outcomes >= n {
			st.report.MatchedPairs += n
			continue
		}
		st.report.MatchedPairs += outcomes
		st.report.UnmatchedIntents += n - outcomes
	}
	for actionID, outcomes := range st.outcomes {
		if st.intents[actionID] == 0 {
			st.report.OutcomeWithoutIntent += outcomes
		}
	}
	if st.report.OutcomeWithoutIntent > 0 {
		st.report.Status = StatusBroken
		st.report.Reason = ReasonChainBroken
		st.report.StructuralViolation = "outcome without matching intent"
		return
	}
	switch {
	case !st.hasOpen:
		st.report.Status = StatusUnverified
		st.report.Reason = ReasonNoOpen
	case st.report.UnmatchedIntents > 0:
		st.report.Status = StatusLimited
		st.report.Reason = ReasonOpenAction
	case st.report.HeartbeatGapDetected:
		st.report.Status = StatusLimited
		st.report.Reason = ReasonHeartbeatGap
	case !st.report.Closed:
		st.report.Status = StatusLimited
		st.report.Reason = ReasonAbnormalEnd
	default:
		st.report.Status = StatusLimited
		st.report.Reason = ReasonBoundedClosed
	}
}

func worse(curStatus Status, curReason Reason, nextStatus Status, nextReason Reason) (Status, Reason) {
	if severity(nextStatus) > severity(curStatus) {
		return nextStatus, nextReason
	}
	if severity(nextStatus) == severity(curStatus) && reasonSeverity(nextReason) > reasonSeverity(curReason) {
		return nextStatus, nextReason
	}
	if curStatus == "" {
		return nextStatus, nextReason
	}
	return curStatus, curReason
}

func severity(status Status) int {
	switch status {
	case StatusBroken:
		return 3
	case StatusUnverified:
		return 2
	case StatusLimited:
		return 1
	default:
		return 0
	}
}

func reasonSeverity(reason Reason) int {
	switch reason {
	case ReasonChainBroken:
		return 100
	case ReasonNoOpen:
		return 80
	case ReasonNoLifecycle, ReasonRecorderDisabled, ReasonNoReceipts:
		return 70
	case ReasonOpenAction:
		return 50
	case ReasonHeartbeatGap:
		return 40
	case ReasonAbnormalEnd:
		return 30
	case ReasonBoundedClosed:
		return 10
	default:
		return 0
	}
}

func firstBrokenRunError(runs []RunReport, fallback string) string {
	for _, run := range runs {
		if run.Status == StatusBroken && run.StructuralViolation != "" {
			return run.StructuralViolation
		}
	}
	return fallback
}
