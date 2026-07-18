// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package completeness

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

func TestMalformedSessionControlRecordsFailClosed(t *testing.T) {
	t.Parallel()

	baseState := func() *runState {
		return &runState{
			report: RunReport{
				RunNonce:            "run-test",
				Status:              StatusLimited,
				Reason:              ReasonBoundedClosed,
				DurabilityMonotonic: true,
				OpenNonce:           "open-test",
			},
			hasOpen:  true,
			intents:  make(map[string]int),
			outcomes: make(map[string]int),
		}
	}
	baseRecord := func() receipt.ActionRecord {
		return receipt.ActionRecord{RunNonce: "run-test", ChainSeq: 4, ChainPrevHash: "head"}
	}

	tests := map[string]struct {
		mutate func(*runState, *receipt.ActionRecord)
		want   string
	}{
		"no_payload": {
			mutate: func(_ *runState, ar *receipt.ActionRecord) {
				ar.SessionControl = &receipt.SessionControl{Kind: receipt.SessionControlOpen}
			},
			want: "exactly one payload",
		},
		"multiple_payloads": {
			mutate: func(_ *runState, ar *receipt.ActionRecord) {
				ar.SessionControl = &receipt.SessionControl{
					Kind:  receipt.SessionControlOpen,
					Open:  &receipt.SessionOpen{},
					Close: &receipt.SessionClose{},
				}
			},
			want: "exactly one payload",
		},
		"unknown_kind": {
			mutate: func(_ *runState, ar *receipt.ActionRecord) {
				ar.SessionControl = &receipt.SessionControl{
					Kind: "future-kind",
					Open: &receipt.SessionOpen{},
				}
			},
			want: "unknown session_control kind",
		},
		"open_run_mismatch": {
			mutate: func(st *runState, ar *receipt.ActionRecord) {
				st.hasOpen = false
				ar.SessionControl = &receipt.SessionControl{
					Kind: receipt.SessionControlOpen,
					Open: &receipt.SessionOpen{RunNonce: "other", OpenNonce: "open-test", ChainOpenSeq: 4},
				}
			},
			want: "run_nonce does not match",
		},
		"open_nonce_empty": {
			mutate: func(st *runState, ar *receipt.ActionRecord) {
				st.hasOpen = false
				ar.SessionControl = &receipt.SessionControl{
					Kind: receipt.SessionControlOpen,
					Open: &receipt.SessionOpen{RunNonce: "run-test", ChainOpenSeq: 4},
				}
			},
			want: "open_nonce is empty",
		},
		"open_sequence_mismatch": {
			mutate: func(st *runState, ar *receipt.ActionRecord) {
				st.hasOpen = false
				ar.SessionControl = &receipt.SessionControl{
					Kind: receipt.SessionControlOpen,
					Open: &receipt.SessionOpen{RunNonce: "run-test", OpenNonce: "open-test", ChainOpenSeq: 3},
				}
			},
			want: "chain_open_seq does not match",
		},
		"duplicate_open": {
			mutate: func(_ *runState, ar *receipt.ActionRecord) {
				ar.SessionControl = &receipt.SessionControl{
					Kind: receipt.SessionControlOpen,
					Open: &receipt.SessionOpen{RunNonce: "run-test", OpenNonce: "open-test", ChainOpenSeq: 4},
				}
			},
			want: "duplicate session_open",
		},
		"heartbeat_run_mismatch": {
			mutate: func(_ *runState, ar *receipt.ActionRecord) {
				ar.SessionControl = &receipt.SessionControl{
					Kind: receipt.SessionControlHeartbeat,
					Heartbeat: &receipt.SessionHeartbeat{
						RunNonce: "other", OpenNonce: "open-test",
					},
				}
			},
			want: "run_nonce does not match",
		},
		"heartbeat_before_open": {
			mutate: func(st *runState, ar *receipt.ActionRecord) {
				st.hasOpen = false
				ar.SessionControl = &receipt.SessionControl{
					Kind: receipt.SessionControlHeartbeat,
					Heartbeat: &receipt.SessionHeartbeat{
						RunNonce: "run-test", OpenNonce: "open-test",
					},
				}
			},
			want: "before session_open",
		},
		"heartbeat_open_mismatch": {
			mutate: func(_ *runState, ar *receipt.ActionRecord) {
				ar.SessionControl = &receipt.SessionControl{
					Kind: receipt.SessionControlHeartbeat,
					Heartbeat: &receipt.SessionHeartbeat{
						RunNonce: "run-test", OpenNonce: "other",
					},
				}
			},
			want: "open_nonce does not match",
		},
		"heartbeat_head_mismatch": {
			mutate: func(_ *runState, ar *receipt.ActionRecord) {
				ar.SessionControl = &receipt.SessionControl{
					Kind: receipt.SessionControlHeartbeat,
					Heartbeat: &receipt.SessionHeartbeat{
						RunNonce: "run-test", OpenNonce: "open-test", ChainHead: "other", ChainSeqHead: 3,
					},
				}
			},
			want: "chain_head does not match",
		},
		"heartbeat_sequence_mismatch": {
			mutate: func(_ *runState, ar *receipt.ActionRecord) {
				ar.SessionControl = &receipt.SessionControl{
					Kind: receipt.SessionControlHeartbeat,
					Heartbeat: &receipt.SessionHeartbeat{
						RunNonce: "run-test", OpenNonce: "open-test", ChainHead: "head", ChainSeqHead: 2,
					},
				}
			},
			want: "chain_seq_head does not match",
		},
		"close_run_mismatch": {
			mutate: func(_ *runState, ar *receipt.ActionRecord) {
				ar.SessionControl = &receipt.SessionControl{
					Kind:  receipt.SessionControlClose,
					Close: &receipt.SessionClose{RunNonce: "other", OpenNonce: "open-test"},
				}
			},
			want: "run_nonce does not match",
		},
		"close_before_open": {
			mutate: func(st *runState, ar *receipt.ActionRecord) {
				st.hasOpen = false
				ar.SessionControl = &receipt.SessionControl{
					Kind:  receipt.SessionControlClose,
					Close: &receipt.SessionClose{RunNonce: "run-test", OpenNonce: "open-test"},
				}
			},
			want: "before session_open",
		},
		"close_open_mismatch": {
			mutate: func(_ *runState, ar *receipt.ActionRecord) {
				ar.SessionControl = &receipt.SessionControl{
					Kind:  receipt.SessionControlClose,
					Close: &receipt.SessionClose{RunNonce: "run-test", OpenNonce: "other"},
				}
			},
			want: "open_nonce does not match",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			st := baseState()
			ar := baseRecord()
			tc.mutate(st, &ar)

			violation := applyRecord(st, ar, recordContext{prefixCount: 4, preCloseRootHash: "head"})
			if !strings.Contains(violation, tc.want) {
				t.Fatalf("violation = %q, want substring %q", violation, tc.want)
			}
			markStructuralViolation(st, violation)
			if st.report.Status != StatusBroken || st.report.Reason != ReasonChainBroken {
				t.Fatalf("malformed record did not fail closed: %#v", st.report)
			}
		})
	}
}

func TestSessionControlNonceExtractionAndLifecycleBounds(t *testing.T) {
	t.Parallel()

	controls := []struct {
		name string
		ctrl *receipt.SessionControl
	}{
		{
			name: "open",
			ctrl: &receipt.SessionControl{
				Kind: receipt.SessionControlOpen,
				Open: &receipt.SessionOpen{RunNonce: "from-open"},
			},
		},
		{
			name: "heartbeat",
			ctrl: &receipt.SessionControl{
				Kind:      receipt.SessionControlHeartbeat,
				Heartbeat: &receipt.SessionHeartbeat{RunNonce: "from-heartbeat"},
			},
		},
		{
			name: "close",
			ctrl: &receipt.SessionControl{
				Kind:  receipt.SessionControlClose,
				Close: &receipt.SessionClose{RunNonce: "from-close"},
			},
		},
	}
	for _, tc := range controls {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := effectiveRunNonce(receipt.ActionRecord{SessionControl: tc.ctrl})
			if got == "" || !strings.HasPrefix(got, "from-") {
				t.Fatalf("effective run nonce = %q", got)
			}
		})
	}

	lifecycle := lifecycleState{opened: map[string]bool{}, closed: map[string]bool{}}
	updateLifecycleState(lifecycle, receipt.ActionRecord{})
	updateLifecycleState(lifecycle, receipt.ActionRecord{
		SessionControl: &receipt.SessionControl{
			Kind: receipt.SessionControlOpen,
			Open: &receipt.SessionOpen{RunNonce: "run-bounds"},
		},
	})
	if !lifecycle.opened["run-bounds"] || lifecycle.closed["run-bounds"] {
		t.Fatalf("open did not establish lifecycle bounds: %#v", lifecycle)
	}
	updateLifecycleState(lifecycle, receipt.ActionRecord{
		SessionControl: &receipt.SessionControl{
			Kind:  receipt.SessionControlClose,
			Close: &receipt.SessionClose{RunNonce: "run-bounds"},
		},
	})
	if !lifecycle.closed["run-bounds"] {
		t.Fatalf("close did not seal lifecycle bounds: %#v", lifecycle)
	}
}

func TestClassificationHelpersPreserveWorstFailClosedConclusion(t *testing.T) {
	t.Parallel()

	status, reason := worse(StatusLimited, ReasonBoundedClosed, StatusUnverified, ReasonNoOpen)
	if status != StatusUnverified || reason != ReasonNoOpen {
		t.Fatalf("worse status = %s/%s", status, reason)
	}
	status, reason = worse(StatusLimited, ReasonAbnormalEnd, StatusLimited, ReasonOpenAction)
	if status != StatusLimited || reason != ReasonOpenAction {
		t.Fatalf("worse reason = %s/%s", status, reason)
	}
	status, reason = worse("", "", StatusLimited, ReasonBoundedClosed)
	if status != StatusLimited || reason != ReasonBoundedClosed {
		t.Fatalf("empty rollup = %s/%s", status, reason)
	}

	for _, tc := range []struct {
		status Status
		want   int
	}{
		{StatusBroken, 3},
		{StatusUnverified, 2},
		{StatusLimited, 1},
		{"future", 0},
	} {
		if got := severity(tc.status); got != tc.want {
			t.Fatalf("severity(%q) = %d, want %d", tc.status, got, tc.want)
		}
	}

	reasons := []Reason{
		ReasonChainBroken,
		ReasonNoOpen,
		ReasonNoLifecycle,
		ReasonRecorderDisabled,
		ReasonNoReceipts,
		ReasonOpenAction,
		ReasonHeartbeatGap,
		ReasonAbnormalEnd,
		ReasonBoundedClosed,
		"future",
	}
	last := 101
	for _, candidate := range reasons {
		got := reasonSeverity(candidate)
		if got > last {
			t.Fatalf("reason severity increased from %d to %d for %q", last, got, candidate)
		}
		last = got
	}

	fallback := firstBrokenRunError([]RunReport{{Status: StatusLimited}}, "integrity failure")
	if fallback != "integrity failure" {
		t.Fatalf("fallback error = %q", fallback)
	}
}

func TestMalformedTypedPayloadsAndMissingLifecycleStateFailClosed(t *testing.T) {
	t.Parallel()

	st := &runState{
		report: RunReport{
			RunNonce:            "run-test",
			Status:              StatusLimited,
			Reason:              ReasonBoundedClosed,
			DurabilityMonotonic: true,
			OpenNonce:           "open-test",
		},
		hasOpen:  true,
		intents:  map[string]int{},
		outcomes: map[string]int{},
	}
	ar := receipt.ActionRecord{RunNonce: "run-test", ChainSeq: 2, ChainPrevHash: "head"}

	for name, run := range map[string]func() string{
		"nil_open":      func() string { return applyOpen(st, ar, nil) },
		"nil_heartbeat": func() string { return applyHeartbeat(st, ar, nil) },
		"nil_close":     func() string { return applyClose(st, ar, nil, recordContext{}) },
	} {
		t.Run(name, func(t *testing.T) {
			if violation := run(); violation == "" {
				t.Fatal("nil typed payload was accepted")
			}
		})
	}

	if got := effectiveRunNonce(receipt.ActionRecord{
		SessionControl: &receipt.SessionControl{Kind: "future-kind"},
	}); got != "" {
		t.Fatalf("unknown control kind yielded run nonce %q", got)
	}
	lifecycle := lifecycleState{opened: map[string]bool{}, closed: map[string]bool{}}
	updateLifecycleState(lifecycle, receipt.ActionRecord{
		SessionControl: &receipt.SessionControl{
			Kind: receipt.SessionControlOpen,
			Open: &receipt.SessionOpen{},
		},
	})
	if len(lifecycle.opened) != 0 || len(lifecycle.closed) != 0 {
		t.Fatalf("missing run nonce mutated lifecycle state: %#v", lifecycle)
	}

	firstBeat := &runState{
		report: RunReport{
			RunNonce:            "run-test",
			Status:              StatusLimited,
			Reason:              ReasonBoundedClosed,
			DurabilityMonotonic: true,
			OpenNonce:           "open-test",
		},
		hasOpen:  true,
		intents:  map[string]int{},
		outcomes: map[string]int{},
	}
	violation := applyHeartbeat(firstBeat, ar, &receipt.SessionHeartbeat{
		RunNonce: "run-test", OpenNonce: "open-test", ChainHead: "head", ChainSeqHead: 1, Beat: 2,
	})
	if violation != "" || !firstBeat.report.HeartbeatGapDetected {
		t.Fatalf("out-of-bounds first heartbeat = %q, report %#v", violation, firstBeat.report)
	}

	noOpen := &runState{
		report:   RunReport{Status: StatusLimited, Reason: ReasonBoundedClosed},
		intents:  map[string]int{},
		outcomes: map[string]int{},
	}
	finalizeRun(noOpen)
	if noOpen.report.Status != StatusUnverified || noOpen.report.Reason != ReasonNoOpen {
		t.Fatalf("missing open did not remain unverified: %#v", noOpen.report)
	}

	status, reason := worse("", "", "", "")
	if status != "" || reason != "" {
		t.Fatalf("empty equal-severity rollup = %q/%q", status, reason)
	}
}

func TestLifecycleOnlyIntegrityWarningIsPreserved(t *testing.T) {
	t.Parallel()

	b := newChainBuilder(t)
	chain := []receipt.Receipt{b.open()}
	report := Analyze(chain, receipt.ChainResult{
		FailureKind:       receipt.ChainFailureLifecycleOpen,
		IntegrityVerified: true,
		Error:             "lifecycle verifier warning",
	})
	if report.Status != StatusLimited || report.Reason != ReasonAbnormalEnd {
		t.Fatalf("continued lifecycle analysis = %s/%s: %#v", report.Status, report.Reason, report)
	}
	if report.Error != "lifecycle verifier warning" {
		t.Fatalf("integrity warning was dropped: %#v", report)
	}
}
