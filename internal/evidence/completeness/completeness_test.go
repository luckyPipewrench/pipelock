// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package completeness

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

const (
	testRunNonce  = "run-completeness-a"
	testOpenNonce = "open-completeness-a"
)

type chainBuilder struct {
	t      *testing.T
	priv   ed25519.PrivateKey
	keyHex string
	prev   string
	seq    uint64
	base   time.Time
	offset time.Duration
}

type rotationKey struct {
	priv   ed25519.PrivateKey
	keyHex string
}

func newChainBuilder(t *testing.T) *chainBuilder {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	return &chainBuilder{
		t:      t,
		priv:   priv,
		keyHex: hex.EncodeToString(pub),
		prev:   receipt.GenesisHash,
		base:   time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC),
	}
}

func newRotationKey(t *testing.T) rotationKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	return rotationKey{
		priv:   priv,
		keyHex: hex.EncodeToString(pub),
	}
}

func (b *chainBuilder) sign(ar receipt.ActionRecord) receipt.Receipt {
	b.t.Helper()
	if ar.Version == 0 {
		ar.Version = receipt.ActionRecordVersion
	}
	if ar.ActionID == "" {
		ar.ActionID = receipt.NewActionID()
	}
	if ar.ActionType == "" {
		ar.ActionType = receipt.ActionRead
	}
	if ar.Timestamp.IsZero() {
		ar.Timestamp = b.base.Add(b.offset)
	}
	if ar.Target == "" {
		ar.Target = "https://api.vendor.example/completeness"
	}
	if ar.Verdict == "" {
		ar.Verdict = "allow"
	}
	if ar.Transport == "" {
		ar.Transport = "fetch"
	}
	if ar.PolicyHash == "" {
		ar.PolicyHash = "policy-completeness"
	}
	ar.ChainPrevHash = b.prev
	ar.ChainSeq = b.seq
	r, err := receipt.Sign(ar, b.priv)
	if err != nil {
		b.t.Fatalf("Sign: %v", err)
	}
	hash, err := receipt.ReceiptHash(r)
	if err != nil {
		b.t.Fatalf("ReceiptHash: %v", err)
	}
	b.prev = hash
	b.seq++
	b.offset += time.Second
	return r
}

func (b *chainBuilder) open() receipt.Receipt {
	b.t.Helper()
	return b.openFor(testRunNonce, testOpenNonce)
}

func (b *chainBuilder) openFor(runNonce, openNonce string) receipt.Receipt {
	b.t.Helper()
	open := receipt.SessionOpen{
		RunNonce:         runNonce,
		OpenNonce:        openNonce,
		RecorderSession:  "proxy",
		PolicyHash:       "policy-completeness",
		SignerKeyEpoch:   "epoch-a",
		HeartbeatSeconds: 10,
		ChainOpenSeq:     b.seq,
	}
	if b.seq == 0 {
		genesis := receipt.ComputeSessionOpenGenesis(open)
		open.GenesisHash = genesis
		b.prev = genesis
	} else {
		open.PriorChainHead = b.prev
		open.PriorChainSeq = b.seq - 1
	}
	return b.sign(receipt.ActionRecord{
		ActionType: receipt.ActionUnclassified,
		Target:     "pipelock://session/open",
		Transport:  "session_control",
		RunNonce:   runNonce,
		SessionControl: &receipt.SessionControl{
			Kind: receipt.SessionControlOpen,
			Open: &open,
		},
	})
}

func (b *chainBuilder) rotateOpenFor(next rotationKey, runNonce, openNonce string) receipt.Receipt {
	b.t.Helper()
	if b.seq == 0 {
		b.t.Fatal("rotateOpenFor requires a prior segment tail")
	}
	priorKey := b.keyHex
	priorHead := b.prev
	priorSeq := b.seq - 1
	b.priv = next.priv
	b.keyHex = next.keyHex
	b.seq = 0
	open := receipt.SessionOpen{
		RunNonce:         runNonce,
		OpenNonce:        openNonce,
		RecorderSession:  "proxy",
		PolicyHash:       "policy-completeness",
		SignerKeyEpoch:   "epoch-b",
		HeartbeatSeconds: 10,
		ChainOpenSeq:     0,
		PriorChainHead:   priorHead,
		PriorChainSeq:    priorSeq,
	}
	return b.sign(receipt.ActionRecord{
		ActionType: receipt.ActionUnclassified,
		Target:     "pipelock://session/open",
		Transport:  "session_control",
		RunNonce:   runNonce,
		KeyTransition: &receipt.KeyTransition{
			PriorSignerKey: priorKey,
			PriorChainSeq:  priorSeq,
			PriorChainHash: priorHead,
		},
		SessionControl: &receipt.SessionControl{
			Kind: receipt.SessionControlOpen,
			Open: &open,
		},
	})
}

func (b *chainBuilder) heartbeat(beat, fsync, blocks uint64) receipt.Receipt {
	b.t.Helper()
	return b.heartbeatFor(testRunNonce, testOpenNonce, beat, fsync, blocks)
}

func (b *chainBuilder) heartbeatFor(runNonce, openNonce string, beat, fsync, blocks uint64) receipt.Receipt {
	b.t.Helper()
	return b.heartbeatForWithMutation(runNonce, openNonce, beat, fsync, blocks, nil)
}

func (b *chainBuilder) heartbeatForWithMutation(runNonce, openNonce string, beat, fsync, blocks uint64, mutate func(*receipt.SessionHeartbeat)) receipt.Receipt {
	b.t.Helper()
	heartbeat := &receipt.SessionHeartbeat{
		RunNonce:         runNonce,
		OpenNonce:        openNonce,
		Beat:             beat,
		ChainHead:        b.prev,
		ChainSeqHead:     receipt.PreviousChainSeq(b.seq),
		HeartbeatTime:    b.base.Add(b.offset).Format(time.RFC3339Nano),
		FsyncErrorsGated: fsync,
		DurabilityBlocks: blocks,
	}
	if mutate != nil {
		mutate(heartbeat)
	}
	return b.sign(receipt.ActionRecord{
		ActionType: receipt.ActionUnclassified,
		Target:     "pipelock://session/heartbeat",
		Transport:  "session_control",
		RunNonce:   runNonce,
		SessionControl: &receipt.SessionControl{
			Kind:      receipt.SessionControlHeartbeat,
			Heartbeat: heartbeat,
		},
	})
}

func (b *chainBuilder) close(fsync, blocks uint64) receipt.Receipt {
	b.t.Helper()
	return b.closeFor(testRunNonce, testOpenNonce, fsync, blocks)
}

func (b *chainBuilder) closeFor(runNonce, openNonce string, fsync, blocks uint64) receipt.Receipt {
	b.t.Helper()
	closeRecord := &receipt.SessionClose{
		RunNonce:         runNonce,
		OpenNonce:        openNonce,
		FinalSeq:         b.seq,
		RootHash:         b.prev,
		ReceiptCount:     b.seq + 1,
		CloseReason:      "normal",
		FsyncErrorsGated: fsync,
		DurabilityBlocks: blocks,
	}
	return b.closeWithRecord(runNonce, closeRecord)
}

func (b *chainBuilder) closeForWithMutation(runNonce, openNonce string, fsync, blocks uint64, mutate func(*receipt.SessionClose)) receipt.Receipt {
	b.t.Helper()
	closeRecord := &receipt.SessionClose{
		RunNonce:         runNonce,
		OpenNonce:        openNonce,
		FinalSeq:         b.seq,
		RootHash:         b.prev,
		ReceiptCount:     b.seq + 1,
		CloseReason:      "normal",
		FsyncErrorsGated: fsync,
		DurabilityBlocks: blocks,
	}
	mutate(closeRecord)
	return b.closeWithRecord(runNonce, closeRecord)
}

func (b *chainBuilder) closeWithRecord(runNonce string, closeRecord *receipt.SessionClose) receipt.Receipt {
	b.t.Helper()
	return b.sign(receipt.ActionRecord{
		ActionType: receipt.ActionUnclassified,
		Target:     "pipelock://session/close",
		Transport:  "session_control",
		RunNonce:   runNonce,
		SessionControl: &receipt.SessionControl{
			Kind:  receipt.SessionControlClose,
			Close: closeRecord,
		},
	})
}

func (b *chainBuilder) intent(actionID string) receipt.Receipt {
	b.t.Helper()
	return b.action(actionID, receipt.DecisionPhaseIntent)
}

func (b *chainBuilder) outcome(actionID string) receipt.Receipt {
	b.t.Helper()
	return b.action(actionID, receipt.DecisionPhaseOutcome)
}

func (b *chainBuilder) action(actionID, phase string) receipt.Receipt {
	b.t.Helper()
	return b.actionFor(testRunNonce, actionID, phase)
}

func (b *chainBuilder) actionFor(runNonce, actionID, phase string) receipt.Receipt {
	b.t.Helper()
	return b.sign(receipt.ActionRecord{
		ActionID:      actionID,
		ActionType:    receipt.ActionRead,
		Target:        "https://api.vendor.example/completeness/action",
		Transport:     "fetch",
		RunNonce:      runNonce,
		DecisionPhase: phase,
	})
}

func (b *chainBuilder) legacyAction() receipt.Receipt {
	b.t.Helper()
	return b.sign(receipt.ActionRecord{
		ActionType: receipt.ActionRead,
		Target:     "https://api.vendor.example/legacy",
		Transport:  "fetch",
	})
}

func analyzeBuilt(chain []receipt.Receipt, keyHex string) Report {
	return Analyze(chain, receipt.VerifyChain(chain, keyHex))
}

func analyzeBuiltIntegrityOnly(chain []receipt.Receipt, keyHex string) Report {
	return Analyze(chain, receipt.VerifyChainIntegrity(chain, keyHex))
}

func requireOneRun(t *testing.T, report Report, status Status, reason Reason) RunReport {
	t.Helper()
	if report.Status != status || report.Reason != reason {
		t.Fatalf("report = %s/%s, want %s/%s: %#v", report.Status, report.Reason, status, reason, report)
	}
	if len(report.Runs) != 1 {
		t.Fatalf("runs = %d, want 1: %#v", len(report.Runs), report)
	}
	run := report.Runs[0]
	if run.Status != status || run.Reason != reason {
		t.Fatalf("run = %s/%s, want %s/%s: %#v", run.Status, run.Reason, status, reason, run)
	}
	return run
}

func requireRun(t *testing.T, report Report, runNonce string, status Status, reason Reason) RunReport {
	t.Helper()
	for _, run := range report.Runs {
		if run.RunNonce != runNonce {
			continue
		}
		if run.Status != status || run.Reason != reason {
			t.Fatalf("run %s = %s/%s, want %s/%s: %#v", runNonce, run.Status, run.Reason, status, reason, run)
		}
		return run
	}
	t.Fatalf("run %s not found in report: %#v", runNonce, report)
	return RunReport{}
}

func TestAnalyzeReasons(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		build func(t *testing.T) ([]receipt.Receipt, string)
		want  Reason
	}{
		"bounded_closed": {
			build: func(t *testing.T) ([]receipt.Receipt, string) {
				b := newChainBuilder(t)
				actionID := "action-bounded"
				chain := []receipt.Receipt{
					b.open(),
					b.intent(actionID),
					b.outcome(actionID),
					b.heartbeat(1, 1, 2),
					b.close(1, 3),
				}
				return chain, b.keyHex
			},
			want: ReasonBoundedClosed,
		},
		"abnormal_end": {
			build: func(t *testing.T) ([]receipt.Receipt, string) {
				b := newChainBuilder(t)
				actionID := "action-abnormal"
				chain := []receipt.Receipt{
					b.open(),
					b.intent(actionID),
					b.outcome(actionID),
				}
				return chain, b.keyHex
			},
			want: ReasonAbnormalEnd,
		},
		"open_action": {
			build: func(t *testing.T) ([]receipt.Receipt, string) {
				b := newChainBuilder(t)
				chain := []receipt.Receipt{
					b.open(),
					b.intent("action-open"),
					b.close(0, 0),
				}
				return chain, b.keyHex
			},
			want: ReasonOpenAction,
		},
		"heartbeat_gap": {
			build: func(t *testing.T) ([]receipt.Receipt, string) {
				b := newChainBuilder(t)
				chain := []receipt.Receipt{
					b.open(),
					b.heartbeat(1, 0, 1),
					b.heartbeat(3, 0, 2),
					b.close(0, 2),
				}
				return chain, b.keyHex
			},
			want: ReasonHeartbeatGap,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			chain, keyHex := tc.build(t)
			run := requireOneRun(t, analyzeBuilt(chain, keyHex), StatusLimited, tc.want)
			if tc.want == ReasonBoundedClosed {
				if run.MatchedPairs != 1 || run.UnmatchedIntents != 0 || !run.Closed || !run.DurabilityMonotonic {
					t.Fatalf("bounded run counters wrong: %#v", run)
				}
			}
		})
	}
}

func TestAnalyzeNoOpenIsBroken(t *testing.T) {
	t.Parallel()
	b := newChainBuilder(t)
	chain := []receipt.Receipt{
		b.heartbeat(1, 0, 1),
		b.close(0, 1),
	}
	res := receipt.VerifyChain(chain, b.keyHex)
	if res.Valid {
		t.Fatal("fixture should trigger the existing chain verifier no-open rejection")
	}
	report := Analyze(chain, res)
	run := requireOneRun(t, report, StatusBroken, ReasonChainBroken)
	if run.StructuralViolation != "heartbeat observed before session_open" {
		t.Fatalf("structural_violation = %q, want heartbeat before open: %#v", run.StructuralViolation, run)
	}
}

func TestAnalyzeCloseClaimsMustMatchObservedPrefix(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*receipt.SessionClose){
		"receipt_count": func(closeRecord *receipt.SessionClose) {
			closeRecord.ReceiptCount++
		},
		"root_hash": func(closeRecord *receipt.SessionClose) {
			closeRecord.RootHash = "contradictory-root-hash"
		},
		"final_seq": func(closeRecord *receipt.SessionClose) {
			closeRecord.FinalSeq++
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			b := newChainBuilder(t)
			chain := []receipt.Receipt{
				b.open(),
				b.closeForWithMutation(testRunNonce, testOpenNonce, 0, 1, func(closeRecord *receipt.SessionClose) {
					mutate(closeRecord)
				}),
			}

			report := analyzeBuiltIntegrityOnly(chain, b.keyHex)
			run := requireOneRun(t, report, StatusBroken, ReasonChainBroken)
			if run.StructuralViolation == "" {
				t.Fatalf("structural violation not surfaced for %s: %#v", name, run)
			}
		})
	}
}

func TestAnalyzeCloseClaimsUseCurrentSegmentPrefix(t *testing.T) {
	t.Parallel()

	t.Run("same_key_restart_uses_chain_prefix_not_run_prefix", func(t *testing.T) {
		t.Parallel()
		b := newChainBuilder(t)
		chain := []receipt.Receipt{
			b.openFor("run-a", "open-a"),
			b.closeFor("run-a", "open-a", 0, 1),
			b.openFor("run-b", "open-b"),
			b.closeFor("run-b", "open-b", 0, 2),
		}

		report := analyzeBuiltIntegrityOnly(chain, b.keyHex)
		if report.Status != StatusLimited || report.Reason != ReasonBoundedClosed {
			t.Fatalf("same-key restart report = %s/%s, want LIMITED/bounded_closed: %#v", report.Status, report.Reason, report)
		}
		runB := requireRun(t, report, "run-b", StatusLimited, ReasonBoundedClosed)
		if runB.CloseReceiptCount != 4 || runB.CloseFinalSeq != 3 {
			t.Fatalf("restart close claims = count %d seq %d, want whole-segment count 4 seq 3: %#v",
				runB.CloseReceiptCount, runB.CloseFinalSeq, runB)
		}
	})

	t.Run("rotated_restart_uses_rotated_segment_prefix", func(t *testing.T) {
		t.Parallel()
		b := newChainBuilder(t)
		keyA := b.keyHex
		keyB := newRotationKey(t)
		chain := []receipt.Receipt{
			b.openFor("run-a", "open-a"),
			b.closeFor("run-a", "open-a", 0, 1),
			b.rotateOpenFor(keyB, "run-b", "open-b"),
			b.closeFor("run-b", "open-b", 0, 2),
		}

		res := receipt.VerifyChainIntegrityTrusted(chain, []string{keyA, keyB.keyHex})
		if !res.Valid {
			t.Fatalf("rotated fixture must verify before completeness analysis: %s", res.Error)
		}
		report := Analyze(chain, res)
		if report.Status != StatusLimited || report.Reason != ReasonBoundedClosed {
			t.Fatalf("rotated restart report = %s/%s, want LIMITED/bounded_closed: %#v", report.Status, report.Reason, report)
		}
		runB := requireRun(t, report, "run-b", StatusLimited, ReasonBoundedClosed)
		if runB.CloseReceiptCount != 2 || runB.CloseFinalSeq != 1 {
			t.Fatalf("rotated close claims = count %d seq %d, want segment count 2 seq 1: %#v",
				runB.CloseReceiptCount, runB.CloseFinalSeq, runB)
		}
	})

	t.Run("rotated_restart_wrong_close_claim_is_broken", func(t *testing.T) {
		t.Parallel()
		b := newChainBuilder(t)
		keyA := b.keyHex
		keyB := newRotationKey(t)
		chain := []receipt.Receipt{
			b.openFor("run-a", "open-a"),
			b.closeFor("run-a", "open-a", 0, 1),
			b.rotateOpenFor(keyB, "run-b", "open-b"),
			b.closeForWithMutation("run-b", "open-b", 0, 2, func(closeRecord *receipt.SessionClose) {
				closeRecord.ReceiptCount++
			}),
		}

		res := receipt.VerifyChainIntegrityTrusted(chain, []string{keyA, keyB.keyHex})
		if !res.Valid {
			t.Fatalf("rotated fixture must verify before completeness analysis: %s", res.Error)
		}
		report := Analyze(chain, res)
		runB := requireRun(t, report, "run-b", StatusBroken, ReasonChainBroken)
		if runB.StructuralViolation == "" {
			t.Fatalf("wrong rotated close claim did not surface a structural violation: %#v", runB)
		}
	})
}

func TestAnalyzeRecordAfterCloseIsBroken(t *testing.T) {
	t.Parallel()

	b := newChainBuilder(t)
	actionID := "action-after-close"
	chain := []receipt.Receipt{
		b.open(),
		b.close(0, 1),
		b.intent(actionID),
		b.outcome(actionID),
	}

	report := analyzeBuiltIntegrityOnly(chain, b.keyHex)
	run := requireOneRun(t, report, StatusBroken, ReasonChainBroken)
	if run.StructuralViolation != "action observed after session_close" {
		t.Fatalf("structural_violation = %q, want action observed after session_close: %#v", run.StructuralViolation, run)
	}
}

func TestAnalyzePostCloseGuardIsScopedToRun(t *testing.T) {
	t.Parallel()

	t.Run("new_run_after_prior_close_is_allowed", func(t *testing.T) {
		t.Parallel()
		b := newChainBuilder(t)
		chain := []receipt.Receipt{
			b.openFor("run-a", "open-a"),
			b.closeFor("run-a", "open-a", 0, 1),
			b.openFor("run-b", "open-b"),
			b.heartbeatFor("run-b", "open-b", 1, 0, 2),
			b.closeFor("run-b", "open-b", 0, 3),
		}

		report := analyzeBuiltIntegrityOnly(chain, b.keyHex)
		if report.Status != StatusLimited || report.Reason != ReasonBoundedClosed {
			t.Fatalf("second run after close = %s/%s, want LIMITED/bounded_closed: %#v", report.Status, report.Reason, report)
		}
		requireRun(t, report, "run-a", StatusLimited, ReasonBoundedClosed)
		requireRun(t, report, "run-b", StatusLimited, ReasonBoundedClosed)
	})

	t.Run("same_run_heartbeat_after_close_is_broken", func(t *testing.T) {
		t.Parallel()
		b := newChainBuilder(t)
		chain := []receipt.Receipt{
			b.open(),
			b.close(0, 1),
			b.heartbeat(1, 0, 2),
		}

		report := analyzeBuiltIntegrityOnly(chain, b.keyHex)
		run := requireOneRun(t, report, StatusBroken, ReasonChainBroken)
		if run.StructuralViolation != "record observed after session_close" {
			t.Fatalf("structural_violation = %q, want post-close guard: %#v", run.StructuralViolation, run)
		}
	})

	t.Run("same_run_second_close_is_broken", func(t *testing.T) {
		t.Parallel()
		b := newChainBuilder(t)
		chain := []receipt.Receipt{
			b.open(),
			b.close(0, 1),
			b.close(0, 2),
		}

		report := analyzeBuiltIntegrityOnly(chain, b.keyHex)
		run := requireOneRun(t, report, StatusBroken, ReasonChainBroken)
		if run.StructuralViolation != "record observed after session_close" {
			t.Fatalf("structural_violation = %q, want post-close guard: %#v", run.StructuralViolation, run)
		}
	})
}

func TestAnalyzeLifecycleChainRejectsActionsOutsideOpenedRun(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		build         func(*chainBuilder) []receipt.Receipt
		wantRun       string
		wantViolation string
	}{
		"pre_open_action": {
			build: func(b *chainBuilder) []receipt.Receipt {
				actionID := "action-pre-open"
				return []receipt.Receipt{
					b.intent(actionID),
					b.open(),
					b.outcome(actionID),
					b.close(0, 1),
				}
			},
			wantRun:       testRunNonce,
			wantViolation: "action observed before matching session_open",
		},
		"post_close_action_missing_run_nonce": {
			build: func(b *chainBuilder) []receipt.Receipt {
				return []receipt.Receipt{
					b.open(),
					b.close(0, 1),
					b.legacyAction(),
				}
			},
			wantRun:       "(missing)",
			wantViolation: "action receipt missing run_nonce in lifecycle chain",
		},
		"post_close_action_unopened_run_nonce": {
			build: func(b *chainBuilder) []receipt.Receipt {
				return []receipt.Receipt{
					b.open(),
					b.close(0, 1),
					b.actionFor("run-unopened", "action-unopened", receipt.DecisionPhaseIntent),
				}
			},
			wantRun:       "run-unopened",
			wantViolation: "action observed before matching session_open",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			b := newChainBuilder(t)
			report := analyzeBuiltIntegrityOnly(tc.build(b), b.keyHex)
			run := requireRun(t, report, tc.wantRun, StatusBroken, ReasonChainBroken)
			if run.StructuralViolation != tc.wantViolation {
				t.Fatalf("structural_violation = %q, want %q: %#v", run.StructuralViolation, tc.wantViolation, run)
			}
		})
	}
}

func TestAnalyzeHeartbeatClaimsMustMatchObservedPrefix(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*receipt.SessionHeartbeat){
		"chain_head": func(heartbeat *receipt.SessionHeartbeat) {
			heartbeat.ChainHead = "forged-heartbeat-chain-head"
		},
		"chain_seq_head": func(heartbeat *receipt.SessionHeartbeat) {
			heartbeat.ChainSeqHead++
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			b := newChainBuilder(t)
			chain := []receipt.Receipt{
				b.open(),
				b.heartbeatForWithMutation(testRunNonce, testOpenNonce, 1, 0, 1, mutate),
				b.close(0, 2),
			}

			report := analyzeBuiltIntegrityOnly(chain, b.keyHex)
			run := requireOneRun(t, report, StatusBroken, ReasonChainBroken)
			if run.StructuralViolation == "" {
				t.Fatalf("heartbeat prefix mutation did not surface a structural violation for %s: %#v", name, run)
			}
		})
	}
}

func TestAnalyzeDurabilityCountersArePerRun(t *testing.T) {
	t.Parallel()

	b := newChainBuilder(t)
	chain := []receipt.Receipt{
		b.openFor("run-a", "open-a"),
		b.heartbeatFor("run-a", "open-a", 1, 5, 9),
		b.closeFor("run-a", "open-a", 5, 9),
		b.openFor("run-b", "open-b"),
		b.heartbeatFor("run-b", "open-b", 1, 0, 0),
		b.closeFor("run-b", "open-b", 0, 1),
	}

	report := analyzeBuiltIntegrityOnly(chain, b.keyHex)
	if report.Status != StatusLimited || report.Reason != ReasonBoundedClosed {
		t.Fatalf("durability counter reset across run = %s/%s, want LIMITED/bounded_closed: %#v",
			report.Status, report.Reason, report)
	}
	runB := requireRun(t, report, "run-b", StatusLimited, ReasonBoundedClosed)
	if runB.DurabilityCounterDrop || !runB.DurabilityMonotonic {
		t.Fatalf("run-b durability should be evaluated independently: %#v", runB)
	}
}

func TestAnalyzeForgedNoOpenIsBroken(t *testing.T) {
	t.Parallel()
	b := newChainBuilder(t)
	chain := []receipt.Receipt{
		b.heartbeat(1, 0, 1),
		b.close(0, 1),
	}
	chain[0].ActionRecord.Target = "https://api.vendor.example/forged-no-open"

	res := receipt.VerifyChain(chain, b.keyHex)
	if res.Valid {
		t.Fatal("fixture should be rejected")
	}
	report := Analyze(chain, res)
	if report.Status != StatusBroken || report.Reason != ReasonChainBroken {
		t.Fatalf("forged no-open = %s/%s, want BROKEN/chain_broken: %#v", report.Status, report.Reason, report)
	}
	if report.SignaturesVerified {
		t.Fatalf("analysis report should not claim signatures verified: %#v", report)
	}
}

func TestAnalyzeDoesNotDowngradeIntegrityTrustOrLifecycleFailures(t *testing.T) {
	t.Parallel()

	tests := map[string]func(t *testing.T) ([]receipt.Receipt, string){
		"forged_first_receipt": func(t *testing.T) ([]receipt.Receipt, string) {
			t.Helper()
			b := newChainBuilder(t)
			chain := []receipt.Receipt{b.open()}
			chain[0].ActionRecord.Target = "https://api.vendor.example/forged-first"
			return chain, b.keyHex
		},
		"forged_mid_chain_receipt": func(t *testing.T) ([]receipt.Receipt, string) {
			t.Helper()
			b := newChainBuilder(t)
			chain := []receipt.Receipt{
				b.open(),
				b.intent("action-forged-mid"),
				b.close(0, 1),
			}
			chain[1].ActionRecord.Target = "https://api.vendor.example/forged-mid"
			return chain, b.keyHex
		},
		"forged_heartbeat": func(t *testing.T) ([]receipt.Receipt, string) {
			t.Helper()
			b := newChainBuilder(t)
			chain := []receipt.Receipt{
				b.open(),
				b.heartbeat(1, 0, 1),
				b.close(0, 1),
			}
			chain[1].ActionRecord.Target = "https://api.vendor.example/forged-heartbeat"
			return chain, b.keyHex
		},
		"forged_close": func(t *testing.T) ([]receipt.Receipt, string) {
			t.Helper()
			b := newChainBuilder(t)
			chain := []receipt.Receipt{
				b.open(),
				b.close(0, 1),
			}
			chain[1].ActionRecord.Target = "https://api.vendor.example/forged-close"
			return chain, b.keyHex
		},
		"duplicate_open_lifecycle": func(t *testing.T) ([]receipt.Receipt, string) {
			t.Helper()
			b := newChainBuilder(t)
			return []receipt.Receipt{
				b.open(),
				b.open(),
			}, b.keyHex
		},
		"wrong_open_nonce_lifecycle": func(t *testing.T) ([]receipt.Receipt, string) {
			t.Helper()
			b := newChainBuilder(t)
			return []receipt.Receipt{
				b.open(),
				b.heartbeatFor(testRunNonce, "wrong-open", 1, 0, 1),
			}, b.keyHex
		},
	}

	for name, build := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			chain, keyHex := build(t)
			report := Analyze(chain, receipt.VerifyChain(chain, keyHex))
			if report.Status != StatusBroken || report.Reason != ReasonChainBroken {
				t.Fatalf("%s = %s/%s, want BROKEN/chain_broken: %#v", name, report.Status, report.Reason, report)
			}
		})
	}
}

func TestAnalyzeOnlyMissingOpenIntegrityFailureDowngrades(t *testing.T) {
	t.Parallel()

	b := newChainBuilder(t)
	chain := []receipt.Receipt{
		b.heartbeat(1, 0, 1),
	}

	tests := map[string]struct {
		chainResult receipt.ChainResult
		wantStatus  Status
		wantReason  Reason
	}{
		"integrity": {
			chainResult: receipt.ChainResult{FailureKind: receipt.ChainFailureIntegrity, Error: "integrity failure"},
			wantStatus:  StatusBroken,
			wantReason:  ReasonChainBroken,
		},
		"trust": {
			chainResult: receipt.ChainResult{FailureKind: receipt.ChainFailureTrust, Error: "trust failure"},
			wantStatus:  StatusBroken,
			wantReason:  ReasonChainBroken,
		},
		"lifecycle_not_missing_open": {
			chainResult: receipt.ChainResult{FailureKind: receipt.ChainFailureLifecycle, IntegrityVerified: true, Error: "lifecycle failure"},
			wantStatus:  StatusBroken,
			wantReason:  ReasonChainBroken,
		},
		"missing_open_without_integrity": {
			chainResult: receipt.ChainResult{FailureKind: receipt.ChainFailureLifecycleOpen, Error: "missing open without integrity"},
			wantStatus:  StatusBroken,
			wantReason:  ReasonChainBroken,
		},
		"missing_open_with_integrity": {
			chainResult: receipt.ChainResult{FailureKind: receipt.ChainFailureLifecycleOpen, IntegrityVerified: true, Error: "missing open"},
			wantStatus:  StatusBroken,
			wantReason:  ReasonChainBroken,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			report := Analyze(chain, tc.chainResult)
			if report.Status != tc.wantStatus || report.Reason != tc.wantReason {
				t.Fatalf("%s = %s/%s, want %s/%s: %#v", name, report.Status, report.Reason, tc.wantStatus, tc.wantReason, report)
			}
		})
	}
}

func TestAnalyzeOutcomeWithoutIntentIsBroken(t *testing.T) {
	t.Parallel()
	b := newChainBuilder(t)
	chain := []receipt.Receipt{
		b.open(),
		b.outcome("action-orphan-outcome"),
		b.close(0, 1),
	}
	report := analyzeBuilt(chain, b.keyHex)
	run := requireOneRun(t, report, StatusBroken, ReasonChainBroken)
	if run.OutcomeWithoutIntent != 1 {
		t.Fatalf("outcome_without_intent = %d, want 1: %#v", run.OutcomeWithoutIntent, run)
	}
	if run.StructuralViolation != "outcome without matching intent" {
		t.Fatalf("structural_violation = %q", run.StructuralViolation)
	}
}

func TestAnalyzeNoLifecycleAndNoReceiptsAreUnverified(t *testing.T) {
	t.Parallel()
	empty := Analyze(nil, receipt.VerifyChain(nil, ""))
	if empty.Status != StatusUnverified || empty.Reason != ReasonNoReceipts {
		t.Fatalf("empty = %s/%s, want UNVERIFIED/no_receipts", empty.Status, empty.Reason)
	}

	b := newChainBuilder(t)
	chain := []receipt.Receipt{b.legacyAction()}
	report := analyzeBuilt(chain, b.keyHex)
	if report.Status != StatusUnverified || report.Reason != ReasonNoLifecycle {
		t.Fatalf("legacy = %s/%s, want UNVERIFIED/no_lifecycle", report.Status, report.Reason)
	}
}

func TestAnalyzeBrokenChainAndDurabilityDrop(t *testing.T) {
	t.Parallel()

	t.Run("tampered_chain", func(t *testing.T) {
		t.Parallel()
		b := newChainBuilder(t)
		chain := []receipt.Receipt{
			b.open(),
			b.intent("action-tampered"),
			b.outcome("action-tampered"),
		}
		chain[1].ActionRecord.Target = "https://api.vendor.example/tampered"
		report := Analyze(chain, receipt.VerifyChain(chain, b.keyHex))
		if report.Status != StatusBroken || report.Reason != ReasonChainBroken {
			t.Fatalf("tampered = %s/%s, want BROKEN/chain_broken: %#v", report.Status, report.Reason, report)
		}
	})

	t.Run("durability_decrease", func(t *testing.T) {
		t.Parallel()
		b := newChainBuilder(t)
		chain := []receipt.Receipt{
			b.open(),
			b.heartbeat(1, 2, 2),
			b.close(1, 2),
		}
		report := analyzeBuilt(chain, b.keyHex)
		run := requireOneRun(t, report, StatusBroken, ReasonChainBroken)
		if !run.DurabilityCounterDrop || run.DurabilityMonotonic {
			t.Fatalf("durability drop not surfaced: %#v", run)
		}
	})
}

func TestAnalyzeStatusDomainIsNeverGreen(t *testing.T) {
	t.Parallel()
	allowed := map[Status]bool{
		StatusLimited:    true,
		StatusBroken:     true,
		StatusUnverified: true,
	}
	for _, status := range []Status{StatusLimited, StatusBroken, StatusUnverified} {
		if !allowedStatus(status, allowed) {
			t.Fatalf("unexpected status domain member %q", status)
		}
		for _, forbidden := range []Status{"COMPLETE", "PASS", "OK"} {
			if status == forbidden {
				t.Fatalf("green status constant %q is forbidden", status)
			}
		}
	}

	tests := map[string]func(t *testing.T) Report{
		"empty": func(t *testing.T) Report {
			t.Helper()
			return Analyze(nil, receipt.VerifyChain(nil, ""))
		},
		"single_receipt_no_lifecycle": func(t *testing.T) Report {
			t.Helper()
			b := newChainBuilder(t)
			return analyzeBuilt([]receipt.Receipt{b.legacyAction()}, b.keyHex)
		},
		"clean_closed": func(t *testing.T) Report {
			t.Helper()
			b := newChainBuilder(t)
			actionID := "action-never-green"
			return analyzeBuilt([]receipt.Receipt{
				b.open(),
				b.intent(actionID),
				b.outcome(actionID),
				b.heartbeat(1, 0, 1),
				b.close(0, 1),
			}, b.keyHex)
		},
		"multi_run_rollup": func(t *testing.T) Report {
			t.Helper()
			b := newChainBuilder(t)
			return analyzeBuilt([]receipt.Receipt{
				b.openFor("run-a", "open-a"),
				b.actionFor("run-a", "action-a", receipt.DecisionPhaseIntent),
				b.actionFor("run-a", "action-a", receipt.DecisionPhaseOutcome),
				b.closeFor("run-a", "open-a", 0, 1),
				b.openFor("run-b", "open-b"),
				b.actionFor("run-b", "action-b", receipt.DecisionPhaseIntent),
				b.closeFor("run-b", "open-b", 0, 2),
			}, b.keyHex)
		},
		"duplicate_open": func(t *testing.T) Report {
			t.Helper()
			b := newChainBuilder(t)
			chain := []receipt.Receipt{
				b.open(),
				b.open(),
			}
			return Analyze(chain, receipt.VerifyChain(chain, b.keyHex))
		},
		"contradictory_open_nonce": func(t *testing.T) Report {
			t.Helper()
			b := newChainBuilder(t)
			return analyzeBuilt([]receipt.Receipt{
				b.open(),
				b.heartbeatFor(testRunNonce, "other-open", 1, 0, 1),
			}, b.keyHex)
		},
		"decreasing_durability_counter": func(t *testing.T) Report {
			t.Helper()
			b := newChainBuilder(t)
			return analyzeBuilt([]receipt.Receipt{
				b.open(),
				b.heartbeat(1, 3, 3),
				b.close(2, 2),
			}, b.keyHex)
		},
		"only_outcomes": func(t *testing.T) Report {
			t.Helper()
			b := newChainBuilder(t)
			return analyzeBuilt([]receipt.Receipt{
				b.open(),
				b.outcome("action-only-outcome"),
				b.close(0, 1),
			}, b.keyHex)
		},
		"only_heartbeats": func(t *testing.T) Report {
			t.Helper()
			b := newChainBuilder(t)
			chain := []receipt.Receipt{
				b.heartbeat(1, 0, 1),
			}
			return Analyze(chain, receipt.VerifyChain(chain, b.keyHex))
		},
		"missing_run_nonce_bucket": func(t *testing.T) Report {
			t.Helper()
			b := newChainBuilder(t)
			chain := []receipt.Receipt{
				b.sign(receipt.ActionRecord{
					ActionType: receipt.ActionUnclassified,
					Target:     "pipelock://session/heartbeat",
					Transport:  "session_control",
					SessionControl: &receipt.SessionControl{
						Kind: receipt.SessionControlHeartbeat,
						Heartbeat: &receipt.SessionHeartbeat{
							RunNonce:         testRunNonce,
							OpenNonce:        testOpenNonce,
							Beat:             1,
							HeartbeatTime:    b.base.Format(time.RFC3339Nano),
							DurabilityBlocks: 1,
						},
					},
				}),
			}
			return analyzeBuilt(chain, b.keyHex)
		},
		"huge_chain": func(t *testing.T) Report {
			t.Helper()
			b := newChainBuilder(t)
			chain := []receipt.Receipt{b.open()}
			for i := 0; i < 256; i++ {
				actionID := receipt.NewActionID()
				chain = append(chain, b.intent(actionID), b.outcome(actionID))
			}
			chain = append(chain, b.heartbeat(1, 0, 1), b.close(0, 2))
			return analyzeBuilt(chain, b.keyHex)
		},
	}

	for name, build := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			report := build(t)
			assertReportStatusDomain(t, report, allowed)
			if report.Status == "COMPLETE" || report.Status == "PASS" || report.Status == "OK" {
				t.Fatalf("green top-line status escaped: %#v", report)
			}
			if name == "clean_closed" && (report.Status != StatusLimited || report.Reason != ReasonBoundedClosed) {
				t.Fatalf("clean run = %s/%s, want LIMITED/bounded_closed", report.Status, report.Reason)
			}
		})
	}
}

func allowedStatus(status Status, allowed map[Status]bool) bool {
	return allowed[status]
}

func assertReportStatusDomain(t *testing.T, report Report, allowed map[Status]bool) {
	t.Helper()
	if !allowedStatus(report.Status, allowed) {
		t.Fatalf("report status %q outside allowed domain: %#v", report.Status, report)
	}
	for _, run := range report.Runs {
		if !allowedStatus(run.Status, allowed) {
			t.Fatalf("run status %q outside allowed domain: %#v", run.Status, run)
		}
	}
}
