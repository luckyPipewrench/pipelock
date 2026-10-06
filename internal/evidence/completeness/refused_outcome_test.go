// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package completeness

import (
	"reflect"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

// TestAnalyzeRefusedOutcomeClosesItsIntent pins how a call refused after its
// intent was written reports. MCP records such a call as an allowed intent and
// an outcome with a block verdict under the same action ID. Completeness pairs
// intents and outcomes by phase and action ID and does not read the verdict, so
// the refused call is a matched pair and the run reports exactly as it would
// for a call that was sent. Completeness proves every intent was closed; only
// the outcome receipt's own verdict says the call was refused and not sent.
func TestAnalyzeRefusedOutcomeClosesItsIntent(t *testing.T) {
	t.Parallel()

	build := func(outcomeVerdict string) (Report, string) {
		b := newChainBuilder(t)
		const actionID = "action-refused"
		// The builder chains receipts in signing order.
		open := b.open()
		intent := b.intent(actionID)
		outcome := b.sign(receipt.ActionRecord{
			ActionID:      actionID,
			ActionType:    receipt.ActionRead,
			Target:        "https://api.vendor.example/completeness/action",
			Transport:     "mcp_http_upstream",
			RunNonce:      testRunNonce,
			DecisionPhase: receipt.DecisionPhaseOutcome,
			Verdict:       outcomeVerdict,
		})
		chain := []receipt.Receipt{open, intent, outcome, b.heartbeat(1, 1, 2), b.close(1, 3)}
		return analyzeBuilt(chain, b.keyHex), outcome.ActionRecord.Verdict
	}

	refused, refusedVerdict := build(config.ActionBlock)
	sent, _ := build(config.ActionAllow)
	if refusedVerdict != config.ActionBlock {
		t.Fatalf("signed outcome verdict = %q, want block", refusedVerdict)
	}

	run := requireOneRun(t, refused, StatusLimited, ReasonBoundedClosed)
	if run.Intents != 1 || run.Outcomes != 1 || run.MatchedPairs != 1 || run.UnmatchedIntents != 0 {
		t.Fatalf("refused call run = %+v, want one matched intent/outcome pair", run)
	}

	// The completeness result carries no trace of the verdict: apart from the
	// hashes that differ per chain, the refused and sent runs report
	// the same thing.
	normalize := func(r Report) Report {
		r.RootHash = ""
		for i := range r.Runs {
			r.Runs[i].RunNonce = ""
			r.Runs[i].CloseRootHash = ""
		}
		return r
	}
	if !reflect.DeepEqual(normalize(refused), normalize(sent)) {
		t.Fatalf("refused report differs from sent report:\nrefused=%+v\nsent=%+v", refused, sent)
	}
}
