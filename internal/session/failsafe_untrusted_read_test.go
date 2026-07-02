// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package session_test

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/session"
)

// TestPolicyMatrixEvaluateWithOptions_FailSafeUntrustedRead covers the
// non-hostile untrusted path: a read/browse/summarize that only reached
// SensitivityProtected because it could not be confidently classified must be
// escalated to HITL under fail-safe, not allowed. The untrusted switch has no
// read-class branch, so before the fix a low-confidence read fell through to
// PolicyAllow even with the toggle on (inert fail-safe).
func TestPolicyMatrixEvaluateWithOptions_FailSafeUntrustedRead(t *testing.T) {
	t.Parallel()

	pm := session.PolicyMatrix{Profile: "balanced"}
	decideRead := func(opts session.PolicyEvaluateOptions) session.PolicyDecision {
		return pm.EvaluateWithOptions(
			session.TaintExternalUntrusted,
			session.ActionClassRead,
			session.SensitivityProtected,
			session.AuthorityUserBroad,
			opts,
		).Decision
	}

	// Toggle OFF: the always-allow read shortcut applies (unchanged behavior).
	if got := decideRead(session.PolicyEvaluateOptions{ClassificationConfident: false}); got != session.PolicyAllow {
		t.Fatalf("fail-safe off: decision = %s, want allow", got)
	}

	// Toggle ON + low-confidence: escalate to HITL (the fixed gap).
	if got := decideRead(session.PolicyEvaluateOptions{FailSafeClassification: true, ClassificationConfident: false}); got != session.PolicyAsk {
		t.Fatalf("fail-safe on, low-confidence: decision = %s, want ask", got)
	}

	// Toggle ON but CONFIDENT: no escalation; confident reads are unaffected
	// (regression guard against over-blocking normal reads).
	if got := decideRead(session.PolicyEvaluateOptions{FailSafeClassification: true, ClassificationConfident: true}); got != session.PolicyAllow {
		t.Fatalf("fail-safe on, confident: decision = %s, want allow", got)
	}
}
