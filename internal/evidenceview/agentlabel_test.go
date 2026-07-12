// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package evidenceview

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

// A session that opens with a session-control (session_open) record must be
// labeled by its first real agent decision, not by the opener actor (which is
// the proxy identity, "pipelock"). Otherwise the Agents roster collapses a real
// agent's session under "pipelock".
func TestAgentLabel_SkipsLifecycleReceipts(t *testing.T) {
	t.Parallel()

	lifecycle := receipt.Receipt{ActionRecord: receipt.ActionRecord{
		Actor:          "pipelock",
		SessionControl: &receipt.SessionControl{Kind: receipt.SessionControlOpen},
	}}
	decision := receipt.Receipt{ActionRecord: receipt.ActionRecord{Actor: "alpha-coder"}}

	if got := agentLabel("proxy", []receipt.Receipt{lifecycle, decision}); got != "alpha-coder" {
		t.Fatalf("agentLabel = %q, want %q (must skip the session_open lifecycle receipt)", got, "alpha-coder")
	}

	// A session with only lifecycle records has no agent decision to attribute;
	// fall back to the opener actor rather than an empty label.
	if got := agentLabel("proxy", []receipt.Receipt{lifecycle}); got != "pipelock" {
		t.Fatalf("all-lifecycle agentLabel = %q, want %q fallback", got, "pipelock")
	}
}

func TestAgentLabel_TrimsLifecycleFallbacks(t *testing.T) {
	t.Parallel()

	lifecycle := receipt.Receipt{ActionRecord: receipt.ActionRecord{
		Actor:          "   ",
		SessionID:      " agent-session ",
		SessionControl: &receipt.SessionControl{Kind: receipt.SessionControlOpen},
	}}

	if got := agentLabel("proxy", []receipt.Receipt{lifecycle}); got != "agent-session" {
		t.Fatalf("agentLabel = %q, want trimmed session fallback", got)
	}
}
