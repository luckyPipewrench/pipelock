// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// TestEvaluateMCPInputGates_NilAirlockConfigKeepsContainedSessionsContained
// pins the deliberate asymmetry between a nil airlock config and a disabled
// one. Disabled means the operator turned containment off, so tool calls
// resume. Nil means the configuration is not currently reachable, which says
// nothing about whether this session is contained, so a session still carrying
// a hard tier stays denied. Collapsing the two would release a contained
// session the moment its config became unavailable, which is a fail-open on
// exactly the path containment exists for.
func TestEvaluateMCPInputGates_NilAirlockConfigKeepsContainedSessionsContained(t *testing.T) {
	t.Parallel()

	sc := testInputScanner(t)
	msg := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"exec_command","arguments":{"cmd":"id"}}}`)
	frame := ParseMCPFrame(msg)

	for _, tc := range []struct {
		name        string
		tier        string
		wantBlocked bool
	}{
		// No configuration and no tier: nothing to enforce, so allow.
		{name: "nil config and no tier allows", tier: config.AirlockTierNone},
		// No configuration but the session is still contained: stay contained.
		{name: "nil config and hard tier still denies", tier: config.AirlockTierHard, wantBlocked: true},
		{name: "nil config and drain tier still denies", tier: config.AirlockTierDrain, wantBlocked: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			opts := testOpts(sc)
			opts.AirlockCfg = nil
			opts.AirlockCfgFn = nil
			opts.Rec = &airlockTestRecorder{tier: tc.tier}

			eval := EvaluateMCPInputGates(context.Background(), frame, msg, "client-a", opts, config.ActionWarn, config.ActionBlock, true)
			if got := eval.BlockingGate != ""; got != tc.wantBlocked {
				t.Fatalf("blocked = %v (gate %q), want %v", got, eval.BlockingGate, tc.wantBlocked)
			}
		})
	}
}

// TestEvaluateMCPInputGates_DisabledAirlockReleasesContainment is the other
// half of the pair above: an explicitly disabled airlock does release a session
// that still carries a hard tier, because that is the operator's decision.
func TestEvaluateMCPInputGates_DisabledAirlockReleasesContainment(t *testing.T) {
	t.Parallel()

	sc := testInputScanner(t)
	msg := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"exec_command","arguments":{"cmd":"id"}}}`)
	frame := ParseMCPFrame(msg)

	disabled := config.Defaults().Airlock
	disabled.Enabled = false

	opts := testOpts(sc)
	opts.AirlockCfg = &disabled
	opts.AirlockCfgFn = nil
	opts.Rec = &airlockTestRecorder{tier: config.AirlockTierHard}

	eval := EvaluateMCPInputGates(context.Background(), frame, msg, "client-a", opts, config.ActionWarn, config.ActionBlock, true)
	if eval.BlockingGate != "" {
		t.Fatalf("BlockingGate = %q, want empty when airlock is explicitly disabled", eval.BlockingGate)
	}
}
