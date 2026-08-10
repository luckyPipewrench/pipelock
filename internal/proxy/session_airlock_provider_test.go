// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestSessionStateAirlockProvider(t *testing.T) {
	t.Parallel()

	s := &SessionState{airlock: AirlockState{tier: config.AirlockTierNone}}
	if got := s.AirlockTier(); got != config.AirlockTierNone {
		t.Fatalf("AirlockTier() = %q, want none", got)
	}
	changed, from, to := s.EscalateAirlock(config.AirlockTierHard, airlockTriggerOnCritical)
	if !changed || from != config.AirlockTierNone || to != config.AirlockTierHard {
		t.Fatalf("EscalateAirlock() = (%v, %q, %q), want (true, none, hard)", changed, from, to)
	}
	if got := s.AirlockTier(); got != config.AirlockTierHard {
		t.Fatalf("AirlockTier() = %q, want hard", got)
	}
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	msg := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{}}}`)
	frame := mcp.ParseMCPFrame(msg)
	opts := mcp.MCPProxyOpts{Scanner: sc, Rec: s}
	if eval := mcp.EvaluateMCPInputGates(context.Background(), frame, msg, "client-a", opts, config.ActionWarn, config.ActionBlock, true); eval.BlockingGate == "" {
		t.Fatal("real hard-tier SessionState allowed tools/call")
	}
	s.airlock.mu.Lock()
	s.airlock.enteredAt = time.Now().Add(-2 * time.Minute)
	s.airlock.mu.Unlock()
	if changed, from, to := s.airlock.TryDeescalate(&config.AirlockTimers{HardMinutes: 1}); !changed || from != config.AirlockTierHard || to != config.AirlockTierSoft {
		t.Fatalf("TryDeescalate() = (%v, %q, %q), want (true, hard, soft)", changed, from, to)
	}
	if got := s.AirlockTier(); got != config.AirlockTierSoft {
		t.Fatalf("AirlockTier() after timer recovery = %q, want soft", got)
	}
	if eval := mcp.EvaluateMCPInputGates(context.Background(), frame, msg, "client-a", opts, config.ActionWarn, config.ActionBlock, true); eval.BlockingGate != "" {
		t.Fatalf("timer-recovered SessionState blocked tools/call at gate %q", eval.BlockingGate)
	}
}
