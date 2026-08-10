// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// TestMCPAirlockConfigFor covers the three states the MCP listener distinguishes.
// The nil-versus-non-nil result is load bearing: nil means airlock is off so the
// MCP gate allows tool calls, while a non-nil config means airlock is on and an
// unknown per-session tier must fail closed rather than pass through.
func TestMCPAirlockConfigFor(t *testing.T) {
	t.Parallel()

	t.Run("nil config returns nil", func(t *testing.T) {
		t.Parallel()
		if got := mcpAirlockConfigFor(nil); got != nil {
			t.Fatalf("mcpAirlockConfigFor(nil) = %+v, want nil", got)
		}
	})

	t.Run("disabled airlock returns nil", func(t *testing.T) {
		t.Parallel()
		cfg := config.Defaults()
		cfg.Airlock.Enabled = false
		if got := mcpAirlockConfigFor(cfg); got != nil {
			t.Fatalf("disabled airlock returned %+v, want nil", got)
		}
	})

	t.Run("enabled airlock returns the live config", func(t *testing.T) {
		t.Parallel()
		cfg := config.Defaults()
		cfg.Airlock.Enabled = true
		cfg.Airlock.Triggers.OnCritical = config.AirlockTierHard
		got := mcpAirlockConfigFor(cfg)
		if got == nil {
			t.Fatal("enabled airlock returned nil, want the live config")
		}
		if got.Triggers.OnCritical != config.AirlockTierHard {
			t.Fatalf("OnCritical = %q, want %q", got.Triggers.OnCritical, config.AirlockTierHard)
		}
		// The pointer aliases the loaded config rather than an unnecessary copy.
		if got != &cfg.Airlock {
			t.Fatal("returned airlock config is a copy, not the live config")
		}
	})
}

// TestMCPSessionManagerOptions covers the standalone `pipelock mcp proxy`
// wiring. Attaching the airlock config is the difference between a standalone
// MCP runtime that can contain a tool call at hard tier and one whose tier never
// leaves none, which is the fail-open this wiring closes.
func TestMCPSessionManagerOptions(t *testing.T) {
	t.Parallel()

	t.Run("airlock disabled attaches no config", func(t *testing.T) {
		t.Parallel()
		cfg := config.Defaults()
		cfg.Airlock.Enabled = false
		if got := mcpSessionManagerOptions(cfg, nil); got.AirlockCfg != nil {
			t.Fatalf("AirlockCfg = %+v, want nil when airlock is disabled", got.AirlockCfg)
		}
	})

	t.Run("nil config attaches no config", func(t *testing.T) {
		t.Parallel()
		if got := mcpSessionManagerOptions(nil, nil); got.AirlockCfg != nil {
			t.Fatalf("AirlockCfg = %+v, want nil for a nil config", got.AirlockCfg)
		}
	})

	t.Run("airlock enabled attaches the live config", func(t *testing.T) {
		t.Parallel()
		cfg := config.Defaults()
		cfg.Airlock.Enabled = true
		got := mcpSessionManagerOptions(cfg, nil)
		if got.AirlockCfg == nil {
			t.Fatal("AirlockCfg = nil, want the live airlock config")
		}
		if got.AirlockCfg != &cfg.Airlock {
			t.Fatal("AirlockCfg is a copy, not the live config")
		}
	})
}
