// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// TestNew_FailsClosedWhenBaselineInitFails proves the proxy refuses to start
// when a configured-enabled behavioral baseline cannot initialize, instead of
// silently running with enforcement off. seasonality_mode "labeled" is accepted
// by config validation (forward-compat) but the baseline manager only
// implements "none", so EnableBaseline fails; New must surface that error.
func TestNew_FailsClosedWhenBaselineInitFails(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SessionProfiling.Enabled = true
	cfg.BehavioralBaseline.Enabled = true
	cfg.BehavioralBaseline.ProfileDir = t.TempDir()
	cfg.BehavioralBaseline.DeviationAction = config.ActionBlock
	cfg.BehavioralBaseline.SeasonalityMode = config.SeasonalityModeLabeled

	logger := audit.NewNop()
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	m := metrics.New()

	if _, err := New(cfg, logger, sc, m); err == nil {
		t.Fatal("proxy.New did not fail closed on behavioral-baseline init failure")
	}
}
