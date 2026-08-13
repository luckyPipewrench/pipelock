// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// divergentConfig returns a valid config whose cross-request entropy budget is
// weaker than its enclosing section, which is the shape configs/strict.yaml
// ships.
func divergentConfig() *config.Config {
	cfg := config.Defaults()
	cfg.ApplyDefaults()
	cfg.CrossRequestDetection.Enabled = true
	cfg.CrossRequestDetection.Action = config.ActionBlock
	cfg.CrossRequestDetection.EntropyBudget.Enabled = true
	cfg.CrossRequestDetection.EntropyBudget.BitsPerWindow = 4096
	cfg.CrossRequestDetection.EntropyBudget.WindowMinutes = 5
	cfg.CrossRequestDetection.EntropyBudget.Action = config.ActionWarn
	return cfg
}

// TestAnalyzeConfigSemantics_ReportsActionDivergence locks the WIRING, not the
// analysis. The analyzer was once correct and simultaneously unreachable from
// the doctor and check commands, because those surfaces build advisories from
// checkDoctorConfigSemantics rather than from ValidateWithWarnings. Every unit
// test of the analyzer passed while operators running `pipelock check` saw
// nothing. This test fails if that wiring is ever removed again.
func TestAnalyzeConfigSemantics_ReportsActionDivergence(t *testing.T) {
	findings := AnalyzeConfigSemantics(divergentConfig())

	var found *ConfigSemanticFinding
	for i := range findings {
		if findings[i].Scope == ConfigScopeActionDivergence {
			found = &findings[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("no action-divergence finding reached the doctor surface: %+v", findings)
	}
	if found.Subject != "cross_request_detection.entropy_budget.action" {
		t.Errorf("subject should name the field to edit, got %q", found.Subject)
	}
	// The detail must name the enclosing section too, or the operator knows
	// something is weak but not what it is weaker than.
	if !strings.Contains(found.Detail, "cross_request_detection.action") {
		t.Errorf("detail does not name the parent section: %s", found.Detail)
	}
	if found.Next == "" {
		t.Error("finding must carry a remediation")
	}
}

// TestCheckConfigAdvisories_IncludesActionDivergence covers the second
// consumer. check builds its own advisory list, so reaching doctor does not
// prove reaching check.
func TestCheckConfigAdvisories_IncludesActionDivergence(t *testing.T) {
	advisories := checkConfigAdvisories(divergentConfig())

	for _, a := range advisories {
		if strings.Contains(a, "cross_request_detection.action") && strings.Contains(a, "weaker") {
			return
		}
	}
	t.Fatalf("pipelock check did not surface the divergence advisory: %+v", advisories)
}

// TestAnalyzeConfigSemantics_ConsistentActionsAreSilent is the false-positive
// guard. An advisory that fires on a correctly-configured deployment trains
// operators to ignore doctor output, which on a security product costs more
// than the silence it replaced.
func TestAnalyzeConfigSemantics_ConsistentActionsAreSilent(t *testing.T) {
	cfg := divergentConfig()
	cfg.CrossRequestDetection.EntropyBudget.Action = config.ActionBlock

	for _, f := range AnalyzeConfigSemantics(cfg) {
		if f.Scope == ConfigScopeActionDivergence {
			t.Fatalf("advisory fired on a consistent config: %+v", f)
		}
	}
}
