// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package config

import "testing"

// A budget pinned to principal grade refuses every tool call today, because no
// shipped runtime path resolves an authenticated MCP principal. That has to be
// visible at load: an operator who sets it and sees every call refused one at a
// time has been handed an outage, not a posture.
func TestDoWPrincipalTrustAdvisory(t *testing.T) {
	t.Run("fires for a principal-grade budget", func(t *testing.T) {
		cfg := &Config{Agents: map[string]AgentProfile{
			"_default": {Budget: BudgetConfig{DoWMinSubjectTrust: "principal"}},
		}}
		msg, ok := cfg.DoWPrincipalTrustAdvisory()
		if !ok {
			t.Fatal("no advisory for a principal-grade budget")
		}
		if msg == "" {
			t.Error("advisory message empty")
		}
	})

	for _, grade := range []string{"", "network", "agent"} {
		t.Run("silent for "+grade+" grade", func(t *testing.T) {
			cfg := &Config{Agents: map[string]AgentProfile{
				"_default": {Budget: BudgetConfig{DoWMinSubjectTrust: grade}},
			}}
			if _, ok := cfg.DoWPrincipalTrustAdvisory(); ok {
				t.Errorf("advisory fired for grade %q, which is satisfiable today", grade)
			}
		})
	}

	t.Run("an unrecognised grade is refused at load", func(t *testing.T) {
		budget := &BudgetConfig{DoWMinSubjectTrust: "supervisor"}
		if err := budget.ValidateDoW(); err == nil {
			t.Error("unrecognised grade accepted; the operator would get a weaker policy than they wrote")
		}
	})

	// Validation rejects an unknown spelling, so an unparseable value here can
	// only mean the config bypassed validation. It must resolve to the
	// strongest grade so the bypass fails closed rather than billing an
	// unidentified subject.
	t.Run("an unparseable grade resolves fail-closed", func(t *testing.T) {
		budget := &BudgetConfig{DoWMinSubjectTrust: "supervisor"}
		if got := budget.MinSubjectTrust(); got != DoWTrustPrincipal {
			t.Errorf("MinSubjectTrust() = %v, want DoWTrustPrincipal", got)
		}
	})

	t.Run("surfaces through ValidateWithWarnings", func(t *testing.T) {
		cfg := Defaults()
		cfg.Internal = nil
		cfg.Agents = map[string]AgentProfile{
			"_default": {Budget: BudgetConfig{DoWMinSubjectTrust: "principal"}},
		}
		warnings, err := cfg.ValidateWithWarnings()
		if err != nil {
			t.Fatalf("ValidateWithWarnings: %v", err)
		}
		found := false
		for _, w := range warnings {
			if w.Field == "agents.budget.dow_min_subject_trust" {
				found = true
			}
		}
		if !found {
			t.Errorf("advisory absent from %d validation warnings; an operator would never see it", len(warnings))
		}
	})
}
