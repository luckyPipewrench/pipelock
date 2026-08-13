// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

// enableAllSubDetectors turns on every section and sub-detector in the
// membership table so each case below controls only the actions it is testing.
// The tuning values are set alongside the enable flags so the result is a
// config that passes full validation, not just one that reaches the analyzer.
func enableAllSubDetectors(c *Config) {
	c.CrossRequestDetection.Enabled = true
	c.CrossRequestDetection.EntropyBudget.Enabled = true
	c.CrossRequestDetection.EntropyBudget.BitsPerWindow = 4096
	c.CrossRequestDetection.EntropyBudget.WindowMinutes = 5
	c.ResponseScanning.Enabled = true
	c.ResponseScanning.SSEStreaming.Enabled = true
	c.ResponseScanning.SSEStreaming.MaxEventBytes = 64 * 1024
	c.RequestBodyScanning.Enabled = true
	c.RequestBodyScanning.ContentEntropyEnabled = true
	c.RequestBodyScanning.ContentEntropyThreshold = 4.5
	c.RequestBodyScanning.ContentEntropyMinLength = 64
}

// setAllActions sets every parent/child pair in the table to the same values,
// so a case that expects "no findings" is asserting it across all three
// members rather than accidentally passing because only one was configured.
func setAllActions(c *Config, parent, child string) {
	c.CrossRequestDetection.Action = parent
	c.CrossRequestDetection.EntropyBudget.Action = child
	c.ResponseScanning.Action = parent
	c.ResponseScanning.SSEStreaming.Action = child
	c.RequestBodyScanning.Action = parent
	c.RequestBodyScanning.ContentEntropyAction = child
}

func TestValidateActionDivergence(t *testing.T) {
	tests := []struct {
		name         string
		parent       string
		child        string
		wantFindings int
	}{
		{name: "weaker child warns", parent: ActionBlock, child: ActionWarn, wantFindings: len(independentSubDetectors)},
		{name: "equal actions are silent", parent: ActionBlock, child: ActionBlock, wantFindings: 0},
		{name: "stronger child is silent", parent: ActionWarn, child: ActionBlock, wantFindings: 0},
		{name: "both warn is silent", parent: ActionWarn, child: ActionWarn, wantFindings: 0},
		// A weaker child under an already-weak parent still diverges: an
		// operator reading `warn` does not expect `allow`.
		{name: "allow under warn diverges", parent: ActionWarn, child: ActionAllow, wantFindings: len(independentSubDetectors)},
		// Fail-safe: an action this package cannot rank is not evidence of
		// weakening. Reporting it would be a false alarm on a value we do
		// not understand.
		{name: "unrecognized child is silent", parent: ActionBlock, child: "definitely-not-an-action", wantFindings: 0},
		{name: "unrecognized parent is silent", parent: "definitely-not-an-action", child: ActionWarn, wantFindings: 0},
		{name: "empty child is silent", parent: ActionBlock, child: "", wantFindings: 0},
		{name: "empty parent is silent", parent: "", child: ActionWarn, wantFindings: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Defaults()
			enableAllSubDetectors(cfg)
			setAllActions(cfg, tt.parent, tt.child)

			var warnings []Warning
			cfg.validateActionDivergence(&warnings)

			if len(warnings) != tt.wantFindings {
				t.Fatalf("got %d findings, want %d: %+v", len(warnings), tt.wantFindings, warnings)
			}
		})
	}
}

// TestValidateActionDivergence_DisabledSubDetectorIsSilent proves the enabled
// predicate is load-bearing. A disabled sub-detector decides nothing, so a
// weaker action on it is not a divergence and reporting it would be noise on
// a config that is behaving exactly as written.
func TestValidateActionDivergence_DisabledSubDetectorIsSilent(t *testing.T) {
	tests := []struct {
		name    string
		disable func(c *Config)
	}{
		{"entropy budget disabled", func(c *Config) { c.CrossRequestDetection.EntropyBudget.Enabled = false }},
		{"cross request section disabled", func(c *Config) { c.CrossRequestDetection.Enabled = false }},
		{"sse streaming disabled", func(c *Config) { c.ResponseScanning.SSEStreaming.Enabled = false }},
		{"response scanning section disabled", func(c *Config) { c.ResponseScanning.Enabled = false }},
		{"content entropy disabled", func(c *Config) { c.RequestBodyScanning.ContentEntropyEnabled = false }},
		{"request body section disabled", func(c *Config) { c.RequestBodyScanning.Enabled = false }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Defaults()
			enableAllSubDetectors(cfg)
			setAllActions(cfg, ActionBlock, ActionWarn)
			tt.disable(cfg)

			var warnings []Warning
			cfg.validateActionDivergence(&warnings)

			// One of the three members is now disabled, so exactly one
			// finding must disappear.
			if want := len(independentSubDetectors) - 1; len(warnings) != want {
				t.Fatalf("got %d findings, want %d: %+v", len(warnings), want, warnings)
			}
		})
	}
}

// TestValidateActionDivergence_MessageNamesBothPathsAndEffect checks the
// warning is actionable. A finding that says something is wrong without
// naming the field to edit and the resulting behavior is the kind of output
// operators learn to skip.
func TestValidateActionDivergence_MessageNamesBothPathsAndEffect(t *testing.T) {
	for _, d := range independentSubDetectors {
		t.Run(d.childField, func(t *testing.T) {
			cfg := Defaults()
			enableAllSubDetectors(cfg)
			setAllActions(cfg, ActionBlock, ActionWarn)

			var warnings []Warning
			cfg.validateActionDivergence(&warnings)

			var found *Warning
			for i := range warnings {
				if warnings[i].Field == d.childField {
					found = &warnings[i]
					break
				}
			}
			if found == nil {
				t.Fatalf("no finding for %s in %+v", d.childField, warnings)
			}
			for _, want := range []string{d.parentField, d.trigger, ActionWarn, ActionBlock} {
				if !strings.Contains(found.Message, want) {
					t.Errorf("message missing %q: %s", want, found.Message)
				}
			}
		})
	}
}

// TestValidateActionDivergence_ReachedThroughValidateWithWarnings proves the
// analyzer is actually wired into the path that startup, reload, doctor and
// check all consume. The analyzer being correct is worth nothing if no caller
// reaches it.
func TestValidateActionDivergence_ReachedThroughValidateWithWarnings(t *testing.T) {
	cfg := Defaults()
	cfg.ApplyDefaults()
	enableAllSubDetectors(cfg)
	setAllActions(cfg, ActionBlock, ActionWarn)

	warnings, err := cfg.ValidateWithWarnings()
	if err != nil {
		t.Fatalf("config must remain valid; the advisory never fails a config: %v", err)
	}

	for _, d := range independentSubDetectors {
		var seen bool
		for _, w := range warnings {
			if w.Field == d.childField {
				seen = true
				break
			}
		}
		if !seen {
			t.Errorf("ValidateWithWarnings did not surface %s", d.childField)
		}
	}
}

// TestActionWeakerThan_UsesTheFullOrdering guards the helper against being
// switched to actionRank in action.go, which ranks only block and warn and
// would silently treat strip, redirect, ask and defer as unrankable.
func TestActionWeakerThan_UsesTheFullOrdering(t *testing.T) {
	ordered := []string{ActionAllow, ActionWarn, ActionStrip, ActionRedirect, ActionAsk, ActionDefer, ActionBlock}
	for i, weaker := range ordered {
		for j, stronger := range ordered {
			got := actionWeakerThan(weaker, stronger)
			if want := i < j; got != want {
				t.Errorf("actionWeakerThan(%q, %q) = %v, want %v", weaker, stronger, got, want)
			}
		}
	}
}
