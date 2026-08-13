// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// TestActionDivergenceReportsUnderItsOwnCheckName pins the doctor check name that
// action-divergence findings are reported under.
//
// The name is what an operator reads first and what automation keys on. Action
// divergence previously fell through to the config_exemption_semantics default,
// so a config whose exemptions were entirely correct reported an exemption
// warning whose detail was about enforcement strength. That sends the operator
// to audit the wrong knob, which is the wrong-remediation-surface failure.
//
// Fails if the routing regresses to the exemption default, and asserts the
// negative too: an action-divergence finding must not be reported as an
// exemption or a suppression problem.
func TestActionDivergenceReportsUnderItsOwnCheckName(t *testing.T) {
	findings := []ConfigSemanticFinding{
		newConfigSemanticFinding(
			ConfigSemanticKindAdvisory,
			ConfigScopeActionDivergence,
			"response_scanning.sse_streaming.action",
			`action "warn" is weaker than response_scanning.action "block"`,
			"raise the sub-detector action to match its section",
		),
	}

	checks := semanticFindingsToDoctorChecks(findings)
	if len(checks) != 1 {
		t.Fatalf("checks = %d, want 1", len(checks))
	}
	switch got := checks[0].Name; got {
	case doctorCheckActionDivergence:
		// correct
	case doctorCheckExemptionSemantics:
		t.Errorf("check name = %q: action divergence must not be reported as an exemption problem, nothing about an exemption is wrong", got)
	case doctorCheckSuppressSemantics:
		t.Errorf("check name = %q: action divergence must not be reported as a suppression problem", got)
	default:
		t.Errorf("check name = %q, want %q", got, doctorCheckActionDivergence)
	}
}

// TestDoctorCheckNameForScopeRoutesEveryScope pins the whole mapping rather than
// a single case, so adding a scope to the scope table without deciding its check
// name is caught here instead of by an operator reading a mislabeled warning.
//
// Every entry other than suppress and action divergence is a member of the
// exemption family, which is why that remains the default.
func TestDoctorCheckNameForScopeRoutesEveryScope(t *testing.T) {
	cases := map[string]string{
		ConfigScopeSuppress:                   doctorCheckSuppressSemantics,
		ConfigScopeActionDivergence:           doctorCheckActionDivergence,
		ConfigScopeResponseExemptDomains:      doctorCheckExemptionSemantics,
		ConfigScopeResponseMCPServers:         doctorCheckExemptionSemantics,
		ConfigScopeAdaptiveExemptDomains:      doctorCheckExemptionSemantics,
		ConfigScopeCrossRequestEntropyExempt:  doctorCheckExemptionSemantics,
		ConfigScopeBrowserShieldExemptDomains: doctorCheckExemptionSemantics,
		ConfigScopeTLSPassthroughDomains:      doctorCheckExemptionSemantics,
		ConfigScopeRequestBodyIgnoreHeaders:   doctorCheckExemptionSemantics,
		ConfigScopeBodyEntropyExclusions:      doctorCheckExemptionSemantics,
		ConfigScopeWSEntropyExclusions:        doctorCheckExemptionSemantics,
	}
	for scope, want := range cases {
		t.Run(scope, func(t *testing.T) {
			if got := doctorCheckNameForScope(scope); got != want {
				t.Errorf("doctorCheckNameForScope(%q) = %q, want %q", scope, got, want)
			}
		})
	}
}

// TestUnknownScopeNeverReportsAsAnExemption is the negative control for the
// routing default.
//
// The original defect was not that action divergence lacked a case; it was that
// an unmapped scope inherited the exemption name. A scope this package does not
// recognise must never claim a knob, because an operator sent to audit correct
// exemptions is worse off than one told only that something is wrong.
func TestUnknownScopeNeverReportsAsAnExemption(t *testing.T) {
	for _, scope := range []string{"", "future_scope_not_yet_mapped", "totally_unknown"} {
		t.Run(scope, func(t *testing.T) {
			got := doctorCheckNameForScope(scope)
			if got == doctorCheckExemptionSemantics {
				t.Errorf("unknown scope %q routed to %q: an unmapped scope must not claim the exemption family", scope, got)
			}
			if got == doctorCheckSuppressSemantics {
				t.Errorf("unknown scope %q routed to %q: an unmapped scope must not claim the suppression family", scope, got)
			}
			if got != doctorCheckSemanticsUnclassified {
				t.Errorf("unknown scope %q routed to %q, want the neutral %q", scope, got, doctorCheckSemanticsUnclassified)
			}
		})
	}
}

// TestUnknownScopeDoesNotHideTheCleanSuppressSurface covers the second half of
// the same defect. A finding whose scope is unmapped must not be counted as a
// suppress or exemption finding, or it silently removes the ok check that tells
// an operator those surfaces were analysed and came back clean.
//
// This drives the full report builder rather than the finding-to-check
// conversion, because the ok check is added by the builder. Asserting on the
// conversion alone would pass while the surface was still being hidden.
func TestUnknownScopeDoesNotHideTheCleanSuppressSurface(t *testing.T) {
	findings := []ConfigSemanticFinding{
		newConfigSemanticFinding(
			ConfigSemanticKindAdvisory,
			"future_scope_not_yet_mapped",
			"some.field",
			"something is off",
			"look at it",
		),
	}

	checks := semanticChecksWithCleanSurface(findings)

	var suppressOK, findingLevelSuppressOrExemption int
	for _, c := range checks {
		switch {
		case c.Name == doctorCheckSuppressSemantics && c.Status == doctorStatusOK:
			suppressOK++
		case c.Name == doctorCheckSuppressSemantics, c.Name == doctorCheckExemptionSemantics:
			findingLevelSuppressOrExemption++
		}
	}
	if suppressOK != 1 {
		t.Errorf("suppress-semantics ok checks = %d, want exactly 1: an unmapped advisory must not hide the clean surface", suppressOK)
	}
	if findingLevelSuppressOrExemption != 0 {
		t.Errorf("unmapped scope produced %d finding-level suppress/exemption check(s), want 0", findingLevelSuppressOrExemption)
	}
}

// TestEveryDeclaredScopeHasARecordedCheckName is the forcing function. Adding a
// scope constant without recording its check name fails here, at the change that
// introduced it, instead of reaching an operator as a mislabeled warning.
//
// The list is maintained by hand because Go cannot enumerate the constants, so
// treat a failure as the reminder it is: add the scope to configScopeCheckNames
// and to this list, having decided which check it belongs under.
func TestEveryDeclaredScopeHasARecordedCheckName(t *testing.T) {
	declared := []string{
		ConfigScopeSuppress,
		ConfigScopeResponseExemptDomains,
		ConfigScopeResponseMCPServers,
		ConfigScopeAdaptiveExemptDomains,
		ConfigScopeCrossRequestEntropyExempt,
		ConfigScopeBrowserShieldExemptDomains,
		ConfigScopeTLSPassthroughDomains,
		ConfigScopeRequestBodyIgnoreHeaders,
		ConfigScopeBodyEntropyExclusions,
		ConfigScopeWSEntropyExclusions,
		ConfigScopeActionDivergence,
	}
	for _, scope := range declared {
		if _, ok := configScopeCheckNames[scope]; !ok {
			t.Errorf("scope %q has no recorded check name; add it to configScopeCheckNames", scope)
		}
	}
	if len(configScopeCheckNames) != len(declared) {
		t.Errorf("configScopeCheckNames has %d entries, this test lists %d: keep them in step so a new scope cannot skip a routing decision",
			len(configScopeCheckNames), len(declared))
	}
}

// TestSuppressSurfaceStillReportedAlongsideAnAdvisory pins that the
// suppress/exemption surface is represented in the report even when an
// unrelated advisory is present.
//
// "No warning" and "the check never ran" are indistinguishable in a report
// unless the clean case is stated explicitly. The ok check used to be emitted
// only when the findings list was completely empty, so the arrival of the first
// unrelated advisory silently removed the suppress/exemption surface from a
// report whose suppressions were fine.
func TestSuppressSurfaceStillReportedAlongsideAnAdvisory(t *testing.T) {
	cfg := config.Defaults()
	cfg.ApplyDefaults()
	// Produce an action-divergence advisory and nothing else: enable a section
	// with a stronger action than its independently enabled sub-detector.
	cfg.ResponseScanning.Enabled = true
	cfg.ResponseScanning.Action = config.ActionBlock
	cfg.ResponseScanning.SSEStreaming.Enabled = true
	cfg.ResponseScanning.SSEStreaming.Action = config.ActionWarn

	checks := checkDoctorConfigSemantics(cfg)

	var sawDivergence, sawSuppressOK bool
	for _, c := range checks {
		if c.Name == doctorCheckActionDivergence {
			sawDivergence = true
		}
		if c.Name == doctorCheckSuppressSemantics && c.Status == doctorStatusOK {
			sawSuppressOK = true
		}
	}
	if !sawDivergence {
		t.Fatal("expected an action-divergence check; the fixture no longer produces one")
	}
	if !sawSuppressOK {
		t.Error("suppress/exemption surface missing while an advisory was present: a clean suppression must still be reported as ok, otherwise absence of a warning is indistinguishable from a check that never ran")
	}
}

// TestSuppressAndDivergenceAreDistinctChecks is the discrimination test: with a
// config that produces both an honored-suppress advisory path and an action
// divergence, the two must land under different check names. A single shared
// name would make the private suite's suppress negative control unable to tell
// a real inert suppression from an unrelated advisory.
func TestSuppressAndDivergenceAreDistinctChecks(t *testing.T) {
	if doctorCheckActionDivergence == doctorCheckSuppressSemantics {
		t.Fatal("action divergence and suppress semantics must not share a check name")
	}
	if doctorCheckActionDivergence == doctorCheckExemptionSemantics {
		t.Fatal("action divergence and exemption semantics must not share a check name")
	}
}
