// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// TestExplainUnevaluatedContentLayers_NilConfigNamesNothing covers the guard
// directly. With no config there is nothing to assert about which scanners are
// enabled, and inventing a caveat would be a claim about a configuration that
// was never loaded.
func TestExplainUnevaluatedContentLayers_NilConfigNamesNothing(t *testing.T) {
	if layers := explainUnevaluatedContentLayers(nil, "host.example"); layers != nil {
		t.Fatalf("nil config should name no layers, got %v", layers)
	}
	// A zero config has both scanners off, so it also names nothing.
	if layers := explainUnevaluatedContentLayers(&config.Config{}, "host.example"); len(layers) != 0 {
		t.Fatalf("zero config should name no layers, got %v", layers)
	}
	// Same guard on the other two helpers in this family. With no config there
	// is nothing to assert about which controls are enabled, and inventing a
	// disclosure would be a claim about a configuration never loaded.
	if notes := explainUnevaluatedLayerNotes(nil, "host.example"); notes != nil {
		t.Fatalf("nil config should produce no notes, got %v", notes)
	}
	if layers := explainUnevaluatedStatefulLayers(nil); layers != nil {
		t.Fatalf("nil config should name no stateful layers, got %v", layers)
	}
	if notes := explainUnevaluatedLayerNotes(&config.Config{}, "host.example"); len(notes) != 0 {
		t.Fatalf("zero config should produce no notes, got %v", notes)
	}
	if layers := explainUnevaluatedStatefulLayers(&config.Config{}); len(layers) != 0 {
		t.Fatalf("zero config should name no stateful layers, got %v", layers)
	}
}

const explainContentScopeNote = "this verdict covers URL-layer checks only"

// TestExplainCmd_AllowedVerdictDisclosesUnevaluatedContentLayers is the
// regression guard for an allowed verdict that reads as a promise explain
// cannot make.
//
// Reproduced against a released binary: a vendor documentation page that the
// proxy blocks with `response contains prompt injection` explained as ALLOWED
// with no mention of response scanning, because every layer explain evaluates
// does pass. The block came from the response body, which exists only after a
// fetch that explain never performs. An operator who hits that block and runs
// the command named explain was told the opposite of what they had just seen.
func TestExplainCmd_AllowedVerdictDisclosesUnevaluatedContentLayers(t *testing.T) {
	cfg := writeConfig(t, `
mode: balanced
response_scanning:
  enabled: true
request_body_scanning:
  enabled: true
`)
	report, err := decodeExplainJSON(t, "--config", cfg, "https://docs.vendor.example/guide")
	if err != nil {
		t.Fatalf("clean URL should be allowed, got: %v", err)
	}
	if !report.Allowed {
		t.Fatalf("expected an allowed verdict, got blocked")
	}

	notes := strings.Join(report.Notes, "\n")
	if !strings.Contains(notes, explainContentScopeNote) {
		t.Fatalf("allowed verdict did not disclose its scope: %q", notes)
	}
	for _, want := range []string{"response scanning", "request body scanning"} {
		if !strings.Contains(notes, want) {
			t.Errorf("scope note does not name %q: %q", want, notes)
		}
	}

	// The text surface is what an operator actually reads, and the scanner
	// names are the actionable part: a generic caveat with no names tells them
	// nothing about where to look.
	out, err := runExplainCmd(t, "--config", cfg, "https://docs.vendor.example/guide")
	if err != nil {
		t.Fatalf("text explain should allow URL, got: %v\n%s", err, out)
	}
	if !strings.Contains(out, explainContentScopeNote) {
		t.Fatalf("text output missing scope note:\n%s", out)
	}
	for _, want := range []string{"response scanning", "request body scanning"} {
		if !strings.Contains(out, want) {
			t.Errorf("text output does not name %q:\n%s", want, out)
		}
	}
}

// TestExplainCmd_DisclosesActiveKillSwitch is the most severe member of this
// class and the one explain could always have known.
//
// `kill_switch.enabled` is an activation source, not a feature toggle: the
// controller returns Active for it and every request is denied except exempt
// endpoints and allowlisted IPs. explain loads that same config, so printing a
// bare ALLOWED while the proxy refuses everything is a statement it had the
// information to avoid.
func TestExplainCmd_DisclosesActiveKillSwitch(t *testing.T) {
	cfg := writeConfig(t, `
mode: balanced
kill_switch:
  enabled: true
`)
	report, err := decodeExplainJSON(t, "--config", cfg, "https://docs.vendor.example/guide")
	if err != nil {
		t.Fatalf("clean URL should be allowed, got: %v", err)
	}
	notes := strings.Join(report.Notes, "\n")
	if !strings.Contains(notes, "kill_switch.enabled") || !strings.Contains(notes, "ACTIVE") {
		t.Fatalf("an active kill switch was not disclosed: %q", notes)
	}
}

// TestExplainCmd_NoKillSwitchNoteWhenInactive keeps that disclosure honest.
func TestExplainCmd_NoKillSwitchNoteWhenInactive(t *testing.T) {
	cfg := writeConfig(t, `
mode: balanced
kill_switch:
  enabled: false
`)
	report, err := decodeExplainJSON(t, "--config", cfg, "https://docs.vendor.example/guide")
	if err != nil {
		t.Fatalf("clean URL should be allowed, got: %v", err)
	}
	if notes := strings.Join(report.Notes, "\n"); strings.Contains(notes, "kill switch is ACTIVE") {
		t.Fatalf("kill-switch note fired while inactive: %q", notes)
	}
}

// TestExplainCmd_DisclosesStatefulLayers covers the controls that decide from
// request history. A single-URL evaluation cannot reach them even in
// principle, and both routinely block a URL that is clean on its own.
func TestExplainCmd_DisclosesStatefulLayers(t *testing.T) {
	cfg := writeConfig(t, `
mode: balanced
session_profiling:
  enabled: true
adaptive_enforcement:
  enabled: true
cross_request_detection:
  enabled: true
  action: warn
  entropy_budget:
    enabled: true
    bits_per_window: 4096
    window_minutes: 5
    action: warn
`)
	report, err := decodeExplainJSON(t, "--config", cfg, "https://docs.vendor.example/guide")
	if err != nil {
		t.Fatalf("clean URL should be allowed, got: %v", err)
	}
	notes := strings.Join(report.Notes, "\n")
	for _, want := range []string{"cross-request detection", "adaptive enforcement", "accumulated request history"} {
		if !strings.Contains(notes, want) {
			t.Errorf("stateful disclosure missing %q: %q", want, notes)
		}
	}
}

// TestExplainCmd_NoStatefulNoteWhenDisabled proves that disclosure is
// conditional too.
func TestExplainCmd_NoStatefulNoteWhenDisabled(t *testing.T) {
	cfg := writeConfig(t, `
mode: balanced
adaptive_enforcement:
  enabled: false
cross_request_detection:
  enabled: false
`)
	report, err := decodeExplainJSON(t, "--config", cfg, "https://docs.vendor.example/guide")
	if err != nil {
		t.Fatalf("clean URL should be allowed, got: %v", err)
	}
	if notes := strings.Join(report.Notes, "\n"); strings.Contains(notes, "accumulated request history") {
		t.Fatalf("stateful note fired with both controls disabled: %q", notes)
	}
}

// TestExplainCmd_ScopeNoteNamesOnlyEnabledLayers keeps the note honest in the
// other direction. Naming a scanner that is switched off would be a false
// alarm, and an advisory that cries wolf is ignored along with the ones that
// matter.
func TestExplainCmd_ScopeNoteNamesOnlyEnabledLayers(t *testing.T) {
	cfg := writeConfig(t, `
mode: balanced
response_scanning:
  enabled: true
request_body_scanning:
  enabled: false
`)
	report, err := decodeExplainJSON(t, "--config", cfg, "https://docs.vendor.example/guide")
	if err != nil {
		t.Fatalf("clean URL should be allowed, got: %v", err)
	}
	notes := strings.Join(report.Notes, "\n")
	if !strings.Contains(notes, "response scanning") {
		t.Fatalf("scope note should name the enabled scanner: %q", notes)
	}
	if strings.Contains(notes, "request body scanning") {
		t.Fatalf("scope note named a disabled scanner: %q", notes)
	}
}

// TestExplainCmd_ScopeNoteRequestBodyOnly covers the request-body-only path.
// Exercising that scanner only alongside response scanning would let a
// regression that gated its disclosure on response scanning pass unnoticed.
func TestExplainCmd_ScopeNoteRequestBodyOnly(t *testing.T) {
	cfg := writeConfig(t, `
mode: balanced
response_scanning:
  enabled: false
request_body_scanning:
  enabled: true
`)
	report, err := decodeExplainJSON(t, "--config", cfg, "https://docs.vendor.example/guide")
	if err != nil {
		t.Fatalf("clean URL should be allowed, got: %v", err)
	}
	notes := strings.Join(report.Notes, "\n")
	if !strings.Contains(notes, "request body scanning") {
		t.Fatalf("scope note should name the enabled scanner: %q", notes)
	}
	if strings.Contains(notes, "response scanning") {
		t.Fatalf("scope note named a disabled scanner: %q", notes)
	}
}

// TestExplainCmd_ScopeNoteQualifiesExemptHostWithoutHidingDLP covers an
// exemption that narrows response scanning without switching it off.
//
// `response_scanning.exempt_domains` skips INJECTION scanning only; response
// DLP still applies and can still block the request. So the disclosure must
// survive for an exempt host, with wording that does not claim injection
// scanning applies. Dropping the entry entirely would hide a live check, which
// is the failure this whole note exists to prevent.
func TestExplainCmd_ScopeNoteQualifiesExemptHostWithoutHidingDLP(t *testing.T) {
	cfg := writeConfig(t, `
mode: balanced
response_scanning:
  enabled: true
  exempt_domains:
    - provider.example
request_body_scanning:
  enabled: true
`)
	report, err := decodeExplainJSON(t, "--config", cfg, "https://provider.example/download")
	if err != nil {
		t.Fatalf("exempt host should be allowed, got: %v", err)
	}
	notes := strings.Join(report.Notes, "\n")
	// The disclosure must survive: response DLP still runs for this host.
	if !strings.Contains(notes, explainContentScopeNote) {
		t.Fatalf("exempt host lost the scope disclosure entirely: %q", notes)
	}
	if !strings.Contains(notes, "response DLP") {
		t.Fatalf("exempt host must still be told response DLP applies: %q", notes)
	}
	// ...but it must not claim injection scanning applies to an exempt host.
	if !strings.Contains(notes, "injection scanning is exempt for this host") {
		t.Fatalf("scope note did not qualify the exemption: %q", notes)
	}
	if !strings.Contains(notes, "request body scanning") {
		t.Fatalf("request body scanning still applies to an exempt host and must be named: %q", notes)
	}
	// The exemption's own advisory is a separate note and must survive.
	if !strings.Contains(notes, "response_scanning.exempt_domains") {
		t.Fatalf("exemption advisory disappeared: %q", notes)
	}
}

// TestExplainCmd_ScopeNoteKeepsResponseScanningForNonExemptHost is the other
// direction: exemptions configured for a DIFFERENT host must not suppress the
// disclosure for this one.
func TestExplainCmd_ScopeNoteKeepsResponseScanningForNonExemptHost(t *testing.T) {
	cfg := writeConfig(t, `
mode: balanced
response_scanning:
  enabled: true
  exempt_domains:
    - provider.example
request_body_scanning:
  enabled: false
`)
	report, err := decodeExplainJSON(t, "--config", cfg, "https://docs.vendor.example/guide")
	if err != nil {
		t.Fatalf("non-exempt host should be allowed, got: %v", err)
	}
	notes := strings.Join(report.Notes, "\n")
	if !strings.Contains(notes, explainContentScopeNote) || !strings.Contains(notes, "response scanning") {
		t.Fatalf("non-exempt host must still be told response scanning applies: %q", notes)
	}
}

// TestExplainCmd_NoScopeNoteWhenNoContentScannerEnabled proves the note is
// conditional. With nothing to disclose, an allowed verdict really does cover
// everything that would run, and adding the caveat anyway would be noise.
func TestExplainCmd_NoScopeNoteWhenNoContentScannerEnabled(t *testing.T) {
	cfg := writeConfig(t, `
mode: balanced
response_scanning:
  enabled: false
request_body_scanning:
  enabled: false
`)
	report, err := decodeExplainJSON(t, "--config", cfg, "https://docs.vendor.example/guide")
	if err != nil {
		t.Fatalf("clean URL should be allowed, got: %v", err)
	}
	notes := strings.Join(report.Notes, "\n")
	if strings.Contains(notes, explainContentScopeNote) {
		t.Fatalf("scope note fired with no content scanner enabled: %q", notes)
	}
}
