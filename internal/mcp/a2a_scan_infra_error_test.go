// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// Synthetic scanner.Result builders for A2A aggregator tests. Mirrors what
// the SSRF layer emits for each classification tier.
func a2aInfraResult() scanner.Result {
	return scanner.Result{
		Allowed: false,
		Reason:  "SSRF check failed: DNS resolution error for extensions.test: lookup extensions.test: i/o timeout",
		Scanner: scanner.ScannerSSRF,
		Score:   1.0,
		Class:   scanner.ClassInfrastructureError,
	}
}

func a2aConfigMismatchResult() scanner.Result {
	return scanner.Result{
		Allowed: false,
		Reason:  "SSRF blocked: allowlisted domain not in trusted_domains",
		Scanner: scanner.ScannerSSRF,
		Score:   0.5,
		Class:   scanner.ClassConfigMismatch,
	}
}

func a2aThreatResult() scanner.Result {
	return scanner.Result{
		Allowed: false,
		Reason:  "SSRF blocked: resolves to private IP 10.0.0.5",
		Scanner: scanner.ScannerSSRF,
		Score:   1.0,
		Class:   scanner.ClassThreat,
	}
}

// TestA2AScanResult_IsInfrastructureError_AllInfra verifies the happy path:
// every URL finding is infrastructure → aggregator reports true.
func TestA2AScanResult_IsInfrastructureError_AllInfra(t *testing.T) {
	r := A2AScanResult{
		Clean: false,
		URLFindings: []scanner.Result{
			a2aInfraResult(),
			a2aInfraResult(),
		},
	}
	if !r.IsInfrastructureError() {
		t.Error("A2A result with only infrastructure URL findings must aggregate to IsInfrastructureError=true")
	}
	if !r.IsAdaptiveNeutral() {
		t.Error("A2A result with only infrastructure URL findings must aggregate to IsAdaptiveNeutral=true")
	}
	if r.IsConfigMismatch() {
		t.Error("infrastructure-only result must not aggregate to IsConfigMismatch=true")
	}
}

// TestA2AScanResult_IsInfrastructureError_Mixed verifies the short-circuit:
// a single real threat among infrastructure findings must prevent aggregation
// to neutral. Without this, an attacker could mix one NXDOMAIN URL alongside
// a real SSRF payload to hide the real probe from adaptive scoring.
func TestA2AScanResult_IsInfrastructureError_Mixed(t *testing.T) {
	r := A2AScanResult{
		Clean: false,
		URLFindings: []scanner.Result{
			a2aInfraResult(),
			a2aThreatResult(), // one real threat mixed in
		},
	}
	if r.IsInfrastructureError() {
		t.Error("A2A result mixing infrastructure + real threat must NOT aggregate to IsInfrastructureError=true (attacker bypass)")
	}
	if r.IsAdaptiveNeutral() {
		t.Error("mixed result must NOT aggregate to IsAdaptiveNeutral=true")
	}
}

// TestA2AScanResult_IsInfrastructureError_WithDLP verifies the cross-category
// short-circuit: DLP or injection findings alongside infrastructure → not neutral.
// An embedded secret in a URL argument still counts as a real finding even
// if another URL field has a DNS failure.
func TestA2AScanResult_IsInfrastructureError_WithDLP(t *testing.T) {
	r := A2AScanResult{
		Clean: false,
		URLFindings: []scanner.Result{
			a2aInfraResult(),
		},
		DLPFindings: []scanner.TextDLPMatch{
			{PatternName: "aws_access_key"},
		},
	}
	if r.IsInfrastructureError() {
		t.Error("A2A result with DLP finding must NOT aggregate to IsInfrastructureError=true")
	}
	if r.IsAdaptiveNeutral() {
		t.Error("A2A result with DLP finding must NOT aggregate to IsAdaptiveNeutral=true")
	}
}

// TestA2AScanResult_IsInfrastructureError_WithInjection same pattern for
// injection findings.
func TestA2AScanResult_IsInfrastructureError_WithInjection(t *testing.T) {
	r := A2AScanResult{
		Clean: false,
		URLFindings: []scanner.Result{
			a2aInfraResult(),
		},
		InjectFindings: []scanner.ResponseMatch{
			{PatternName: "jailbreak"},
		},
	}
	if r.IsInfrastructureError() {
		t.Error("A2A result with injection finding must NOT aggregate to IsInfrastructureError=true")
	}
	if r.IsAdaptiveNeutral() {
		t.Error("A2A result with injection finding must NOT aggregate to IsAdaptiveNeutral=true")
	}
}

// TestA2AScanResult_IsInfrastructureError_Clean verifies that a clean result
// is never classified as infrastructure (the aggregator only matters for
// non-clean results where a block is imminent).
func TestA2AScanResult_IsInfrastructureError_Clean(t *testing.T) {
	r := A2AScanResult{Clean: true}
	if r.IsInfrastructureError() {
		t.Error("clean A2A result must not aggregate to IsInfrastructureError=true")
	}
	if r.IsAdaptiveNeutral() {
		t.Error("clean A2A result must not aggregate to IsAdaptiveNeutral=true")
	}
}

// TestA2AScanResult_IsInfrastructureError_NoURLFindings verifies that a
// non-clean result with zero URL findings is not classified as infrastructure.
// This prevents the aggregator from silently returning true for DLP-only blocks.
func TestA2AScanResult_IsInfrastructureError_NoURLFindings(t *testing.T) {
	r := A2AScanResult{
		Clean: false,
		DLPFindings: []scanner.TextDLPMatch{
			{PatternName: "aws_access_key"},
		},
	}
	if r.IsInfrastructureError() {
		t.Error("DLP-only finding must not aggregate to IsInfrastructureError=true")
	}
}

// TestA2AScanResult_IsAdaptiveNeutral_WithConfigMismatch verifies that the
// IsAdaptiveNeutral aggregator does NOT cover config mismatch. Config mismatch
// must remain a bounded NearMiss signal; folding it into "neutral" would
// silently drop probe visibility of misconfigured allowlists.
func TestA2AScanResult_IsAdaptiveNeutral_WithConfigMismatch(t *testing.T) {
	r := A2AScanResult{
		Clean: false,
		URLFindings: []scanner.Result{
			a2aConfigMismatchResult(),
		},
	}
	if r.IsAdaptiveNeutral() {
		t.Error("A2A result with config-mismatch URL finding must NOT aggregate to IsAdaptiveNeutral=true — config mismatch is a bounded NearMiss, not neutral")
	}
	if !r.IsConfigMismatch() {
		t.Error("A2A result with only config-mismatch URL finding must aggregate to IsConfigMismatch=true")
	}
}

// TestA2AScanResult_IsAdaptiveNeutral_MixedNeutralClasses verifies that the
// aggregator returns true when all findings are adaptive-neutral even if they
// mix protective and infrastructure classes. This guards the "helper is the
// union of protective + infrastructure" contract at the aggregator level.
func TestA2AScanResult_IsAdaptiveNeutral_MixedNeutralClasses(t *testing.T) {
	r := A2AScanResult{
		Clean: false,
		URLFindings: []scanner.Result{
			a2aInfraResult(),
			{
				Allowed: false,
				Reason:  "rate limit exceeded",
				Scanner: scanner.ScannerRateLimit,
				Class:   scanner.ClassProtective,
			},
		},
	}
	if !r.IsAdaptiveNeutral() {
		t.Error("aggregator must return true when all URL findings are adaptive-neutral (mix of protective + infrastructure)")
	}
	if r.IsInfrastructureError() {
		t.Error("aggregator must NOT return IsInfrastructureError=true when mixed with protective (only pure infrastructure qualifies)")
	}
}
