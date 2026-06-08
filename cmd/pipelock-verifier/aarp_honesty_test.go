// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/aarp"
)

// TestEmitAARPHumanLeadsWithLimitations proves the default human view is
// self-incriminating: does_not_assert and overclaim_risks are printed BEFORE the
// verified claims, so the first thing a reader sees is what is NOT proven.
func TestEmitAARPHumanLeadsWithLimitations(t *testing.T) {
	t.Parallel()
	ap := &aarp.Appraisal{
		Profile:         aarp.Profile,
		AssertionSigned: true,
		VerifiedClaims:  []string{aarp.ClaimReceiptSignatureValid, aarp.ClaimSigningWorkloadSVIDBound},
		DoesNotAssert: []string{
			"absence_of_bypass",
			aarp.DNAssertNetworkNonBypassFromIdentity,
		},
		OverclaimRisks: []string{
			aarp.RiskSignatureValidNotTransparency,
			aarp.RiskSVIDIdentityNotDeploymentNonBypass,
		},
		Assurance: aarp.AssuranceSummary{AxesWithVerifiedClaims: []string{aarp.AxisIdentity, aarp.AxisIntegrity}},
		Signatures: []aarp.SignatureResult{
			{KeyID: "k-signer", Alg: "ed25519", Status: aarp.SigVerified},
		},
	}
	var buf bytes.Buffer
	emitAARPHuman(&buf, ap)
	out := buf.String()

	idxDNA := strings.Index(out, "does_not_assert")
	idxRisks := strings.Index(out, "overclaim_risks")
	idxVerified := strings.Index(out, "verified_claims")
	if idxDNA < 0 || idxRisks < 0 || idxVerified < 0 {
		t.Fatalf("missing a section in output:\n%s", out)
	}
	if idxDNA >= idxRisks || idxRisks >= idxVerified {
		t.Fatalf("limitations must lead: does_not_assert(%d) < overclaim_risks(%d) < verified_claims(%d)\n%s",
			idxDNA, idxRisks, idxVerified, out)
	}
	// The axis-set descriptor reports coverage against all six axes, never a grade.
	if !strings.Contains(out, "evidence covers axes: identity, integrity (2 of 6)") {
		t.Fatalf("axis coverage line missing or wrong:\n%s", out)
	}
	// A risk renders its plain-language sentence, not just the code.
	if !strings.Contains(out, "not proof the receipt was witnessed by an external transparency log") {
		t.Fatalf("overclaim risk sentence missing:\n%s", out)
	}
}

// TestEmitAARPHumanNoRisks confirms the overclaim_risks block is omitted when
// there are none, and the axis line reports "(none)" for an unsigned appraisal.
func TestEmitAARPHumanNoRisks(t *testing.T) {
	t.Parallel()
	ap := &aarp.Appraisal{Profile: aarp.Profile, DoesNotAssert: []string{"efficacy"}}
	var buf bytes.Buffer
	emitAARPHuman(&buf, ap)
	out := buf.String()
	if strings.Contains(out, "overclaim_risks") {
		t.Fatalf("expected no overclaim_risks block:\n%s", out)
	}
	if !strings.Contains(out, "evidence covers axes: (none) (0 of 6)") {
		t.Fatalf("expected (none) axis coverage:\n%s", out)
	}
}

// TestOverclaimRiskSentence maps every known code to a sentence and falls back to
// the bare code for an unknown one, so a verifier ahead of this CLI never drops a
// warning silently.
func TestOverclaimRiskSentence(t *testing.T) {
	t.Parallel()
	known := []string{
		aarp.RiskSignatureValidNotTransparency,
		aarp.RiskSVIDIdentityNotDeploymentNonBypass,
		aarp.RiskChainLinkNotContiguousChain,
	}
	for _, code := range known {
		if s := overclaimRiskSentence(code); s == "" || s == code {
			t.Fatalf("code %q: want an explanatory sentence, got %q", code, s)
		}
	}
	const unknown = "some_future_risk_code"
	if s := overclaimRiskSentence(unknown); s != unknown {
		t.Fatalf("unknown code: want bare code %q, got %q", unknown, s)
	}
}
