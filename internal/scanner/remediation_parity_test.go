// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"fmt"
	"strings"
	"testing"
)

func TestGuidancePhraseParity(t *testing.T) {
	phrases := []string{"", "nested url in query parameter", nestedURLBudgetReason}
	reasons := []string{
		"", "URL length 2049 exceeds maximum 2048", "plain reason", "NESTED URL IN QUERY PARAMETER",
		"nested url in query parameter", "nested URL in query parameter", "SHARED RESOLUTION BUDGET",
		"nested url \u0130n query parameter", "shared resolut\u0130on budget", "前nested URL in query parameter後",
	}
	for value := byte(0); ; value++ {
		text := string([]byte{value})
		reasons = append(reasons, text+"nested URL in query parameter", "nested URL "+text+"in query parameter", "shared resolution budget"+text)
		if value == 255 {
			break
		}
	}
	for i, reason := range reasons {
		t.Run(fmt.Sprintf("reason_%d", i), func(t *testing.T) {
			for _, phrase := range phrases {
				if got, want := containsLowerASCII(reason, phrase), strings.Contains(strings.ToLower(reason), phrase); got != want {
					t.Fatalf("phrase %q differs for %q: got %v, want %v", phrase, reason, got, want)
				}
			}
		})
	}
}

func TestGuidanceAnnotationParityAndRequestIsolation(t *testing.T) {
	reasons := []string{
		"URL length 2049 exceeds maximum 2048",
		`nested URL in query parameter "next": blocked destination`,
		`nested URL in query parameter "shared resolution budget": blocked destination`,
		`nested URL in query parameter "next": shared resolution budget`,
		`NESTED URL IN QUERY PARAMETER "next": BLOCKED DESTINATION`,
		`nested url \"next\": malformed description`,
		"nested url \u0130n query parameter",
		"different body",
	}
	for pass := 0; pass < 2; pass++ {
		for i := range reasons {
			index := i
			if pass != 0 {
				index = len(reasons) - 1 - i
			}
			reason := reasons[index]
			stripped := stripNestedURLReasonPrefix(reason)
			for _, label := range []string{ScannerLength, ScannerSSRF, ScannerCoreSSRF, ScannerDLP} {
				for _, immutable := range []bool{false, true} {
					g := RemediationGuidance{OperatorKnob: "existing hint", AgentReason: "existing reason", Immutable: immutable}
					got := annotateNestedURLGuidance(g, label, reason, stripped)
					want := referenceAnnotateNestedURLGuidance(g, label, reason, stripped)
					if got != want {
						t.Fatalf("annotation differs for %q / %q: got %+v, want %+v", label, reason, got, want)
					}
				}
			}
		}
	}
}

func referenceAnnotateNestedURLGuidance(g RemediationGuidance, label, reason, stripped string) RemediationGuidance {
	if strings.Contains(strings.ToLower(stripped), strings.ToLower(nestedURLBudgetReason)) {
		return g
	}
	if !strings.Contains(strings.ToLower(reason), "nested url in query parameter") {
		return g
	}
	nestedKnob := " Nested query destinations are evaluated because `fetch_proxy.monitoring.scan_nested_urls` is enabled (nil/true). Set it false only for an endpoint whose contract legitimately carries private or blocklisted URLs in query strings."
	switch label {
	case ScannerSSRF, ScannerCoreSSRF:
		if !g.Immutable {
			nestedKnob += " The nested host consults `ssrf.ip_allowlist`, `trusted_domains`, and `dns.host_overrides` because it reuses the same destination checks as the outer host."
		}
	}
	g.OperatorKnob += nestedKnob
	return g
}
