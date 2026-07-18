// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package session

import "testing"

func TestRiskInternalHelpers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		action      ActionClass
		sensitivity ActionSensitivity
		want        bool
	}{
		{name: "elevated read is sensitive", action: ActionClassRead, sensitivity: SensitivityElevated, want: true},
		{name: "normal read is not sensitive", action: ActionClassRead, sensitivity: SensitivityNormal, want: false},
		{name: "normal write is sensitive", action: ActionClassWrite, sensitivity: SensitivityNormal, want: true},
		{name: "normal exec is sensitive", action: ActionClassExec, sensitivity: SensitivityNormal, want: true},
		{name: "normal secret is sensitive", action: ActionClassSecret, sensitivity: SensitivityNormal, want: true},
		{name: "normal publish is sensitive", action: ActionClassPublish, sensitivity: SensitivityNormal, want: true},
		{name: "normal network is not sensitive", action: ActionClassNetwork, sensitivity: SensitivityNormal, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := isSensitiveAction(tt.action, tt.sensitivity); got != tt.want {
				t.Fatalf("isSensitiveAction(%s, %s) = %v, want %v", tt.action, tt.sensitivity, got, tt.want)
			}
		})
	}

	sources := appendBoundedSource([]TaintSourceRef{
		{URL: "https://one.example"},
		{URL: "https://two.example"},
	}, TaintSourceRef{URL: "https://three.example"}, 2)
	if len(sources) != 2 || sources[0].URL != "https://two.example" || sources[1].URL != "https://three.example" {
		t.Fatalf("appendBoundedSource trimmed to %v, want last two sources", sources)
	}

	var risk *SessionRisk
	risk.Observe(RiskObservation{Source: TaintSourceRef{URL: "https://ignored.example", Level: TaintExternalHostile}})
}
