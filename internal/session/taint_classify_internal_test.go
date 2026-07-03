// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package session

import "testing"

func TestFailSafeSensitivity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		opts      ClassificationOptions
		confident bool
		want      ActionSensitivity
	}{
		{name: "failsafe_low_confidence_protects", opts: ClassificationOptions{FailSafe: true}, confident: false, want: SensitivityProtected},
		{name: "failsafe_confident_stays_normal", opts: ClassificationOptions{FailSafe: true}, confident: true, want: SensitivityNormal},
		{name: "disabled_low_confidence_stays_normal", opts: ClassificationOptions{}, confident: false, want: SensitivityNormal},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := failSafeSensitivity(tc.opts, tc.confident); got != tc.want {
				t.Fatalf("failSafeSensitivity(%+v, %v) = %s, want %s", tc.opts, tc.confident, got, tc.want)
			}
		})
	}
}
