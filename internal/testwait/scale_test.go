// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package testwait

import (
	"math"
	"testing"
	"time"
)

// TestScaleDeadline pins every state the scaling can be in. Without this the
// factor is a number nobody checks: a typo that made it 1 would silently restore
// the flaky behavior, and one that made it enormous would turn a real hang into a
// package timeout with no useful failure.
//
// The non-positive and overflow rows matter for the failure DIRECTION. A rejected
// or saturated factor must leave the wait usable; a factor that produced zero or
// a negative Duration would expire every wait immediately and report timing as
// product failure, which is exactly what this scaling exists to stop.
func TestScaleDeadline(t *testing.T) {
	base := 10 * time.Second
	ci := 40 * time.Second

	tests := []struct {
		name  string
		ci    string
		scale string
		want  time.Duration
	}{
		{name: "local, unscaled", ci: "", scale: "", want: base},
		{name: "ci scales 4x", ci: "true", scale: "", want: ci},
		// A pin must beat CI, so a bisect can reproduce the original timing on a
		// runner rather than only on a laptop.
		{name: "pin to 1 beats ci", ci: "true", scale: "1", want: base},
		{name: "pin to 1 locally", ci: "", scale: "1", want: base},
		{name: "fractional pin", ci: "true", scale: "0.5", want: 5 * time.Second},
		// Under one nanosecond the product truncates to zero, which expires
		// every wait immediately. It is positive, so the f > 0 check passes and
		// only the representability check catches it.
		{name: "sub-nanosecond falls through to local", ci: "", scale: "5e-324", want: base},
		{name: "sub-nanosecond falls through to ci", ci: "true", scale: "1e-20", want: ci},
		{name: "unparseable falls through to ci", ci: "true", scale: "bogus", want: ci},
		{name: "unparseable falls through to local", ci: "", scale: "bogus", want: base},
		{name: "zero is rejected", ci: "true", scale: "0", want: ci},
		{name: "negative is rejected", ci: "true", scale: "-1", want: ci},
		{name: "negative is rejected locally", ci: "", scale: "-2.5", want: base},
		{name: "whitespace is not an override", ci: "true", scale: "   ", want: ci},
		{name: "overflow saturates", ci: "", scale: "1e300", want: time.Duration(math.MaxInt64)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("CI", tt.ci)
			t.Setenv("PIPELOCK_TEST_DEADLINE_SCALE", tt.scale)
			got := scaleDeadline(base)
			if got != tt.want {
				t.Errorf("scaleDeadline(%v) = %v, want %v", base, got, tt.want)
			}
			if got <= 0 {
				t.Errorf("scaleDeadline(%v) = %v: a non-positive deadline expires every wait immediately", base, got)
			}
		})
	}
}
