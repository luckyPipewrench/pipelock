// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package inference

import (
	"math"
	"testing"
)

// wilsonTolerance is the per-row comparison tolerance for the Wilson
// edge-case table. Three decimal places is the contract guarantee in the
// design; tighter tolerances belong in property tests, not row tables.
const wilsonTolerance = 1e-3

func TestWilsonLowerBound_EdgeCases(t *testing.T) {
	t.Parallel()

	// Reference values computed from the closed-form formula with
	// z = 1.959963984540054 (alpha = 0.05). Defensive cases return 0.0.
	cases := []struct {
		name        string
		observed    int
		opportunity int
		alpha       float64
		want        float64
	}{
		// Required design-table rows.
		{"zero/zero", 0, 0, DefaultWilsonAlpha, 0.0},
		{"observed_gt_opportunity_defensive", 5, 0, DefaultWilsonAlpha, 0.0},
		{"one_trial_zero_observed", 0, 1, DefaultWilsonAlpha, 0.0},
		{"one_trial_one_observed", 1, 1, DefaultWilsonAlpha, 0.207},
		{"five_of_five", 5, 5, DefaultWilsonAlpha, 0.566},
		{"twenty_of_twenty", 20, 20, DefaultWilsonAlpha, 0.839},
		{"twenty_eight_of_twenty_eight", 28, 28, DefaultWilsonAlpha, 0.879},
		{"hundred_trials_zero_observed", 0, 100, DefaultWilsonAlpha, 0.0},
		{"hundred_of_hundred", 100, 100, DefaultWilsonAlpha, 0.964},

		// Additional boundary probes.
		{"high_n_all_positive", 10000, 10000, DefaultWilsonAlpha, 1.000},
		{"two_of_two", 2, 2, DefaultWilsonAlpha, 0.342},
		{"fifty_fifty", 50, 100, DefaultWilsonAlpha, 0.404},
		{"one_third_of_thirty", 10, 30, DefaultWilsonAlpha, 0.192},
		{"two_thirds_of_thirty", 20, 30, DefaultWilsonAlpha, 0.488},
		{"negative_observed_defensive", -1, 10, DefaultWilsonAlpha, 0.0},
		{"alpha_zero_defensive", 50, 100, 0.0, 0.0},
		{"alpha_one_defensive", 50, 100, 1.0, 0.0},
		{"observed_exceeds_opportunity_defensive", 20, 10, DefaultWilsonAlpha, 0.0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := WilsonLowerBound(tc.observed, tc.opportunity, tc.alpha)
			if math.IsNaN(got) {
				t.Fatalf("WilsonLowerBound(%d,%d,%g) returned NaN; must be defined",
					tc.observed, tc.opportunity, tc.alpha)
			}
			// High-N all-positive case: lower bound approaches 1 but is
			// strictly below it. Accept anything within tolerance of 1.
			if math.Abs(got-tc.want) > wilsonTolerance {
				t.Fatalf("WilsonLowerBound(%d,%d,%g) = %.6f; want %.3f (±%g)",
					tc.observed, tc.opportunity, tc.alpha,
					got, tc.want, wilsonTolerance)
			}
		})
	}
}

func TestWilsonLowerBound_Monotonicity(t *testing.T) {
	t.Parallel()

	const n = 100
	prev := WilsonLowerBound(0, n, DefaultWilsonAlpha)
	for k := 1; k <= n; k++ {
		got := WilsonLowerBound(k, n, DefaultWilsonAlpha)
		if got < prev {
			t.Fatalf("monotonicity violated at k=%d: got=%.9f prev=%.9f",
				k, got, prev)
		}
		prev = got
	}
}

func TestWilsonLowerBound_Determinism(t *testing.T) {
	t.Parallel()

	// Same inputs must produce bitwise-identical output across 1000 calls.
	first := WilsonLowerBound(50, 100, DefaultWilsonAlpha)
	for i := 0; i < 1000; i++ {
		got := WilsonLowerBound(50, 100, DefaultWilsonAlpha)
		if got != first {
			t.Fatalf("non-deterministic at iteration %d: got=%v first=%v",
				i, got, first)
		}
	}
}

func TestWilsonComplementarySymmetry(t *testing.T) {
	t.Parallel()

	// For valid (k, n), WilsonLowerBound(n-k, n) == 1 - WilsonUpperBound(k, n).
	// This is the canonical symmetry property of the Wilson interval.
	cases := []struct {
		k, n int
	}{
		{3, 10},
		{50, 100},
		{750, 1000},
	}
	const symTolerance = 1e-9
	for _, tc := range cases {
		lower := WilsonLowerBound(tc.n-tc.k, tc.n, DefaultWilsonAlpha)
		upper := WilsonUpperBound(tc.k, tc.n, DefaultWilsonAlpha)
		want := 1 - upper
		if math.Abs(lower-want) > symTolerance {
			t.Fatalf("symmetry broken for k=%d n=%d: lower(n-k)=%.12f 1-upper(k)=%.12f diff=%.3g",
				tc.k, tc.n, lower, want, math.Abs(lower-want))
		}
	}
}

func TestDefaultWilsonAlpha_Locked(t *testing.T) {
	t.Parallel()

	// Contract-against-drift guard. If anyone bumps this constant, this
	// test fails and the reviewer must justify the change in the PR.
	if DefaultWilsonAlpha != 0.05 {
		t.Fatalf("DefaultWilsonAlpha drift detected: got %v, want 0.05", DefaultWilsonAlpha)
	}
}

// TestWilsonUpperBound_EdgeCases exercises the upper-bound defensive paths
// and standard cases. Required for 100% line coverage on wilson.go and to
// prove the upper bound's defensive returns match the lower bound's.
func TestWilsonUpperBound_EdgeCases(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		observed    int
		opportunity int
		alpha       float64
		want        float64
	}{
		{"zero_opportunity", 0, 0, DefaultWilsonAlpha, 0.0},
		{"negative_observed", -1, 10, DefaultWilsonAlpha, 0.0},
		{"observed_exceeds_opportunity", 20, 10, DefaultWilsonAlpha, 0.0},
		{"alpha_zero", 50, 100, 0.0, 0.0},
		{"alpha_one", 50, 100, 1.0, 0.0},
		{"hundred_trials_zero_observed", 0, 100, DefaultWilsonAlpha, 0.037},
		{"fifty_fifty", 50, 100, DefaultWilsonAlpha, 0.596},
		{"hundred_of_hundred_caps_at_one", 100, 100, DefaultWilsonAlpha, 1.0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := WilsonUpperBound(tc.observed, tc.opportunity, tc.alpha)
			if math.IsNaN(got) {
				t.Fatalf("WilsonUpperBound(%d,%d,%g) returned NaN; must be defined",
					tc.observed, tc.opportunity, tc.alpha)
			}
			if math.Abs(got-tc.want) > wilsonTolerance {
				t.Fatalf("WilsonUpperBound(%d,%d,%g) = %.6f; want %.3f (±%g)",
					tc.observed, tc.opportunity, tc.alpha,
					got, tc.want, wilsonTolerance)
			}
		})
	}
}

// TestWilsonNonDefaultAlpha exercises the Beasley-Springer-Moro path
// (alpha != 0.05). Required for 100% line coverage on the invNormalCDF
// branches. We probe the central region (alpha=0.10), the lower tail
// (alpha=0.001 → 1-alpha/2=0.9995, falls through to upper tail of
// invNormalCDF), and verify the body region with alpha=0.5
// (1-alpha/2=0.75, central region of invNormalCDF).
func TestWilsonNonDefaultAlpha(t *testing.T) {
	t.Parallel()

	// Central region of invNormalCDF (p = 0.95 for alpha=0.10).
	// z_{0.95} ≈ 1.6449. For n=100, k=50, lower ≈ 0.4188.
	got90 := WilsonLowerBound(50, 100, 0.10)
	if math.Abs(got90-0.4188) > 1e-3 {
		t.Fatalf("alpha=0.10 (central region): n=100 k=50 lower = %.6f, want ~0.4188", got90)
	}

	// Upper-tail region of invNormalCDF: alpha=0.0001 → p=1-alpha/2=0.99995,
	// which is greater than pHigh (≈0.97575), so the upper-tail branch fires.
	// z_{0.99995} ≈ 3.8906. For n=100, k=50, lower ≈ 0.3187.
	gotTiny := WilsonLowerBound(50, 100, 0.0001)
	if math.Abs(gotTiny-0.3187) > 1e-3 {
		t.Fatalf("alpha=0.0001 (upper tail): n=100 k=50 lower = %.6f, want ~0.3187", gotTiny)
	}

	// Lower-tail region of invNormalCDF (p < pLow ≈ 0.02425). This branch
	// is unreachable from WilsonLowerBound's alpha input alone (alpha must
	// be in (0,1), so 1-alpha/2 is in (0.5, 1) and never below pLow).
	// Cover it via direct invocation. invNormalCDF(0.001) ≈ -3.0902.
	zLowTail := invNormalCDF(0.001)
	if math.Abs(zLowTail-(-3.0902)) > 1e-3 {
		t.Fatalf("invNormalCDF(0.001) (lower tail) = %.6f, want ~-3.0902", zLowTail)
	}

	// Wide alpha (alpha=0.5 → p=0.75, central region of invNormalCDF).
	// z_{0.75} ≈ 0.6745. For n=100, k=50, lower ≈ 0.4664.
	gotWide := WilsonLowerBound(50, 100, 0.5)
	if math.Abs(gotWide-0.4664) > 1e-3 {
		t.Fatalf("alpha=0.5 (wide central): n=100 k=50 lower = %.6f, want ~0.4664", gotWide)
	}
}
