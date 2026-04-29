// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package inference

import (
	"math"
	"slices"
	"testing"
)

// budgetTolerance is the absolute float-equality tolerance used for
// percentile assertions in this file. The reference windows are
// integer-valued, so the floats round-trip exactly; 1e-9 is plenty of
// room for any future scaled-input rows without admitting silent drift.
const budgetTolerance = 1e-9

// floatEq reports whether |a - b| <= budgetTolerance.
func floatEq(a, b float64) bool {
	return math.Abs(a-b) <= budgetTolerance
}

// TestDefaultHeadrooms_Locked is the contract-against-drift guard for the
// numeric-budget headroom defaults. Parallel to TestDefaultWilsonAlpha_Locked
// and TestDefaultFloors_Locked: if anyone bumps these constants, this test
// fails and the reviewer must justify the change in the PR. Cross-deployment
// audit parity requires the headrooms be locked at the same value everywhere.
func TestDefaultHeadrooms_Locked(t *testing.T) {
	t.Parallel()

	if DefaultHeadroomRate != 0.20 {
		t.Fatalf("DefaultHeadroomRate drift detected: got %v, want 0.20", DefaultHeadroomRate)
	}
	if DefaultHeadroomSize != 0.50 {
		t.Fatalf("DefaultHeadroomSize drift detected: got %v, want 0.50", DefaultHeadroomSize)
	}
}

// TestBudgetStats_EmptyWindow verifies the zero-valued return for empty
// inputs: nil and []float64{}. Empty windows are a valid "no observations
// yet" state and must NOT panic.
func TestBudgetStats_EmptyWindow(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   []float64
	}{
		{name: "nil_slice", in: nil},
		{name: "empty_slice", in: []float64{}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := BudgetStats(tc.in)
			want := Budget{}
			if got != want {
				t.Fatalf("BudgetStats(%v) = %+v, want %+v", tc.in, got, want)
			}
			if got.SampleCount != 0 {
				t.Fatalf("SampleCount = %d, want 0", got.SampleCount)
			}
		})
	}
}

// TestBudgetStats_FiltersNonFinite asserts that NaN and +/-Inf values
// in the input window are filtered out before percentile computation,
// so the resulting Budget never persists non-finite floats. SampleCount
// reflects the count after filtering. A window containing only
// non-finite values returns a zero-valued Budget. This is the
// fail-closed-but-valid contract on the budget math: a future caller
// that pipes a divide-by-zero result into BudgetStats cannot poison
// the persisted contract or the policy hash with NaN/Inf.
func TestBudgetStats_FiltersNonFinite(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   []float64
		want Budget
	}{
		{
			name: "interleaved_finite_and_nan",
			in:   []float64{10, math.NaN(), 20, 30, math.NaN(), 40},
			// After filtering: [10, 20, 30, 40]. Nearest-rank median:
			// ceil(50*4/100) = 2, sorted[1] = 20.
			want: Budget{P99: 40, P95: 40, Median: 20, Max: 40, SampleCount: 4},
		},
		{
			name: "interleaved_finite_and_inf",
			in:   []float64{10, math.Inf(1), 20, math.Inf(-1), 30},
			want: Budget{P99: 30, P95: 30, Median: 20, Max: 30, SampleCount: 3},
		},
		{
			name: "all_nan_returns_zero_budget",
			in:   []float64{math.NaN(), math.NaN(), math.NaN()},
			want: Budget{},
		},
		{
			name: "all_inf_returns_zero_budget",
			in:   []float64{math.Inf(1), math.Inf(-1)},
			want: Budget{},
		},
		{
			name: "mixed_inf_nan_returns_zero_budget",
			in:   []float64{math.NaN(), math.Inf(1), math.Inf(-1)},
			want: Budget{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := BudgetStats(tc.in)
			if got != tc.want {
				t.Fatalf("BudgetStats(%v) = %+v, want %+v", tc.in, got, tc.want)
			}
			if math.IsNaN(got.P99) || math.IsInf(got.P99, 0) ||
				math.IsNaN(got.P95) || math.IsInf(got.P95, 0) ||
				math.IsNaN(got.Median) || math.IsInf(got.Median, 0) ||
				math.IsNaN(got.Max) || math.IsInf(got.Max, 0) {
				t.Fatalf("Budget contains non-finite value: %+v", got)
			}
		})
	}
}

// TestBudgetStats_SingleElement verifies that a one-element window
// collapses to a Budget where all four percentile/max values equal the
// single sample.
func TestBudgetStats_SingleElement(t *testing.T) {
	t.Parallel()

	got := BudgetStats([]float64{42.5})
	want := Budget{P99: 42.5, P95: 42.5, Median: 42.5, Max: 42.5, SampleCount: 1}
	if got != want {
		t.Fatalf("BudgetStats([42.5]) = %+v, want %+v", got, want)
	}
}

// TestBudgetStats_KnownValues exercises the nearest-rank percentile
// formula on reference windows where the expected statistics are known
// by inspection. Integer-valued windows so the floats are exact.
func TestBudgetStats_KnownValues(t *testing.T) {
	t.Parallel()

	// Build [1..100] for the larger row.
	hundred := make([]float64, 100)
	for i := range hundred {
		hundred[i] = float64(i + 1)
	}

	tests := []struct {
		name   string
		in     []float64
		p99    float64
		p95    float64
		median float64
		max    float64
		count  int
	}{
		{
			name:   "one_through_ten",
			in:     []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
			p99:    10,
			p95:    10,
			median: 5,
			max:    10,
			count:  10,
		},
		{
			name:   "tens_through_hundred",
			in:     []float64{10, 20, 30, 40, 50, 60, 70, 80, 90, 100},
			p99:    100,
			p95:    100,
			median: 50,
			max:    100,
			count:  10,
		},
		{
			name:   "one_through_one_hundred",
			in:     hundred,
			p99:    99,
			p95:    95,
			median: 50,
			max:    100,
			count:  100,
		},
		{
			name:   "all_same",
			in:     []float64{7, 7, 7, 7, 7},
			p99:    7,
			p95:    7,
			median: 7,
			max:    7,
			count:  5,
		},
		{
			name:   "unsorted_input",
			in:     []float64{5, 1, 9, 3, 7, 2, 8, 4, 6, 10},
			p99:    10,
			p95:    10,
			median: 5,
			max:    10,
			count:  10,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := BudgetStats(tc.in)
			if !floatEq(got.P99, tc.p99) {
				t.Errorf("P99 = %v, want %v", got.P99, tc.p99)
			}
			if !floatEq(got.P95, tc.p95) {
				t.Errorf("P95 = %v, want %v", got.P95, tc.p95)
			}
			if !floatEq(got.Median, tc.median) {
				t.Errorf("Median = %v, want %v", got.Median, tc.median)
			}
			if !floatEq(got.Max, tc.max) {
				t.Errorf("Max = %v, want %v", got.Max, tc.max)
			}
			if got.SampleCount != tc.count {
				t.Errorf("SampleCount = %d, want %d", got.SampleCount, tc.count)
			}
		})
	}
}

// TestBudgetStats_DoesNotMutateInput verifies the caller's slice is
// untouched. BudgetStats sorts a defensive clone, not the input.
func TestBudgetStats_DoesNotMutateInput(t *testing.T) {
	t.Parallel()

	in := []float64{5, 1, 9, 3, 7, 2, 8, 4, 6, 10}
	before := slices.Clone(in)

	_ = BudgetStats(in)

	if !slices.Equal(in, before) {
		t.Fatalf("input mutated: before=%v, after=%v", before, in)
	}
}

// TestBudgetStats_PropertyP99GeP95GeMedian proves the percentile
// monotonicity invariant required by the kickoff: P99 >= P95 >= Median
// for any non-empty window. Validates that nearest-rank produces a
// monotone-increasing sequence over (50, 95, 99) percentiles.
func TestBudgetStats_PropertyP99GeP95GeMedian(t *testing.T) {
	t.Parallel()

	ascending := make([]float64, 1000)
	for i := range ascending {
		ascending[i] = float64(i + 1)
	}
	descending := make([]float64, 1000)
	for i := range descending {
		descending[i] = float64(1000 - i)
	}
	allSame := make([]float64, 100)
	for i := range allSame {
		allSame[i] = 42
	}
	nearUniform := []float64{
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
	}
	singleCluster := []float64{
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		100, // single outlier
	}

	tests := []struct {
		name string
		in   []float64
	}{
		{name: "ascending_1_to_1000", in: ascending},
		{name: "descending_1000_to_1", in: descending},
		{name: "all_same_value", in: allSame},
		{name: "near_uniform_1_to_20", in: nearUniform},
		{name: "single_cluster_with_outlier", in: singleCluster},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			b := BudgetStats(tc.in)
			if b.P99 < b.P95 {
				t.Errorf("P99 (%v) < P95 (%v); monotonicity violated", b.P99, b.P95)
			}
			if b.P95 < b.Median {
				t.Errorf("P95 (%v) < Median (%v); monotonicity violated", b.P95, b.Median)
			}
		})
	}
}

// TestBudgetStats_PropertyMaxGeP99 proves the Max-dominates-tail
// invariant: Max >= P99 for any non-empty window. Nearest-rank P99
// always selects an element of the slice, so Max (the slice's largest
// element) cannot be smaller than P99.
func TestBudgetStats_PropertyMaxGeP99(t *testing.T) {
	t.Parallel()

	ascending := make([]float64, 1000)
	for i := range ascending {
		ascending[i] = float64(i + 1)
	}
	descending := make([]float64, 1000)
	for i := range descending {
		descending[i] = float64(1000 - i)
	}
	allSame := make([]float64, 100)
	for i := range allSame {
		allSame[i] = 42
	}
	nearUniform := []float64{
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
	}
	singleCluster := []float64{
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		100,
	}

	tests := []struct {
		name string
		in   []float64
	}{
		{name: "ascending_1_to_1000", in: ascending},
		{name: "descending_1000_to_1", in: descending},
		{name: "all_same_value", in: allSame},
		{name: "near_uniform_1_to_20", in: nearUniform},
		{name: "single_cluster_with_outlier", in: singleCluster},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			b := BudgetStats(tc.in)
			if b.Max < b.P99 {
				t.Errorf("Max (%v) < P99 (%v); Max-dominance violated", b.Max, b.P99)
			}
		})
	}
}

// TestEnforcedValue_HappyPath exercises the headroom formula on
// representative inputs, including both default headroom constants and
// a P99=0 (empty Budget) row.
func TestEnforcedValue_HappyPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		budget   Budget
		headroom float64
		want     float64
	}{
		{
			name:     "p99_100_headroom_0_20",
			budget:   Budget{P99: 100, SampleCount: 50},
			headroom: 0.20,
			want:     120,
		},
		{
			name:     "p99_100_headroom_0_50",
			budget:   Budget{P99: 100, SampleCount: 50},
			headroom: 0.50,
			want:     150,
		},
		{
			name:     "p99_zero_any_headroom",
			budget:   Budget{},
			headroom: 0.20,
			want:     0,
		},
		{
			name:     "p99_42_5_headroom_default_rate",
			budget:   Budget{P99: 42.5, SampleCount: 30},
			headroom: DefaultHeadroomRate,
			want:     51.0,
		},
		{
			name:     "p99_42_5_headroom_default_size",
			budget:   Budget{P99: 42.5, SampleCount: 30},
			headroom: DefaultHeadroomSize,
			want:     63.75,
		},
		{
			name:     "p99_100_headroom_zero",
			budget:   Budget{P99: 100, SampleCount: 50},
			headroom: 0,
			want:     100,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := tc.budget.EnforcedValue(tc.headroom)
			if !floatEq(got, tc.want) {
				t.Fatalf("EnforcedValue(%v) on %+v = %v, want %v", tc.headroom, tc.budget, got, tc.want)
			}
		})
	}
}

// TestEnforcedValue_PropertyHeadroomMonotonic proves that as headroom
// increases, EnforcedValue strictly increases (when P99 is non-zero).
// This is the property called out in the kickoff: "headroom always
// increases enforced when input is non-zero".
func TestEnforcedValue_PropertyHeadroomMonotonic(t *testing.T) {
	t.Parallel()

	b := Budget{P99: 100, SampleCount: 50}
	headrooms := []float64{0.0, 0.1, 0.2, 0.5, 1.0}

	prev := b.EnforcedValue(headrooms[0])
	for i := 1; i < len(headrooms); i++ {
		got := b.EnforcedValue(headrooms[i])
		if got <= prev {
			t.Errorf("EnforcedValue(%v)=%v is not strictly greater than EnforcedValue(%v)=%v",
				headrooms[i], got, headrooms[i-1], prev)
		}
		// Also confirm the >= 0-headroom invariant (the zero-headroom
		// floor is the un-padded P99).
		if got < b.EnforcedValue(0) {
			t.Errorf("EnforcedValue(%v)=%v dipped below EnforcedValue(0)=%v", headrooms[i], got, b.EnforcedValue(0))
		}
		prev = got
	}
}

// TestEnforcedValue_NegativeHeadroomShrinks proves the documented
// behavior that negative headroom in [-1, 0) shrinks the ceiling
// without ever going negative. Callers that want a tighter-than-
// observed ceiling can express it directly.
func TestEnforcedValue_NegativeHeadroomShrinks(t *testing.T) {
	t.Parallel()

	b := Budget{P99: 100, SampleCount: 50}
	got := b.EnforcedValue(-0.10)
	want := 90.0
	if !floatEq(got, want) {
		t.Fatalf("EnforcedValue(-0.10) = %v, want %v", got, want)
	}
}

// TestEnforcedValue_ClampsAtZero proves the fail-closed-but-valid
// contract: headroom that would otherwise yield a negative ceiling is
// clamped to 0. Negative ceilings are nonsensical for a budget; a
// future caller bug that produced one could cascade into deny-all or
// allow-all behavior in downstream enforcement paths depending on how
// each callsite handles the value. Clamping here guarantees the
// invariant `EnforcedValue(...) >= 0` for any (Budget, headroom) input.
func TestEnforcedValue_ClampsAtZero(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		p99      float64
		headroom float64
		want     float64
	}{
		{"headroom_minus_one_exact_zero", 100, -1.0, 0.0},
		{"headroom_minus_one_point_five_clamps", 100, -1.5, 0.0},
		{"headroom_minus_two_clamps", 100, -2.0, 0.0},
		{"headroom_minus_one_thousand_clamps", 100, -1000.0, 0.0},
		{"empty_budget_with_clamping_headroom", 0, -10.0, 0.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			b := Budget{P99: tt.p99, SampleCount: 50}
			got := b.EnforcedValue(tt.headroom)
			if !floatEq(got, tt.want) {
				t.Fatalf("EnforcedValue(p99=%v, headroom=%v) = %v, want %v", tt.p99, tt.headroom, got, tt.want)
			}
			if got < 0 {
				t.Fatalf("EnforcedValue produced negative %v; clamp invariant violated", got)
			}
		})
	}
}

// TestNearestRank_DefensiveClamps exercises the two clamp branches of
// the internal nearestRank helper that the public BudgetStats path
// (which only ever calls with p in {50, 95, 99}) cannot reach.
//
// These clamps exist as defense-in-depth so a future caller that
// invokes nearestRank with a degenerate percentile cannot index out of
// bounds. The test uses p=0 to drive the rank<1 branch and p=200 to
// drive the rank>n branch, returning sorted[0] and sorted[n-1]
// respectively. Removing the clamps would also make this test
// disappear — by design, since the clamps are the contract.
func TestNearestRank_DefensiveClamps(t *testing.T) {
	t.Parallel()

	sorted := []float64{1, 2, 3, 4, 5}

	// p = 0 → rank = (0*5 + 99) / 100 = 0, clamps to 1, returns sorted[0].
	if got := nearestRank(sorted, 0); got != 1 {
		t.Fatalf("nearestRank(sorted, 0) = %v, want 1 (rank<1 clamp)", got)
	}

	// p = 200 → rank = (200*5 + 99) / 100 = 10, clamps to n=5, returns sorted[4].
	if got := nearestRank(sorted, 200); got != 5 {
		t.Fatalf("nearestRank(sorted, 200) = %v, want 5 (rank>n clamp)", got)
	}
}

// TestThinSample exercises the strict-less-than badge predicate at and
// around the boundary. The "just barely cleared the floor" case
// (SampleCount == minEvents) returns false: the floor was cleared.
func TestThinSample(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		count     int
		minEvents int
		want      bool
	}{
		{name: "below_floor", count: 10, minEvents: 20, want: true},
		{name: "exactly_at_floor", count: 20, minEvents: 20, want: false},
		{name: "above_floor", count: 20, minEvents: 19, want: false},
		{name: "zero_count_positive_floor", count: 0, minEvents: 20, want: true},
		{name: "both_zero", count: 0, minEvents: 0, want: false},
		{name: "well_above_floor", count: 100, minEvents: 20, want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			b := Budget{SampleCount: tc.count}
			got := b.ThinSample(tc.minEvents)
			if got != tc.want {
				t.Fatalf("ThinSample(SampleCount=%d, minEvents=%d) = %v, want %v",
					tc.count, tc.minEvents, got, tc.want)
			}
		})
	}
}
