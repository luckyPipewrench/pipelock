// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package inference

import (
	"math"
	"slices"
)

// DefaultHeadroomRate is the default multiplicative headroom applied to
// the observed P99 of a rate-dimensioned numeric budget (events per unit
// time). The enforced ceiling is computed as `p99 * (1 + headroom)`, so
// 0.20 means "allow 20% above the observed tail".
//
// Like DefaultWilsonAlpha, TauStable, and TauBrittle, this constant is
// part of the statistical contract and is NOT exposed as a config field.
// Making it deployment-configurable would let two installs derive
// different enforced ceilings from identical recorder data, which is
// audit drift rather than flexibility. The value comes from the
// contract inference engine design baseline.
//
// The Budget type itself is dimension-agnostic; the caller picks
// DefaultHeadroomRate vs DefaultHeadroomSize when invoking
// Budget.EnforcedValue based on what kind of metric the rule covers.
const DefaultHeadroomRate = 0.20

// DefaultHeadroomSize is the default multiplicative headroom applied to
// the observed P99 of a size-dimensioned numeric budget (bytes or
// element count per request). Larger than DefaultHeadroomRate because
// per-request size distributions tolerate more variability than per-time
// rate distributions: a single oversized request is a much weaker signal
// than a sudden burst of requests, so the safety margin can be wider
// without admitting noise.
//
// Same contract logic as DefaultHeadroomRate: locked, not deployment-
// configurable, sourced from the contract inference engine design
// baseline. The value is 0.50, meaning "allow 50% above the observed
// tail".
const DefaultHeadroomSize = 0.50

// Budget is the inference package's pure value type for the persisted
// statistics of a numeric-budget rule. The four observed statistics
// (P99, P95, Median, Max) plus SampleCount are the canonical record-level
// shape from the design baseline: review UX renders all of them, the
// "thin-sample" badge is driven by SampleCount vs the rule's MinEvents
// floor, and the property test pack uses Median to prove the
// percentile-monotonicity invariant.
//
// No YAML or JSON tags here — this is a pure value type. The config and
// persistence layers wrap it later with their own tags.
type Budget struct {
	// P99 is the 99th-percentile observed value across the input window.
	P99 float64

	// P95 is the 95th-percentile observed value across the input window.
	P95 float64

	// Median is the 50th-percentile (median) observed value across the
	// input window. Persisted alongside the tail percentiles so the
	// review UX can show the typical value next to the tail values, and
	// so the contract test pack can prove the P99 >= P95 >= Median
	// monotonicity invariant on observed data.
	Median float64

	// Max is the maximum observed value across the input window.
	Max float64

	// SampleCount is the count of samples that produced these
	// statistics (NOT the number of samples retained after any drop or
	// dedup pass — the BudgetStats constructor does no filtering, so
	// this equals len(window) at construction time).
	SampleCount int
}

// BudgetStats computes the observed statistics for a numeric-budget rule
// from the input window of float64 samples.
//
// Empty input (`len(window) == 0`) returns a zero-valued Budget with
// SampleCount = 0. Empty windows are a valid "no observations yet"
// state, parallel to zero-opportunity in Wilson — neither a panic nor
// an error condition.
//
// Single-element input returns a Budget where P99, P95, Median, and Max
// all equal that single value with SampleCount = 1.
//
// General case: percentiles use the nearest-rank method per Wikipedia
// (https://en.wikipedia.org/wiki/Percentile#The_nearest-rank_method) on
// a sorted copy of the window. For percentile p in (0, 100], the rank
// is ceil(p * n / 100); the value at that 1-indexed position in the
// sorted slice is returned. Nearest-rank is deterministic, requires no
// interpolation, and is exact for integer-valued samples — properties
// that matter for cross-deployment audit parity. The sort runs once and
// the four percentile reads are constant-time lookups, so this is
// O(n log n) total with no extra allocations beyond the sorted copy.
//
// The caller's slice is NOT mutated: BudgetStats works on a clone made
// via slices.Clone.
//
// Non-finite samples (NaN, +Inf, -Inf) are filtered out before
// computing statistics so the inference path cannot persist nonsensical
// budgets that downstream JSON encoding or enforcement comparisons
// might handle inconsistently. SampleCount reflects the count after
// filtering. A window that contains only non-finite values returns a
// zero-valued Budget (same shape as an empty input window).
func BudgetStats(window []float64) Budget {
	if len(window) == 0 {
		return Budget{}
	}

	sorted := make([]float64, 0, len(window))
	for _, v := range window {
		if math.IsNaN(v) || math.IsInf(v, 0) {
			continue
		}
		sorted = append(sorted, v)
	}
	n := len(sorted)
	if n == 0 {
		return Budget{}
	}
	slices.Sort(sorted)

	return Budget{
		P99:         nearestRank(sorted, 99),
		P95:         nearestRank(sorted, 95),
		Median:      nearestRank(sorted, 50),
		Max:         sorted[n-1],
		SampleCount: n,
	}
}

// nearestRank returns the value at the nearest-rank percentile p of a
// sorted (ascending) slice. p is in (0, 100]; the slice is non-empty.
//
// Formula: rank = ceil(p * n / 100), 1-indexed. Implemented with integer
// arithmetic — `(p*n + 99) / 100` — to keep results deterministic
// without dragging math.Ceil and float-rounding quirks into the path.
// The rank is clamped into [1, n] so a percentile
// of 100 (which would otherwise round to n+1 on n-element slices via
// some formulations) maps cleanly to the maximum.
func nearestRank(sorted []float64, p int) float64 {
	n := len(sorted)
	rank := (p*n + 99) / 100 // integer ceil of p*n/100
	if rank < 1 {
		rank = 1
	}
	if rank > n {
		rank = n
	}
	return sorted[rank-1]
}

// EnforcedValue returns the enforced ceiling for the budget under the
// given multiplicative headroom: `enforced = b.P99 * (1 + headroom)`,
// clamped to a non-negative result.
//
// Headroom semantics:
//   - Positive headroom widens the ceiling (the common case; pass
//     DefaultHeadroomRate or DefaultHeadroomSize).
//   - Zero headroom returns P99 itself (no widening).
//   - Negative headroom in the half-open range [-1, 0) shrinks the
//     ceiling, supported so a caller that wants a tighter-than-observed
//     ceiling can express it without a separate code path. The shrunk
//     value remains non-negative because P99 is non-negative.
//   - Negative headroom below -1 would otherwise produce a nonsensical
//     negative ceiling. The result is clamped to 0 so a future caller
//     bug or bad plumbing cannot push a negative ceiling into an
//     enforcement path. This is the fail-closed-but-valid contract: a
//     budget of 0 denies everything (which any reasonable enforcer
//     handles), whereas a negative budget could trigger
//     undefined-behavior cascades depending on downstream comparisons.
//
// An empty Budget (SampleCount == 0, all percentiles zero) yields 0
// for any headroom; no special branch needed because the formula
// already produces 0 from a zero P99.
//
// Pure: no I/O, no allocations beyond the float result.
func (b Budget) EnforcedValue(headroom float64) float64 {
	v := b.P99 * (1 + headroom)
	if v < 0 {
		return 0
	}
	return v
}

// ThinSample reports whether SampleCount is below minEvents. The review
// UX renders a "thin-sample" badge on a numeric-budget rule when this
// returns true, signaling to the operator that the persisted statistics
// were computed from a window that did not clear the rule's exposure
// floor.
//
// Strictly less-than: SampleCount == minEvents returns false (the floor
// was just barely cleared, but it was cleared). This matches FloorsPass,
// which uses observed >= floors.MinEvents.
func (b Budget) ThinSample(minEvents int) bool {
	return b.SampleCount < minEvents
}
