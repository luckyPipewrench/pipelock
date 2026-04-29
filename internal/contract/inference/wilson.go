// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package inference implements the contract-compile inference engine:
// Wilson lower-bound confidence, conditional opportunity denominators,
// exposure-floor gates, and numeric-budget statistics. Pure functions —
// no I/O, no transports, no logging. Inputs are recorder.Entry events that
// have already been classified by internal/contract/privacy.
package inference

import "math"

// DefaultWilsonAlpha is the canonical alpha (1 - confidence level) for the
// contract-compile inference engine. Production callers (Classify and the
// higher-level glue) MUST go through this constant rather than reading a
// per-deployment config field. Wilson confidence is part of the statistical
// contract; making it deployment-configurable would let two installs infer
// different classifications from identical recorder data, which is audit
// drift, not flexibility.
const DefaultWilsonAlpha = 0.05

// wilsonZ95 is the inverse-normal-CDF value for 1 - alpha/2 = 0.975 (i.e.
// alpha = 0.05). Hardcoded so the production Wilson path stays
// deterministic for a given input on supported Go builds — math.Erfinv
// is not invoked at runtime, so its precision cannot drift this value.
const wilsonZ95 = 1.959963984540054

// WilsonLowerBound returns the Wilson score interval lower bound for
// `observed` successes out of `opportunity` trials at confidence level
// 1 - alpha. The Wilson interval is the canonical reference for binomial
// proportion confidence intervals on small or skewed samples; see
// Newcombe (1998), "Two-sided confidence intervals for the single
// proportion: comparison of seven methods", Statistics in Medicine 17,
// 857-872.
//
// Closed form:
//
//	z      = invNormalCDF(1 - alpha/2)
//	p_hat  = observed / opportunity
//	denom  = 1 + z^2 / n
//	center = (p_hat + z^2 / (2n)) / denom
//	margin = (z / denom) * sqrt((p_hat * (1 - p_hat) + z^2 / (4n)) / n)
//	lower  = center - margin
//
// Defensive returns of 0.0 (never panic, never NaN) for these cases:
//   - opportunity == 0 (no trials → no evidence → floor at 0)
//   - observed < 0 (programmer error, but still safe)
//   - observed > opportunity (programmer error, but still safe)
//   - alpha out of (0, 1) (degenerate confidence level)
//
// Pure: no I/O, no logging, no allocations beyond the float result.
func WilsonLowerBound(observed, opportunity int, alpha float64) float64 {
	if opportunity <= 0 || observed < 0 || observed > opportunity {
		return 0.0
	}
	if alpha <= 0 || alpha >= 1 {
		return 0.0
	}
	// Wilson formula guarantees lower ∈ [0, 1] for valid inputs (validated
	// above): when k=0, center == margin exactly, so lower = 0; for any
	// k > 0, lower > 0. No post-formula clamp needed; if a future change
	// to the formula breaks that guarantee, the test pack catches it.
	center, margin := wilsonCenterMargin(observed, opportunity, alpha)
	return center - margin
}

// WilsonUpperBound returns the Wilson score interval upper bound for
// `observed` successes out of `opportunity` trials at confidence level
// 1 - alpha. Required by the contract test pack to prove complementary
// symmetry: WilsonLowerBound(n-k, n, a) ≈ 1 - WilsonUpperBound(k, n, a).
//
// Same defensive edge cases as WilsonLowerBound.
func WilsonUpperBound(observed, opportunity int, alpha float64) float64 {
	if opportunity <= 0 || observed < 0 || observed > opportunity {
		return 0.0
	}
	if alpha <= 0 || alpha >= 1 {
		return 0.0
	}
	// Wilson formula guarantees upper ∈ [0, 1] for valid inputs: when k=n,
	// center + margin = 1 exactly. No post-formula clamp needed.
	center, margin := wilsonCenterMargin(observed, opportunity, alpha)
	return center + margin
}

// wilsonCenterMargin returns the Wilson center and margin for valid
// (observed, opportunity, alpha) inputs. Callers must validate edge cases
// before invoking; this helper assumes opportunity > 0 and 0 < alpha < 1.
func wilsonCenterMargin(observed, opportunity int, alpha float64) (center, margin float64) {
	n := float64(opportunity)
	k := float64(observed)

	z := wilsonZ(alpha)
	z2 := z * z

	pHat := k / n
	denom := 1 + z2/n
	center = (pHat + z2/(2*n)) / denom
	margin = (z / denom) * math.Sqrt((pHat*(1-pHat)+z2/(4*n))/n)
	return center, margin
}

// wilsonZ returns the inverse normal CDF value at 1 - alpha/2. The
// alpha = 0.05 fast path returns the locked wilsonZ95 constant so the
// production code path returns a fixed value for the default alpha.
// Other alphas use the Beasley-Springer-Moro rational approximation,
// which is accurate to roughly 1e-7 across the tail and has no math/big
// or third-party deps.
func wilsonZ(alpha float64) float64 {
	if alpha == DefaultWilsonAlpha {
		return wilsonZ95
	}
	return invNormalCDF(1 - alpha/2)
}

// invNormalCDF approximates the inverse standard-normal CDF at p ∈ (0, 1)
// using the Beasley-Springer-Moro rational approximation (Moro 1995). The
// approximation is accurate to ~1e-7 in the body and tails, which is well
// within the test tolerance of 3 decimal places for any non-default alpha
// the engine would realistically encounter.
//
// Caller validates 0 < alpha < 1 before reaching this path, but very
// small alpha (e.g. 1e-16) can round 1 - alpha/2 to exactly 1.0 in
// IEEE-754 double, which would otherwise drive the rational
// approximation toward +Inf. The clamp pulls p back into a safely
// representable open interval (1e-15, 1 - 1e-15) so the function never
// returns NaN or Inf even for degenerate alpha. The supported alpha
// range for accurate output is roughly [1e-12, 1 - 1e-12]; outside that
// band the result remains finite but accuracy degrades.
func invNormalCDF(p float64) float64 {
	if p < 1e-15 {
		p = 1e-15
	} else if p > 1-1e-15 {
		p = 1 - 1e-15
	}
	// Beasley-Springer central region coefficients.
	a := [...]float64{
		-3.969683028665376e+01,
		2.209460984245205e+02,
		-2.759285104469687e+02,
		1.383577518672690e+02,
		-3.066479806614716e+01,
		2.506628277459239e+00,
	}
	b := [...]float64{
		-5.447609879822406e+01,
		1.615858368580409e+02,
		-1.556989798598866e+02,
		6.680131188771972e+01,
		-1.328068155288572e+01,
	}
	// Moro tail-region coefficients.
	c := [...]float64{
		-7.784894002430293e-03,
		-3.223964580411365e-01,
		-2.400758277161838e+00,
		-2.549732539343734e+00,
		4.374664141464968e+00,
		2.938163982698783e+00,
	}
	d := [...]float64{
		7.784695709041462e-03,
		3.224671290700398e-01,
		2.445134137142996e+00,
		3.754408661907416e+00,
	}

	const pLow = 0.02425
	const pHigh = 1 - pLow

	switch {
	case p < pLow:
		// Lower tail.
		q := math.Sqrt(-2 * math.Log(p))
		return (((((c[0]*q+c[1])*q+c[2])*q+c[3])*q+c[4])*q + c[5]) /
			((((d[0]*q+d[1])*q+d[2])*q+d[3])*q + 1)
	case p <= pHigh:
		// Central region.
		q := p - 0.5
		r := q * q
		return (((((a[0]*r+a[1])*r+a[2])*r+a[3])*r+a[4])*r + a[5]) * q /
			(((((b[0]*r+b[1])*r+b[2])*r+b[3])*r+b[4])*r + 1)
	default:
		// Upper tail.
		q := math.Sqrt(-2 * math.Log(1-p))
		return -(((((c[0]*q+c[1])*q+c[2])*q+c[3])*q+c[4])*q + c[5]) /
			((((d[0]*q+d[1])*q+d[2])*q+d[3])*q + 1)
	}
}
