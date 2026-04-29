// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package inference

import (
	"errors"
	"fmt"
)

// TauStable is the Wilson lower-bound threshold a rule must clear (in
// addition to the exposure floors) to be classified ConfidenceStable.
//
// Like DefaultWilsonAlpha, this constant is part of the statistical
// contract and is NOT exposed as a config field. Making the threshold
// deployment-configurable would let two installs infer different
// classifications from identical recorder data, which is audit drift
// rather than flexibility. The value comes from the contract inference
// engine design baseline.
const TauStable = 0.85

// TauBrittle is the Wilson lower-bound threshold a rule must clear (in
// addition to the exposure floors) to be classified ConfidenceBrittle
// rather than ConfidenceNeverConfirmed.
//
// Same contract logic as TauStable: locked, not deployment-configurable,
// sourced from the design baseline.
const TauBrittle = 0.50

// Default exposure floors. A rule cannot be classified ConfidenceStable
// or ConfidenceBrittle until ALL three floors are cleared, regardless of
// how high the Wilson lower bound climbs. Floors are AND-composed with
// Wilson — never OR — so a low-volume signal cannot promote itself to
// stable just by being lucky on a handful of trials. Values come from
// the contract inference engine design baseline.
const (
	// DefaultMinSessions is the minimum number of distinct sessions in
	// which a rule must have been observed before it can be classified
	// as anything other than never_confirmed.
	DefaultMinSessions = 5

	// DefaultMinEvents is the minimum number of observed events (the
	// "successes" numerator passed to Wilson) required before a rule
	// can be classified as anything other than never_confirmed.
	DefaultMinEvents = 20

	// DefaultMinWindows is the minimum number of distinct time windows
	// across which a rule must have been observed. Windows guard
	// against burst-only signals: 20 events in one minute should not
	// look the same as 20 events spread across 3 windows.
	DefaultMinWindows = 3
)

// Floors is the inference package's pure value type for exposure-floor
// configuration. The config package wraps it with its own struct + YAML
// tags in a follow-up step; this type intentionally has no tags so the
// inference layer stays free of YAML/JSON concerns.
type Floors struct {
	// MinSessions is the minimum number of distinct sessions a rule
	// must have been observed in before classification can leave
	// never_confirmed.
	MinSessions int

	// MinEvents is the minimum observed-event count (the numerator
	// passed to Wilson) before classification can leave never_confirmed.
	MinEvents int

	// MinWindows is the minimum number of distinct time windows the
	// rule must have been observed across.
	MinWindows int
}

// DefaultFloors returns a Floors value populated with the design's
// canonical defaults: MinSessions=5, MinEvents=20, MinWindows=3.
func DefaultFloors() Floors {
	return Floors{
		MinSessions: DefaultMinSessions,
		MinEvents:   DefaultMinEvents,
		MinWindows:  DefaultMinWindows,
	}
}

// Resolved returns a Floors with any zero-valued field replaced by the
// corresponding default. This implements the "config omitted → defaults"
// layer for a YAML-parsed Floors where missing fields decode as zero.
//
// Negative values pass through unchanged. Callers should run Validate
// first if they want to reject negatives; Resolved is purely about
// supplying defaults for missing fields, not sanitizing bad data.
func (f Floors) Resolved() Floors {
	out := f
	if out.MinSessions == 0 {
		out.MinSessions = DefaultMinSessions
	}
	if out.MinEvents == 0 {
		out.MinEvents = DefaultMinEvents
	}
	if out.MinWindows == 0 {
		out.MinWindows = DefaultMinWindows
	}
	return out
}

// ErrNegativeFloor is returned by Floors.Validate when any floor field
// is negative. Callers MUST compare with errors.Is, not raw == — Validate
// wraps the sentinel with fmt.Errorf("%w") so the field name and value
// reach the operator without breaking errors.Is chains.
//
// This sentinel is distinct from ErrNegativeOpportunityCount even though
// they share the "negative count" theme: ErrNegativeFloor is config
// validation (a deployment-configurable surface), while
// ErrNegativeOpportunityCount is runtime aggregator data. They surface
// different bugs and travel through different alert paths.
var ErrNegativeFloor = errors.New("inference: negative exposure floor")

// Validate returns nil if all floor fields are non-negative, otherwise
// it returns an error that wraps ErrNegativeFloor and names the offending
// field in the lowercase snake_case wire form so the operator can locate
// it in YAML.
//
// Only the first negative field is reported; once the operator fixes it
// and re-runs validation, any second negative field will surface in turn.
// Reporting all negatives in one error would require buffering and offers
// no help when the typical case is a single fat-fingered field.
func (f Floors) Validate() error {
	if f.MinSessions < 0 {
		return fmt.Errorf("%w (field=min_sessions, value=%d)", ErrNegativeFloor, f.MinSessions)
	}
	if f.MinEvents < 0 {
		return fmt.Errorf("%w (field=min_events, value=%d)", ErrNegativeFloor, f.MinEvents)
	}
	if f.MinWindows < 0 {
		return fmt.Errorf("%w (field=min_windows, value=%d)", ErrNegativeFloor, f.MinWindows)
	}
	return nil
}

// FloorsPass reports whether the observed (event), session, and window
// counts each meet or exceed the corresponding floor. Returns true only
// if all three thresholds clear; AND-composed by design.
//
// Negative input counts return false. Callers should validate inputs at
// the aggregator boundary, but FloorsPass is defensive — it never panics
// on bad input and never silently treats a negative count as passing.
func FloorsPass(observed, sessions, windows int, floors Floors) bool {
	if observed < 0 || sessions < 0 || windows < 0 {
		return false
	}
	return observed >= floors.MinEvents &&
		sessions >= floors.MinSessions &&
		windows >= floors.MinWindows
}

// Confidence is the verdict returned by Classify. The three levels map
// directly to the design's Wilson edge-case table: never_confirmed
// covers both "below TauBrittle" and "any floor failed"; brittle covers
// the [TauBrittle, TauStable) band when all floors clear; stable covers
// >= TauStable when all floors clear.
//
// The wire-form strings (lowercase snake_case) are used as metrics
// labels and audit-log values. Renaming a label is a downstream-breaking
// change.
type Confidence int

const (
	// ConfidenceNeverConfirmed means at least one of: a floor failed,
	// or the Wilson lower bound is below TauBrittle. The rule cannot
	// be trusted as a stable signal.
	ConfidenceNeverConfirmed Confidence = iota

	// ConfidenceBrittle means all floors cleared and the Wilson lower
	// bound is in [TauBrittle, TauStable). The rule has enough evidence
	// to consider but not enough to lock down on its own.
	ConfidenceBrittle

	// ConfidenceStable means all floors cleared and the Wilson lower
	// bound is at or above TauStable. The rule is safe to lock down.
	ConfidenceStable

	// confidenceSentinel is the exclusive upper bound used by tests to
	// detect out-of-range int casts. Unexported so external callers
	// cannot depend on the count of levels.
	confidenceSentinel
)

// String returns the lowercase snake_case wire-form label. Any value
// outside the defined range returns "unknown" so a stray int cast never
// silently produces a real label in metrics or logs.
func (c Confidence) String() string {
	switch c {
	case ConfidenceNeverConfirmed:
		return "never_confirmed"
	case ConfidenceBrittle:
		return "brittle"
	case ConfidenceStable:
		return "stable"
	default:
		return "unknown"
	}
}

// Classify composes the exposure-floor gate with the Wilson lower bound
// to produce a Confidence verdict. The composition is AND on floors and
// then a band test on Wilson:
//
//   - If any floor fails (or any input count is negative), the verdict
//     is ConfidenceNeverConfirmed regardless of how high Wilson climbs.
//     A high Wilson on a tiny sample is exactly the case the floors
//     exist to catch.
//   - Otherwise, the Wilson lower bound is computed at the locked
//     DefaultWilsonAlpha (0.05). Wilson >= TauStable yields
//     ConfidenceStable; Wilson >= TauBrittle yields ConfidenceBrittle;
//     anything below yields ConfidenceNeverConfirmed.
//
// Production callers go through this single entry point; the locked
// alpha is intentional. Tests that need to probe non-default alphas
// call WilsonLowerBound directly — Classify must not grow an alpha
// parameter or functional options for that case.
func Classify(observed, opportunity, sessions, windows int, floors Floors) Confidence {
	if !FloorsPass(observed, sessions, windows, floors) {
		return ConfidenceNeverConfirmed
	}
	wilson := WilsonLowerBound(observed, opportunity, DefaultWilsonAlpha)
	switch {
	case wilson >= TauStable:
		return ConfidenceStable
	case wilson >= TauBrittle:
		return ConfidenceBrittle
	default:
		return ConfidenceNeverConfirmed
	}
}
