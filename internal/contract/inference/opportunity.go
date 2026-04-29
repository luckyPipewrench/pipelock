// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package inference

import (
	"errors"
	"fmt"
)

// OpportunityLevel identifies which inference rule the engine is evaluating.
// It selects the matching denominator field from an OpportunityContext via
// Denominator. Each rule level has a different "what counts as an opportunity"
// definition (sessions vs events vs calls vs windows), and the picker turns
// that abstract row from the design's Conditional Opportunity Hierarchy table
// into a concrete integer to feed Wilson lower-bound math.
//
// The zero value is OpportunityLevelUnknown, which is intentionally invalid:
// a caller that forgets to set the level cannot accidentally pick the first
// real level. Denominator returns ErrUnknownOpportunityLevel for the zero
// value (and any unrecognized int).
//
// HeaderShape and ArgSchema are split into separate enum members even though
// they share a denominator field today (ToolEndpointCalls). This lets tests
// distinguish them in error messages and metrics labels and lets a future
// refinement give them different counts without changing the API.
type OpportunityLevel int

const (
	// OpportunityLevelUnknown is the zero value. It is invalid by design so
	// uninitialized callers cannot silently pick the first real level. Any
	// path that reaches Denominator with this level returns
	// ErrUnknownOpportunityLevel.
	OpportunityLevelUnknown OpportunityLevel = iota

	// OpportunityLevelHostStability evaluates how stable a host signal is
	// across the operator's traffic. Denominator: HTTPSessions (sessions
	// where any outbound HTTP was observed).
	OpportunityLevelHostStability

	// OpportunityLevelPathFamilyStability evaluates how stable a path-family
	// signal is per host. Denominator: HostSessions (sessions where that
	// host was observed).
	OpportunityLevelPathFamilyStability

	// OpportunityLevelMethodStability evaluates how stable an HTTP method
	// signal is per host/path-family. Denominator: HostPathFamilyEvents
	// (events or sessions where that host/path-family was observed).
	OpportunityLevelMethodStability

	// OpportunityLevelHeaderShape evaluates how stable a header-shape
	// signal is per tool/endpoint. Denominator: ToolEndpointCalls (calls
	// where that tool or endpoint was observed). Shares its denominator
	// field with OpportunityLevelArgSchema today; intentionally split so
	// tests, metrics, and future divergence stay clean.
	OpportunityLevelHeaderShape

	// OpportunityLevelArgSchema evaluates how stable an argument-schema
	// signal is per tool/endpoint. Denominator: ToolEndpointCalls. Shares
	// its denominator field with OpportunityLevelHeaderShape today; see
	// the note on HeaderShape.
	OpportunityLevelArgSchema

	// OpportunityLevelSequenceNGram evaluates how stable a tool-call
	// sequence (n-gram) signal is per source action. Denominator:
	// SourceActionWindows (windows or sessions where the source action
	// occurred).
	OpportunityLevelSequenceNGram

	// opportunityLevelSentinel is the exclusive upper bound used by
	// Valid() and tests to detect out-of-range int casts. It is unexported
	// so external callers cannot depend on the count of levels.
	opportunityLevelSentinel
)

// String returns the lowercase snake_case wire-form label for the level.
// Used in error messages, metrics labels, and structured logs. Stable across
// versions; renaming a label is a breaking change for downstream dashboards
// and audit pipelines.
func (l OpportunityLevel) String() string {
	switch l {
	case OpportunityLevelUnknown:
		return "unknown"
	case OpportunityLevelHostStability:
		return "host_stability"
	case OpportunityLevelPathFamilyStability:
		return "path_family_stability"
	case OpportunityLevelMethodStability:
		return "method_stability"
	case OpportunityLevelHeaderShape:
		return "header_shape"
	case OpportunityLevelArgSchema:
		return "arg_schema"
	case OpportunityLevelSequenceNGram:
		return "sequence_ngram"
	default:
		return "invalid"
	}
}

// Valid reports whether l is a defined non-Unknown opportunity level. Use
// this in config validators and at the entry to any function that needs a
// usable level. OpportunityLevelUnknown returns false; out-of-range int
// casts return false.
func (l OpportunityLevel) Valid() bool {
	return l > OpportunityLevelUnknown && l < opportunityLevelSentinel
}

// OpportunityContext holds the precomputed counts the inference engine needs
// to pick a denominator for any rule level. Each field documents which level
// reads it. The upstream aggregator populates these counts from the recorder;
// Denominator just selects the right field and validates.
//
// Passed by value: the struct is small, value semantics make accidental
// mutation impossible, and the cost is below measurement noise.
type OpportunityContext struct {
	// HTTPSessions is the count of sessions in which any outbound HTTP was
	// observed. Read by OpportunityLevelHostStability.
	HTTPSessions int

	// HostSessions is the count of sessions in which the host under
	// evaluation was observed. Read by
	// OpportunityLevelPathFamilyStability.
	HostSessions int

	// HostPathFamilyEvents is the count of events (or sessions, per the
	// design's row) in which the host/path-family under evaluation was
	// observed. Read by OpportunityLevelMethodStability.
	HostPathFamilyEvents int

	// ToolEndpointCalls is the count of calls in which the tool or
	// endpoint under evaluation was observed. Read by both
	// OpportunityLevelHeaderShape and OpportunityLevelArgSchema; they
	// share this field today.
	ToolEndpointCalls int

	// SourceActionWindows is the count of windows (or sessions, per the
	// design's row) in which the source action of the n-gram occurred.
	// Read by OpportunityLevelSequenceNGram.
	SourceActionWindows int
}

// Sentinel errors for Denominator. Callers MUST compare with errors.Is, not
// raw == comparison; Denominator wraps ErrNegativeOpportunityCount with
// fmt.Errorf("%w") so context (level + count) survives without breaking
// errors.Is.
var (
	// ErrUnknownOpportunityLevel is returned by Denominator when the
	// supplied level is OpportunityLevelUnknown or an unrecognized int
	// (e.g., out-of-range cast). Callers can detect this with
	// errors.Is(err, ErrUnknownOpportunityLevel).
	ErrUnknownOpportunityLevel = errors.New("inference: unknown opportunity level")

	// ErrNegativeOpportunityCount is returned by Denominator when the
	// selected count is negative. Negative counts indicate an aggregator
	// bug, not adversarial input, but the inference engine never panics
	// on runtime input, so we return the error and let the caller decide.
	// Callers can detect this with
	// errors.Is(err, ErrNegativeOpportunityCount).
	ErrNegativeOpportunityCount = errors.New("inference: negative opportunity count")
)

// Denominator returns the opportunity count that pairs with level for
// Wilson-lower-bound math. The function is pure: no I/O, no allocations
// beyond the wrapped-error case, no panics ever.
//
// Behavior:
//   - Defined non-Unknown levels: returns the matching ctx field and nil.
//   - OpportunityLevelUnknown or any unrecognized int: returns
//     (0, ErrUnknownOpportunityLevel).
//   - Negative selected count: returns (0, wrapped
//     ErrNegativeOpportunityCount with level + count context).
//   - Zero selected count: returns (0, nil). Zero is a valid "no
//     opportunity yet" state; the downstream floor gates handle the
//     implication.
func Denominator(level OpportunityLevel, ctx OpportunityContext) (int, error) {
	var count int
	switch level {
	case OpportunityLevelHostStability:
		count = ctx.HTTPSessions
	case OpportunityLevelPathFamilyStability:
		count = ctx.HostSessions
	case OpportunityLevelMethodStability:
		count = ctx.HostPathFamilyEvents
	case OpportunityLevelHeaderShape, OpportunityLevelArgSchema:
		count = ctx.ToolEndpointCalls
	case OpportunityLevelSequenceNGram:
		count = ctx.SourceActionWindows
	case OpportunityLevelUnknown:
		return 0, ErrUnknownOpportunityLevel
	default:
		return 0, ErrUnknownOpportunityLevel
	}
	if count < 0 {
		return 0, fmt.Errorf("%w (level=%s, count=%d)", ErrNegativeOpportunityCount, level, count)
	}
	return count, nil
}
