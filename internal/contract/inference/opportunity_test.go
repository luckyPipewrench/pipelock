// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package inference

import (
	"errors"
	"testing"
)

// Synthetic context values used across happy-path and zero-count tables.
// Each value is distinct and non-trivial so a wrong field selection in
// Denominator surfaces as an obviously wrong number.
const (
	testHTTPSessions         = 100
	testHostSessions         = 42
	testHostPathFamilyEvents = 17
	testToolEndpointCalls    = 9
	testSourceActionWindows  = 3
)

// TestOpportunityLevel_String pins the wire-form label for every defined
// level (and the invalid-default case). These strings ship in error
// messages and metrics labels — renaming is a downstream-breaking change.
func TestOpportunityLevel_String(t *testing.T) {
	t.Parallel()

	cases := []struct {
		level OpportunityLevel
		want  string
	}{
		{OpportunityLevelUnknown, "unknown"},
		{OpportunityLevelHostStability, "host_stability"},
		{OpportunityLevelPathFamilyStability, "path_family_stability"},
		{OpportunityLevelMethodStability, "method_stability"},
		{OpportunityLevelHeaderShape, "header_shape"},
		{OpportunityLevelArgSchema, "arg_schema"},
		{OpportunityLevelSequenceNGram, "sequence_ngram"},
		// Out-of-range int casts must hit the default branch and return
		// the stable "invalid" label so metrics/logs never silently swap
		// a typo'd int for a real label.
		{OpportunityLevel(99), "invalid"},
		{OpportunityLevel(-1), "invalid"},
	}

	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			t.Parallel()
			if got := tc.level.String(); got != tc.want {
				t.Fatalf("OpportunityLevel(%d).String() = %q, want %q", tc.level, got, tc.want)
			}
		})
	}
}

// TestOpportunityLevel_Valid confirms every defined non-Unknown level is
// Valid, and that Unknown / out-of-range casts are not. This is the
// boundary callers and config validators rely on.
func TestOpportunityLevel_Valid(t *testing.T) {
	t.Parallel()

	validLevels := []OpportunityLevel{
		OpportunityLevelHostStability,
		OpportunityLevelPathFamilyStability,
		OpportunityLevelMethodStability,
		OpportunityLevelHeaderShape,
		OpportunityLevelArgSchema,
		OpportunityLevelSequenceNGram,
	}
	for _, l := range validLevels {
		l := l
		t.Run("valid_"+l.String(), func(t *testing.T) {
			t.Parallel()
			if !l.Valid() {
				t.Fatalf("%s: Valid() = false, want true", l)
			}
		})
	}

	invalidLevels := []OpportunityLevel{
		OpportunityLevelUnknown,
		OpportunityLevel(-1),
		OpportunityLevel(99),
		// One past the last defined level — exercises the upper-bound
		// guard in Valid() without exporting the sentinel.
		OpportunityLevel(int(OpportunityLevelSequenceNGram) + 1),
	}
	for _, l := range invalidLevels {
		l := l
		t.Run("invalid_"+l.String(), func(t *testing.T) {
			t.Parallel()
			if l.Valid() {
				t.Fatalf("OpportunityLevel(%d): Valid() = true, want false", l)
			}
		})
	}
}

// fullContext returns a context with every field populated to a distinct
// non-zero value. Used to verify the right field is selected for each
// level in the happy path.
func fullContext() OpportunityContext {
	return OpportunityContext{
		HTTPSessions:         testHTTPSessions,
		HostSessions:         testHostSessions,
		HostPathFamilyEvents: testHostPathFamilyEvents,
		ToolEndpointCalls:    testToolEndpointCalls,
		SourceActionWindows:  testSourceActionWindows,
	}
}

// TestDenominator_HappyPath asserts each defined non-Unknown level pulls
// the correct field from a fully-populated context. HeaderShape and
// ArgSchema deliberately return the same value (testToolEndpointCalls);
// this row is the explicit, test-enforced documentation that they share
// a denominator today.
func TestDenominator_HappyPath(t *testing.T) {
	t.Parallel()

	ctx := fullContext()
	cases := []struct {
		level OpportunityLevel
		want  int
	}{
		{OpportunityLevelHostStability, testHTTPSessions},
		{OpportunityLevelPathFamilyStability, testHostSessions},
		{OpportunityLevelMethodStability, testHostPathFamilyEvents},
		{OpportunityLevelHeaderShape, testToolEndpointCalls},
		{OpportunityLevelArgSchema, testToolEndpointCalls},
		{OpportunityLevelSequenceNGram, testSourceActionWindows},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.level.String(), func(t *testing.T) {
			t.Parallel()
			n, err := Denominator(tc.level, ctx)
			if err != nil {
				t.Fatalf("Denominator(%s) returned error: %v", tc.level, err)
			}
			if n != tc.want {
				t.Fatalf("Denominator(%s) = %d, want %d", tc.level, n, tc.want)
			}
		})
	}
}

// TestDenominator_RejectsUnknownLevel asserts the zero value and any
// out-of-range int both return ErrUnknownOpportunityLevel. The error MUST
// be detectable via errors.Is, never raw equality.
func TestDenominator_RejectsUnknownLevel(t *testing.T) {
	t.Parallel()

	ctx := fullContext()
	cases := []struct {
		name  string
		level OpportunityLevel
	}{
		{"zero_value", OpportunityLevelUnknown},
		{"out_of_range_high", OpportunityLevel(99)},
		{"out_of_range_negative", OpportunityLevel(-1)},
		// Exactly one past the last defined level — exercises the
		// default branch boundary without leaking the sentinel.
		{
			"one_past_last",
			OpportunityLevel(int(OpportunityLevelSequenceNGram) + 1),
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			n, err := Denominator(tc.level, ctx)
			if n != 0 {
				t.Fatalf("Denominator(%s) returned n=%d, want 0", tc.level, n)
			}
			if err == nil {
				t.Fatalf("Denominator(%s) returned nil error, want ErrUnknownOpportunityLevel", tc.level)
			}
			if !errors.Is(err, ErrUnknownOpportunityLevel) {
				t.Fatalf("Denominator(%s) error = %v, want errors.Is(ErrUnknownOpportunityLevel)", tc.level, err)
			}
		})
	}
}

// TestDenominator_RejectsNegativeCount asserts that any negative source
// count returns wrapped ErrNegativeOpportunityCount with n=0, regardless
// of which level reads it. errors.Is must still match through the
// fmt.Errorf("%w") wrapping.
func TestDenominator_RejectsNegativeCount(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		level OpportunityLevel
		mut   func(*OpportunityContext)
	}{
		{
			"host_stability_negative",
			OpportunityLevelHostStability,
			func(c *OpportunityContext) { c.HTTPSessions = -1 },
		},
		{
			"path_family_stability_negative",
			OpportunityLevelPathFamilyStability,
			func(c *OpportunityContext) { c.HostSessions = -1 },
		},
		{
			"method_stability_negative",
			OpportunityLevelMethodStability,
			func(c *OpportunityContext) { c.HostPathFamilyEvents = -1 },
		},
		{
			"header_shape_negative",
			OpportunityLevelHeaderShape,
			func(c *OpportunityContext) { c.ToolEndpointCalls = -1 },
		},
		{
			"arg_schema_negative",
			OpportunityLevelArgSchema,
			func(c *OpportunityContext) { c.ToolEndpointCalls = -1 },
		},
		{
			"sequence_ngram_negative",
			OpportunityLevelSequenceNGram,
			func(c *OpportunityContext) { c.SourceActionWindows = -1 },
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := fullContext()
			tc.mut(&ctx)

			n, err := Denominator(tc.level, ctx)
			if n != 0 {
				t.Fatalf("Denominator(%s) returned n=%d, want 0", tc.level, n)
			}
			if err == nil {
				t.Fatalf("Denominator(%s) returned nil error, want ErrNegativeOpportunityCount", tc.level)
			}
			if !errors.Is(err, ErrNegativeOpportunityCount) {
				t.Fatalf("Denominator(%s) error = %v, want errors.Is(ErrNegativeOpportunityCount)", tc.level, err)
			}
			// The wrapped error MUST surface level + count for audit;
			// confirm both substrings are present in the message.
			msg := err.Error()
			if !contains(msg, "level="+tc.level.String()) {
				t.Fatalf("Denominator(%s) error = %q, want it to contain level=%s", tc.level, msg, tc.level)
			}
			if !contains(msg, "count=-1") {
				t.Fatalf("Denominator(%s) error = %q, want it to contain count=-1", tc.level, msg)
			}
		})
	}
}

// TestDenominator_ZeroCountAllowed asserts that an opportunity count of
// zero is a valid state, not an error. The downstream floor gates turn
// zero into a "not enough evidence yet" classification; Denominator just
// reports the count.
func TestDenominator_ZeroCountAllowed(t *testing.T) {
	t.Parallel()

	// Empty context: every field is the zero int, so every level reads 0.
	zeroCtx := OpportunityContext{}

	levels := []OpportunityLevel{
		OpportunityLevelHostStability,
		OpportunityLevelPathFamilyStability,
		OpportunityLevelMethodStability,
		OpportunityLevelHeaderShape,
		OpportunityLevelArgSchema,
		OpportunityLevelSequenceNGram,
	}

	for _, l := range levels {
		l := l
		t.Run(l.String(), func(t *testing.T) {
			t.Parallel()
			n, err := Denominator(l, zeroCtx)
			if err != nil {
				t.Fatalf("Denominator(%s, zero) returned error: %v, want nil", l, err)
			}
			if n != 0 {
				t.Fatalf("Denominator(%s, zero) = %d, want 0", l, n)
			}
		})
	}
}

// contains is a tiny strings.Contains-equivalent so the test file does
// not pull in the strings package just for one helper. Keeps the test
// file's import block minimal and audit-friendly.
func contains(haystack, needle string) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
