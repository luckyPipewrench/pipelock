// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package normalize

import (
	"errors"
	"strings"
	"testing"
)

const (
	testAlgorithm    = "frequency_weighted_entropy_v1"
	testHost         = "api.example.com"
	testMethod       = "GET"
	testParentPrefix = "/v1"
)

// validEvidence returns a fully populated NormalizationEvidence that
// passes Validate. Tests mutate one field to assert each invariant.
func validEvidence() NormalizationEvidence {
	return NormalizationEvidence{
		Algorithm: testAlgorithm,
		Bucket: Bucket{
			Host:         testHost,
			Method:       testMethod,
			ParentPrefix: testParentPrefix,
		},
		CollapsedSegments: []CollapsedSegment{
			{
				Index:          3,
				DistinctValues: 47,
				EventCount:     211,
				Entropy:        4.92,
				Reason:         ReasonHighEntropyIdentifierSegment,
			},
		},
		RetainedSegments: []RetainedSegment{
			{
				Index:  2,
				Value:  "users",
				Reason: ReasonReservedSegment,
			},
		},
	}
}

func TestNormalizationEvidence_Validate_HappyPath(t *testing.T) {
	t.Parallel()

	if err := validEvidence().Validate(); err != nil {
		t.Fatalf("validEvidence().Validate() = %v, want nil", err)
	}
}

func TestNormalizationEvidence_Validate_RejectsEmptyAlgorithm(t *testing.T) {
	t.Parallel()

	e := validEvidence()
	e.Algorithm = ""
	err := e.Validate()
	if !errors.Is(err, ErrInvalidNormalizationEvidence) {
		t.Fatalf("Validate() = %v, want wrapped ErrInvalidNormalizationEvidence", err)
	}
	if !strings.Contains(err.Error(), "algorithm") {
		t.Fatalf("error message = %q, want field=algorithm reference", err.Error())
	}
}

func TestNormalizationEvidence_Validate_RejectsEmptyBucketHost(t *testing.T) {
	t.Parallel()

	e := validEvidence()
	e.Bucket.Host = ""
	err := e.Validate()
	if !errors.Is(err, ErrInvalidNormalizationEvidence) {
		t.Fatalf("Validate() = %v, want wrapped ErrInvalidNormalizationEvidence", err)
	}
	if !strings.Contains(err.Error(), "bucket.host") {
		t.Fatalf("error message = %q, want field=bucket.host reference", err.Error())
	}
}

func TestNormalizationEvidence_Validate_RejectsEmptyBucketMethod(t *testing.T) {
	t.Parallel()

	e := validEvidence()
	e.Bucket.Method = ""
	err := e.Validate()
	if !errors.Is(err, ErrInvalidNormalizationEvidence) {
		t.Fatalf("Validate() = %v, want wrapped ErrInvalidNormalizationEvidence", err)
	}
	if !strings.Contains(err.Error(), "bucket.method") {
		t.Fatalf("error message = %q, want field=bucket.method reference", err.Error())
	}
}

func TestNormalizationEvidence_Validate_AcceptsEmptyParentPrefix(t *testing.T) {
	t.Parallel()

	e := validEvidence()
	e.Bucket.ParentPrefix = ""
	if err := e.Validate(); err != nil {
		t.Fatalf("Validate() with empty ParentPrefix = %v, want nil (root-level paths are valid)", err)
	}
}

func TestNormalizationEvidence_Validate_RejectsBadCollapsedSegment(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		mutate    func(*CollapsedSegment)
		fieldHint string
	}{
		{
			name:      "negative event count",
			mutate:    func(c *CollapsedSegment) { c.EventCount = -1 },
			fieldHint: "event_count",
		},
		{
			name:      "negative distinct values",
			mutate:    func(c *CollapsedSegment) { c.DistinctValues = -1 },
			fieldHint: "distinct_values",
		},
		{
			name:      "zero index",
			mutate:    func(c *CollapsedSegment) { c.Index = 0 },
			fieldHint: "index",
		},
		{
			name:      "negative index",
			mutate:    func(c *CollapsedSegment) { c.Index = -3 },
			fieldHint: "index",
		},
		{
			name:      "empty reason",
			mutate:    func(c *CollapsedSegment) { c.Reason = "" },
			fieldHint: "reason",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := validEvidence()
			tc.mutate(&e.CollapsedSegments[0])
			err := e.Validate()
			if !errors.Is(err, ErrInvalidNormalizationEvidence) {
				t.Fatalf("Validate() = %v, want wrapped ErrInvalidNormalizationEvidence", err)
			}
			if !strings.Contains(err.Error(), tc.fieldHint) {
				t.Fatalf("error message = %q, want %q reference", err.Error(), tc.fieldHint)
			}
			if !strings.Contains(err.Error(), "collapsed_segments") {
				t.Fatalf("error message = %q, want collapsed_segments path", err.Error())
			}
		})
	}
}

func TestNormalizationEvidence_Validate_RejectsBadRetainedSegment(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		mutate    func(*RetainedSegment)
		fieldHint string
	}{
		{
			name:      "zero index",
			mutate:    func(r *RetainedSegment) { r.Index = 0 },
			fieldHint: "index",
		},
		{
			name:      "negative index",
			mutate:    func(r *RetainedSegment) { r.Index = -1 },
			fieldHint: "index",
		},
		{
			name:      "empty reason",
			mutate:    func(r *RetainedSegment) { r.Reason = "" },
			fieldHint: "reason",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := validEvidence()
			tc.mutate(&e.RetainedSegments[0])
			err := e.Validate()
			if !errors.Is(err, ErrInvalidNormalizationEvidence) {
				t.Fatalf("Validate() = %v, want wrapped ErrInvalidNormalizationEvidence", err)
			}
			if !strings.Contains(err.Error(), tc.fieldHint) {
				t.Fatalf("error message = %q, want %q reference", err.Error(), tc.fieldHint)
			}
			if !strings.Contains(err.Error(), "retained_segments") {
				t.Fatalf("error message = %q, want retained_segments path", err.Error())
			}
		})
	}
}

func TestNormalizationEvidence_Validate_AcceptsAllSegmentLiterals(t *testing.T) {
	t.Parallel()

	// Rare but valid: a rule on a host where every path was already a
	// constant literal so no collapse decision was reached and no
	// retain decision was emitted either. The Validate contract
	// permits this.
	e := NormalizationEvidence{
		Algorithm: testAlgorithm,
		Bucket: Bucket{
			Host:         testHost,
			Method:       testMethod,
			ParentPrefix: "",
		},
	}
	if err := e.Validate(); err != nil {
		t.Fatalf("Validate() with empty Collapsed and Retained = %v, want nil", err)
	}
}

func TestReasonConstants_WireForms(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		got  string
		want string
	}{
		{"ReasonHighEntropyIdentifierSegment", ReasonHighEntropyIdentifierSegment, "high_entropy_identifier_segment"},
		{"ReasonLowEntropyLiteralSegment", ReasonLowEntropyLiteralSegment, "low_entropy_literal_segment"},
		{"ReasonInsufficientEvents", ReasonInsufficientEvents, "insufficient_events"},
		{"ReasonInsufficientDistinct", ReasonInsufficientDistinct, "insufficient_distinct_values"},
		{"ReasonReservedSegment", ReasonReservedSegment, "reserved_segment"},
		{"ReasonNoMergeRule", ReasonNoMergeRule, "no_merge_rule_high_risk_sibling"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if tc.got != tc.want {
				t.Fatalf("%s = %q, want %q (drift guard: don't change the wire form without bumping the algorithm version)", tc.name, tc.got, tc.want)
			}
		})
	}
}
