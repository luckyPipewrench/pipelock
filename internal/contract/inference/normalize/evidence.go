// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package normalize

import (
	"errors"
	"fmt"
)

// NormalizationEvidence is the per-rule artifact emitted by the
// path-normalization layer. It is attached to every rule in the
// compiled contract YAML and to the signed JCS preimage so verifiers
// can reconstruct the bucket and reason about why a segment was
// collapsed or retained. The struct is the wire-form contract; the
// runtime proxy never reads it (consumed only at compile time and by
// the review UX).
type NormalizationEvidence struct {
	Algorithm         string             `json:"algorithm" yaml:"algorithm"`
	Bucket            Bucket             `json:"bucket" yaml:"bucket"`
	CollapsedSegments []CollapsedSegment `json:"collapsed_segments,omitempty" yaml:"collapsed_segments,omitempty"`
	RetainedSegments  []RetainedSegment  `json:"retained_segments,omitempty" yaml:"retained_segments,omitempty"`
}

// Bucket is the (host, method, parent-prefix) triple that scopes
// frequency-weighted entropy. Path-family inference is per-bucket;
// global path-family inference is forbidden by design (W7 in the
// W-list at the bottom of the design doc).
type Bucket struct {
	Host         string `json:"host" yaml:"host"`
	Method       string `json:"method" yaml:"method"`
	ParentPrefix string `json:"parent_prefix" yaml:"parent_prefix"`
}

// CollapsedSegment records a path segment position that the algorithm
// merged into a wildcard. It carries enough audit data for the review
// UX to render the decision: how many distinct values were observed,
// how many events those values covered, the entropy that triggered
// the collapse, and the reason code.
type CollapsedSegment struct {
	Index          int     `json:"index" yaml:"index"` // 1-indexed segment position
	DistinctValues int     `json:"distinct_values" yaml:"distinct_values"`
	EventCount     int     `json:"event_count" yaml:"event_count"`
	Entropy        float64 `json:"entropy" yaml:"entropy"`
	Reason         string  `json:"reason" yaml:"reason"` // collapse-reason wire form (see Reason* constants)
}

// RetainedSegment records a path segment position that the algorithm
// kept as a literal because it failed at least one collapse gate.
type RetainedSegment struct {
	Index  int    `json:"index" yaml:"index"`
	Value  string `json:"value" yaml:"value"`
	Reason string `json:"reason" yaml:"reason"` // retain-reason wire form
}

// Collapse-reason wire forms emitted on CollapsedSegment.Reason. The
// review UX groups by these values; downstream tooling alerts on
// specific reasons.
const (
	ReasonHighEntropyIdentifierSegment = "high_entropy_identifier_segment"
)

// Retain-reason wire forms emitted on RetainedSegment.Reason. Each
// reason corresponds to one of the 5 collapse gates failing in a way
// that means the segment must be kept as a literal.
const (
	ReasonLowEntropyLiteralSegment = "low_entropy_literal_segment"
	ReasonInsufficientEvents       = "insufficient_events"
	ReasonInsufficientDistinct     = "insufficient_distinct_values"
	ReasonReservedSegment          = "reserved_segment"
	ReasonNoMergeRule              = "no_merge_rule_high_risk_sibling"
)

// ErrInvalidNormalizationEvidence is the sentinel returned (wrapped)
// by Validate when an evidence struct fails any of its invariants.
// Callers use errors.Is for matching.
var ErrInvalidNormalizationEvidence = errors.New("normalize: invalid normalization evidence")

// Validate reports whether the evidence struct is internally
// consistent. It enforces the wire-form invariants documented on each
// field. An evidence struct with both CollapsedSegments and
// RetainedSegments empty is accepted (rare but valid: a rule on a
// host where every path was a constant literal already and no
// collapse decision was reached).
func (e NormalizationEvidence) Validate() error {
	if e.Algorithm == "" {
		return fmt.Errorf("normalize: %w (field=algorithm, value=\"\")", ErrInvalidNormalizationEvidence)
	}
	if e.Bucket.Host == "" {
		return fmt.Errorf("normalize: %w (field=bucket.host, value=\"\")", ErrInvalidNormalizationEvidence)
	}
	if e.Bucket.Method == "" {
		return fmt.Errorf("normalize: %w (field=bucket.method, value=\"\")", ErrInvalidNormalizationEvidence)
	}
	for i, seg := range e.CollapsedSegments {
		if seg.Index < 1 {
			return fmt.Errorf("normalize: %w (field=collapsed_segments[%d].index, value=%d)", ErrInvalidNormalizationEvidence, i, seg.Index)
		}
		if seg.DistinctValues < 0 {
			return fmt.Errorf("normalize: %w (field=collapsed_segments[%d].distinct_values, value=%d)", ErrInvalidNormalizationEvidence, i, seg.DistinctValues)
		}
		if seg.EventCount < 0 {
			return fmt.Errorf("normalize: %w (field=collapsed_segments[%d].event_count, value=%d)", ErrInvalidNormalizationEvidence, i, seg.EventCount)
		}
		if seg.Reason == "" {
			return fmt.Errorf("normalize: %w (field=collapsed_segments[%d].reason, value=\"\")", ErrInvalidNormalizationEvidence, i)
		}
	}
	for i, seg := range e.RetainedSegments {
		if seg.Index < 1 {
			return fmt.Errorf("normalize: %w (field=retained_segments[%d].index, value=%d)", ErrInvalidNormalizationEvidence, i, seg.Index)
		}
		if seg.Reason == "" {
			return fmt.Errorf("normalize: %w (field=retained_segments[%d].reason, value=\"\")", ErrInvalidNormalizationEvidence, i)
		}
	}
	return nil
}
