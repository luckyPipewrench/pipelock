// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package normalize

import (
	"errors"
	"fmt"
	"math"
	"net/url"
	"sort"
	"strings"

	"golang.org/x/text/unicode/norm"
)

// AlgorithmFrequencyWeightedEntropyV1 is the wire-form algorithm name
// emitted on every NormalizationEvidence struct produced by Decide.
// The version suffix exists so future changes to the gate matrix or
// entropy definition can ship under v2/v3 without breaking
// signature-verification on contracts compiled against v1.
const AlgorithmFrequencyWeightedEntropyV1 = "frequency_weighted_entropy_v1"

// Path-length ceiling. 2048 chars is the design's stated cap and is a
// generous bound: real-world recorder paths above 2048 are almost
// always pathological (encoded payload smuggling, fuzz noise, or
// mis-decoded binary). We reject these at the boundary rather than try
// to normalize them — a normalize step that succeeds on a 100 KB path
// is a DoS amplifier on the compile pipeline.
const maxPathBytes = 2048

// EntropyThresholdMaxBits is the upper bound for
// DecideConfig.EntropyThresholdBits accepted by Validate. A single
// segment can carry at most log2(N_distinct) bits of entropy, and
// requiring more than 8 bits before we collapse means even 256
// distinct values per segment wouldn't be enough — almost certainly a
// config typo (e.g. someone wrote "30" thinking percent).
const EntropyThresholdMaxBits = 8.0

// Sentinel errors returned (wrapped) from Canonicalize. Callers MUST
// match with errors.Is, never raw equality, because every return
// wraps with fmt.Errorf("%w (...detail)") so the operator sees the
// offending input without breaking the errors.Is chain.
var (
	// ErrPathEmpty signals the raw input was the empty string.
	ErrPathEmpty = errors.New("normalize: path is empty")

	// ErrPathTooLong signals the raw input exceeded maxPathBytes
	// after no normalization. The byte length, not the rune count,
	// is the gate — a multi-byte UTF-8 sequence still costs bytes
	// downstream.
	ErrPathTooLong = errors.New("normalize: path exceeds 2048 chars")

	// ErrPathNonCanonical signals the path contains structural noise
	// the canonicalizer refuses to silently rewrite: dot-segments
	// (".", ".."), double slashes, trailing slash on a non-root
	// path, control characters, or a percent-encoded slash that
	// would change topology after decoding.
	ErrPathNonCanonical = errors.New("normalize: path is non-canonical")

	// ErrPathDecodeFailure signals a malformed percent-escape
	// (truncated %xy, non-hex digits) inside a segment.
	ErrPathDecodeFailure = errors.New("normalize: percent-decode failed")
)

// ErrInvalidDecideConfig is returned (wrapped) by DecideConfig.Validate
// when any knob is out of range. Matches with errors.Is.
var ErrInvalidDecideConfig = errors.New("normalize: invalid decide config")

// Canonicalize transforms a raw path from a recorder event into the
// form Decide consumes. The pipeline is:
//
//  1. Reject empty or > maxPathBytes inputs.
//  2. Apply Unicode NFC normalization.
//  3. Lowercase via strings.ToLower (full-Unicode, not just ASCII).
//  4. Split on '/' and percent-decode each segment with
//     url.PathUnescape.
//  5. Reject any non-canonical structure: ".", "..", "//",
//     trailing-slash-on-non-root, control characters, percent-encoded
//     slashes, segments containing literal '/' after decode.
//
// Only path topology is validated here. Host, query, and fragment are
// the caller's responsibility — Bucket.Host comes from a separate
// host-normalization pass at the recorder boundary.
//
// Pure: no I/O, no allocations beyond the result strings, no panics.
// Returns the canonical path string, the segment slice (1-indexed by
// the algorithm but Go-0-indexed in the slice), and a wrapped
// sentinel on failure.
func Canonicalize(rawPath string) (string, []string, error) {
	if rawPath == "" {
		return "", nil, fmt.Errorf("%w", ErrPathEmpty)
	}
	if len(rawPath) > maxPathBytes {
		return "", nil, fmt.Errorf("%w (length=%d)", ErrPathTooLong, len(rawPath))
	}

	// NFC normalization first so any combining-character form
	// folds into the composed code points before we lowercase or
	// split. Note: NFC, not NFKC. NFKC is a different security
	// surface (compat decomposition) and is not what the design
	// asks for here; the path-level canonicalization is conservative
	// and only normalizes form, not visual confusables.
	canonical := norm.NFC.String(rawPath)

	// Full-Unicode lowercase. Many ID strings reach pipelock via
	// agents that uppercase casually; the bucket is per-host
	// per-method, so case folding the path keeps "/Repos/Foo" and
	// "/repos/foo" in the same bucket.
	canonical = strings.ToLower(canonical)

	// Reject control characters anywhere in the path before we
	// touch percent-decoding. A %00 in a path is a strong signal
	// the agent is probing a parser differential, and accepting it
	// would let attackers embed null bytes in collapsed segments
	// downstream.
	if hasControlChar(canonical) {
		return "", nil, fmt.Errorf("%w (reason=control_char)", ErrPathNonCanonical)
	}

	// A leading '/' is required for a recorder path. Bare "foo"
	// would split into [""] which is misleading — reject up front.
	if !strings.HasPrefix(canonical, "/") {
		return "", nil, fmt.Errorf("%w (reason=missing_leading_slash)", ErrPathNonCanonical)
	}

	// Special case: root path "/". Splitting on "/" yields ["", ""]
	// which is two empty segments, but the algorithm wants
	// segments=[].
	if canonical == "/" {
		return "/", []string{}, nil
	}

	// Trailing slash on a non-root path is non-canonical: it
	// changes the bucket parent_prefix for the same logical
	// resource. Reject so the caller fixes it upstream.
	if strings.HasSuffix(canonical, "/") {
		return "", nil, fmt.Errorf("%w (reason=trailing_slash)", ErrPathNonCanonical)
	}

	// Split on '/'. Drop the leading empty element from the leading
	// '/'. We've already rejected trailing slash on non-root, so no
	// trailing empty element here.
	rawSegments := strings.Split(canonical[1:], "/")

	// Percent-decode each segment, rejecting double slashes,
	// dot-segments, decode failures, and decoded-segments
	// containing literal '/' (which would indicate a percent-encoded
	// slash, a topology-changing bypass).
	segments := make([]string, 0, len(rawSegments))
	decodedSegments := make([]string, 0, len(rawSegments))
	for _, seg := range rawSegments {
		if seg == "" {
			return "", nil, fmt.Errorf("%w (reason=double_slash)", ErrPathNonCanonical)
		}
		if seg == "." || seg == ".." {
			return "", nil, fmt.Errorf("%w (reason=dot_segment, segment=%q)", ErrPathNonCanonical, seg)
		}
		decoded, err := url.PathUnescape(seg)
		if err != nil {
			return "", nil, fmt.Errorf("%w (segment=%q): %w", ErrPathDecodeFailure, seg, err)
		}
		// Decoded segment containing a literal '/' means the input
		// had %2F, which would silently change the path topology
		// (one segment becomes multiple). Treat as a bypass and
		// reject.
		if strings.ContainsRune(decoded, '/') {
			return "", nil, fmt.Errorf("%w (reason=percent_encoded_slash, segment=%q)", ErrPathNonCanonical, seg)
		}
		// Defense-in-depth: decoded value should not contain any
		// control char either. Without this, a %01 inside a
		// segment would slip through (we only checked the raw
		// input's control chars before decoding).
		if hasControlChar(decoded) {
			return "", nil, fmt.Errorf("%w (reason=decoded_control_char)", ErrPathNonCanonical)
		}
		// Note: a non-empty seg cannot decode to "" because
		// url.PathUnescape never strips bytes without erroring,
		// so no explicit empty-decoded check is needed here.
		segments = append(segments, decoded)
		decodedSegments = append(decodedSegments, decoded)
	}

	// Re-emit the canonical form from the decoded segments so the
	// returned string matches the segment slice byte-for-byte. This
	// guarantees a caller that splits the canonical path on '/' will
	// recover the same slice.
	canonicalOut := "/" + strings.Join(decodedSegments, "/")
	return canonicalOut, segments, nil
}

// hasControlChar reports whether s contains any byte in the C0
// (\x00-\x1F) or DEL (\x7F) ranges. Operates on bytes, not runes,
// because control bytes embedded in UTF-8 mid-sequence are still
// dangerous regardless of how the surrounding rune is counted.
func hasControlChar(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= 0x1F || c == 0x7F {
			return true
		}
	}
	return false
}

// Entropy returns the frequency-weighted Shannon entropy in bits of
// the value distribution described by counts. counts maps each
// distinct value at a single segment position to the number of
// recorder events that produced it. The formula is:
//
//	H = -Σ p_i * log2(p_i)   where p_i = counts[v_i] / total
//
// Edge cases:
//   - Empty map or total <= 0 returns 0.0 (no entropy).
//   - A single distinct value returns 0.0 (perfect predictability).
//   - Any non-positive count is skipped so log2(0) never appears.
//
// Pure: no I/O, never panics, never returns NaN or Inf.
func Entropy(counts map[string]int) float64 {
	if len(counts) == 0 {
		return 0.0
	}
	total := 0
	for _, c := range counts {
		if c <= 0 {
			continue
		}
		total += c
	}
	if total <= 0 {
		return 0.0
	}
	var h float64
	denom := float64(total)
	for _, c := range counts {
		if c <= 0 {
			continue
		}
		p := float64(c) / denom
		// p is strictly positive here because c > 0 and denom > 0.
		h -= p * math.Log2(p)
	}
	// Guard against any residual numerical noise. A pure
	// computation should not produce NaN or Inf, but a defensive
	// clamp protects downstream code that hashes evidence into a
	// policy hash.
	if math.IsNaN(h) || math.IsInf(h, 0) {
		return 0.0
	}
	return h
}

// DecideConfig carries the algorithm knobs for Decide. Every field
// maps 1:1 to a YAML field on
// learn.inference.normalization in the deployment config; the YAML
// loader is responsible for translating between snake_case YAML and
// these typed Go fields.
type DecideConfig struct {
	// MinEvents is gate 1: the bucket must contain at least this
	// many total events at the position before any collapse is
	// considered.
	MinEvents int

	// MinDistinctValues is gate 2: the position must show at least
	// this many distinct value strings. With min=5 and 4 distinct
	// values we retain.
	MinDistinctValues int

	// EntropyThresholdBits is gate 3: the position's
	// frequency-weighted Shannon entropy must equal or exceed this
	// many bits before we collapse.
	EntropyThresholdBits float64

	// ReservedExtras is appended to the package's canonical
	// reserved-segment list when running gate 4. Operator-supplied
	// extras can extend the security floor but cannot remove
	// canonical entries.
	ReservedExtras []string

	// HighRiskSiblings drives gate 5: if any value at the position
	// matches one of these names, the entire position retains. The
	// caller decides which siblings count as "high risk"; this
	// package only enforces the rule.
	HighRiskSiblings []string
}

// Default knob values, matching the design baseline. The
// constants are unexported so callers must go through
// DefaultDecideConfig — that pattern makes the drift guard test
// trivial (TestDefaultDecideConfig_Locked) and keeps the values out
// of unrelated import sets.
const (
	defaultDecideMinEvents            = 10
	defaultDecideMinDistinctValues    = 5
	defaultDecideEntropyThresholdBits = 3.0
)

// DefaultDecideConfig returns the design's canonical defaults:
// MinEvents=10, MinDistinctValues=5, EntropyThresholdBits=3.0,
// ReservedExtras=nil, HighRiskSiblings=nil. The drift-guard test
// asserts exact equality so these values cannot move silently.
func DefaultDecideConfig() DecideConfig {
	return DecideConfig{
		MinEvents:            defaultDecideMinEvents,
		MinDistinctValues:    defaultDecideMinDistinctValues,
		EntropyThresholdBits: defaultDecideEntropyThresholdBits,
		ReservedExtras:       nil,
		HighRiskSiblings:     nil,
	}
}

// Resolved returns a DecideConfig with each zero-valued numeric field
// replaced by its default. Negative values pass through unchanged so
// Validate (which the caller is expected to run first or after) can
// surface them as configuration errors instead of silently rewriting
// them to a default.
//
// The slice fields ReservedExtras and HighRiskSiblings are passed
// through; nil slices are valid inputs and stay nil.
func (c DecideConfig) Resolved() DecideConfig {
	out := c
	if out.MinEvents == 0 {
		out.MinEvents = defaultDecideMinEvents
	}
	if out.MinDistinctValues == 0 {
		out.MinDistinctValues = defaultDecideMinDistinctValues
	}
	if out.EntropyThresholdBits == 0 {
		out.EntropyThresholdBits = defaultDecideEntropyThresholdBits
	}
	return out
}

// Validate reports whether the config is internally consistent.
// Negative integer thresholds, negative entropy, or entropy above
// EntropyThresholdMaxBits are all rejected with a wrapped sentinel.
// Slice fields are not validated here; the caller validates segment
// content at the boundary where it has type info.
func (c DecideConfig) Validate() error {
	if c.MinEvents < 0 {
		return fmt.Errorf("%w (field=min_events, value=%d)", ErrInvalidDecideConfig, c.MinEvents)
	}
	if c.MinDistinctValues < 0 {
		return fmt.Errorf("%w (field=min_distinct_values, value=%d)", ErrInvalidDecideConfig, c.MinDistinctValues)
	}
	if c.EntropyThresholdBits < 0 {
		return fmt.Errorf("%w (field=entropy_threshold_bits, value=%g)", ErrInvalidDecideConfig, c.EntropyThresholdBits)
	}
	if c.EntropyThresholdBits > EntropyThresholdMaxBits {
		return fmt.Errorf("%w (field=entropy_threshold_bits, value=%g, max=%g)", ErrInvalidDecideConfig, c.EntropyThresholdBits, EntropyThresholdMaxBits)
	}
	return nil
}

// SegmentObservation is one observed (value-at-position, event-weight)
// pair from a single bucket. The future compile pipeline will flatten
// recorder events into a slice of these per (host, method,
// parent_prefix) bucket and per segment position.
//
// Index is 1-indexed to match the wire-form Index field on
// CollapsedSegment / RetainedSegment. Decide preserves that 1-indexed
// convention end-to-end.
type SegmentObservation struct {
	// Index is the 1-indexed segment position. Index 1 is the
	// segment immediately after the leading '/'.
	Index int

	// Value is the already-canonicalized literal segment text. The
	// caller is responsible for running Canonicalize and pulling
	// the matching slice element before constructing this struct.
	Value string

	// EventCount is how many recorder events observed this Value
	// at this Index. Non-positive counts are treated as zero by
	// Decide.
	EventCount int
}

// Decide composes the bucket's observations into a NormalizationEvidence,
// running the 5-gate test per segment position and emitting one entry
// per position into either CollapsedSegments or RetainedSegments.
//
// Gates (in order, first-failure-wins for retain reasons):
//
//  1. min_events: total event count at the position >= cfg.MinEvents.
//     Failure → ReasonInsufficientEvents.
//  2. min_distinct_values: count of distinct values at the position
//     >= cfg.MinDistinctValues. Single-distinct-value positions retain
//     with ReasonLowEntropyLiteralSegment (covers "/repos always
//     appears at index 1"); 2..(min-1) distinct retain with
//     ReasonInsufficientDistinct.
//  3. entropy: frequency-weighted Shannon entropy >= cfg.EntropyThresholdBits.
//     Failure → ReasonLowEntropyLiteralSegment.
//  4. reserved: any value at the position matches IsReserved with
//     cfg.ReservedExtras. Failure → ReasonReservedSegment.
//  5. no-merge: any value at the position matches cfg.HighRiskSiblings.
//     Failure → ReasonNoMergeRule.
//
// Gates 4 and 5 are evaluated AFTER 1/2/3 in the listing above, but
// the reserved/no-merge checks are position-level: they apply
// regardless of how high entropy climbs. The implementation evaluates
// gates 4 and 5 BEFORE gates 2 and 3 so that even a position with
// only one distinct value still surfaces "reserved_segment" if that
// value is reserved — that's the security floor.
//
// Determinism: positions are emitted in ascending Index order. The
// caller hashes this evidence into the policy hash, so non-deterministic
// map iteration would break audit reproducibility.
func Decide(observations []SegmentObservation, cfg DecideConfig) NormalizationEvidence {
	resolved := cfg.Resolved()
	evidence := NormalizationEvidence{
		Algorithm: AlgorithmFrequencyWeightedEntropyV1,
	}
	if len(observations) == 0 {
		return evidence
	}

	// Aggregate: per-index map of value -> count.
	type positionAgg struct {
		counts map[string]int
		total  int
	}
	byIndex := make(map[int]*positionAgg)
	for _, obs := range observations {
		if obs.Index < 1 {
			// Defensive: skip malformed input. The caller is
			// supposed to use 1-indexed positions; a 0 or
			// negative index is a programming error upstream
			// but Decide must not panic on it.
			continue
		}
		count := obs.EventCount
		if count <= 0 {
			continue
		}
		agg, ok := byIndex[obs.Index]
		if !ok {
			agg = &positionAgg{counts: make(map[string]int)}
			byIndex[obs.Index] = agg
		}
		agg.counts[obs.Value] += count
		agg.total += count
	}

	// Sort indices ascending so emission order is deterministic.
	// Map iteration in Go is randomized; without this sort the
	// signed contract hash would change run-to-run on identical
	// input.
	indices := make([]int, 0, len(byIndex))
	for i := range byIndex {
		indices = append(indices, i)
	}
	sort.Ints(indices)

	for _, idx := range indices {
		agg := byIndex[idx]

		// Gate 4 first: reserved-segment presence. A reserved
		// value at this index forces retain regardless of
		// entropy, distinct count, or event count. We retain a
		// stable representative value for the wire form (the
		// first reserved value in sorted order, so the evidence
		// is reproducible).
		if reservedHit := firstReservedValue(agg.counts, resolved.ReservedExtras); reservedHit != "" {
			evidence.RetainedSegments = append(evidence.RetainedSegments, RetainedSegment{
				Index:  idx,
				Value:  reservedHit,
				Reason: ReasonReservedSegment,
			})
			continue
		}

		// Gate 5: high-risk sibling presence. Same logic as
		// reserved but with the operator-supplied list.
		if siblingHit := firstSiblingValue(agg.counts, resolved.HighRiskSiblings); siblingHit != "" {
			evidence.RetainedSegments = append(evidence.RetainedSegments, RetainedSegment{
				Index:  idx,
				Value:  siblingHit,
				Reason: ReasonNoMergeRule,
			})
			continue
		}

		// Gate 1: min_events.
		if agg.total < resolved.MinEvents {
			evidence.RetainedSegments = append(evidence.RetainedSegments, RetainedSegment{
				Index:  idx,
				Value:  representativeValue(agg.counts),
				Reason: ReasonInsufficientEvents,
			})
			continue
		}

		// Gate 2: min_distinct_values. Single-distinct-value
		// positions get a more specific reason because the most
		// common case is a literal path component like "/repos"
		// that should never collapse — calling that
		// "insufficient_distinct" would be misleading in audit.
		distinct := len(agg.counts)
		if distinct < resolved.MinDistinctValues {
			reason := ReasonInsufficientDistinct
			if distinct <= 1 {
				reason = ReasonLowEntropyLiteralSegment
			}
			evidence.RetainedSegments = append(evidence.RetainedSegments, RetainedSegment{
				Index:  idx,
				Value:  representativeValue(agg.counts),
				Reason: reason,
			})
			continue
		}

		// Gate 3: entropy.
		entropy := Entropy(agg.counts)
		if entropy < resolved.EntropyThresholdBits {
			evidence.RetainedSegments = append(evidence.RetainedSegments, RetainedSegment{
				Index:  idx,
				Value:  representativeValue(agg.counts),
				Reason: ReasonLowEntropyLiteralSegment,
			})
			continue
		}

		// All 5 gates passed — collapse.
		evidence.CollapsedSegments = append(evidence.CollapsedSegments, CollapsedSegment{
			Index:          idx,
			DistinctValues: distinct,
			EventCount:     agg.total,
			Entropy:        entropy,
			Reason:         ReasonHighEntropyIdentifierSegment,
		})
	}

	return evidence
}

// firstReservedValue returns the lexicographically-first value in
// counts that matches IsReserved. Sorting first guarantees a
// deterministic representative value for the audit record;
// non-deterministic order would break the signed contract hash.
// Returns "" when no value matches.
func firstReservedValue(counts map[string]int, extras []string) string {
	keys := sortedKeys(counts)
	for _, k := range keys {
		if IsReserved(k, extras) {
			return k
		}
	}
	return ""
}

// firstSiblingValue returns the lexicographically-first value in
// counts that matches any name in siblings. Same determinism
// rationale as firstReservedValue.
func firstSiblingValue(counts map[string]int, siblings []string) string {
	if len(siblings) == 0 {
		return ""
	}
	keys := sortedKeys(counts)
	for _, k := range keys {
		for _, s := range siblings {
			if k == s {
				return k
			}
		}
	}
	return ""
}

// representativeValue returns the lexicographically-first value in
// counts. Used for the RetainedSegment.Value field on retain reasons
// that are not tied to a specific value (insufficient_events,
// insufficient_distinct, low_entropy_literal_segment). Stable across
// runs; never panics; "" only when counts is empty (which Decide
// already filters out before reaching this path).
func representativeValue(counts map[string]int) string {
	keys := sortedKeys(counts)
	if len(keys) == 0 {
		return ""
	}
	return keys[0]
}

// sortedKeys returns the keys of counts in ascending byte order.
// Centralized so all three helper functions share the same
// determinism contract; callers must not mutate the result.
func sortedKeys(counts map[string]int) []string {
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
