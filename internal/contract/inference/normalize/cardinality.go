// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package normalize

import (
	"errors"
	"fmt"
	"sort"
)

// tailBucketPattern is the canonical wire form for the aggregated
// tail bucket emitted when a host's distinct path-family count
// exceeds the cap. The review UX renders this verbatim; downstream
// metrics emit a `learn_normalize_tail_events_total` counter keyed
// by this label.
const tailBucketPattern = "_other"

// PathFamily is a (post-collapse) path-family entry contributed by
// the caller after Decide has run on each bucket. Cardinality cap
// operates at the host level: PathFamily.Host is the bucket's host,
// the canonical pattern is the segment-collapsed form, and
// EventCount is the total events observed against this family
// during the window.
type PathFamily struct {
	Host       string
	Pattern    string // post-collapse path pattern, e.g. "/repos/*"
	EventCount int
}

// CapResult is what CapPerHost returns: the kept top-N families
// plus an aggregated _other tail entry (if overflow occurred), plus
// the promotion-block decision. The struct is the wire-form
// contract for the review UX and the policy hash.
type CapResult struct {
	Kept            []PathFamily // top-N by EventCount, deterministically sorted
	Tail            PathFamily   // _other bucket; Pattern == "_other"; EventCount == sum of dropped
	HostTotalEvents int          // sum of all input EventCount for this host (kept + tail)
	Overflowed      bool         // true iff input had > N families for this host
	PromotionBlock  bool         // true iff Tail.EventCount / HostTotalEvents > tail_promotion_block_pct AND !acceptTail
}

// ShouldBlockPromotion returns the PromotionBlock field. Callers
// can write `if result.ShouldBlockPromotion() { ... }` for
// readability.
func (c CapResult) ShouldBlockPromotion() bool {
	return c.PromotionBlock
}

// CapConfig carries the algorithm knobs for CapPerHost. Mirrors the
// YAML knobs at
// learn.inference.normalization.{cardinality_cap_per_host,
// tail_promotion_block_pct}.
type CapConfig struct {
	CardinalityCapPerHost int     // max distinct families per host before tail bucketing
	TailPromotionBlockPct float64 // tail-event% threshold above which promotion is blocked
}

// Default cap-config values mirror the design doc
// (learn-and-lock-design.md, lines 1100-1106). 1000 distinct
// families per host is the per-host ceiling; >5% tail coverage
// blocks promotion unless the operator opts in via accept_tail.
const (
	defaultCardinalityCapPerHost = 1000
	defaultTailPromotionBlockPct = 5.0
	maxTailPromotionBlockPct     = 100.0
)

// DefaultCapConfig returns the canonical defaults baked into the
// design. Tested by TestDefaultCapConfig_Locked as a drift guard.
func DefaultCapConfig() CapConfig {
	return CapConfig{
		CardinalityCapPerHost: defaultCardinalityCapPerHost,
		TailPromotionBlockPct: defaultTailPromotionBlockPct,
	}
}

// Resolved returns a CapConfig with missing/zero fields filled from
// DefaultCapConfig(). Negative values pass through unchanged so
// Validate can flag them; Resolved deliberately does not silently
// repair invalid input.
func (c CapConfig) Resolved() CapConfig {
	out := c
	if out.CardinalityCapPerHost == 0 {
		out.CardinalityCapPerHost = defaultCardinalityCapPerHost
	}
	if out.TailPromotionBlockPct == 0 {
		out.TailPromotionBlockPct = defaultTailPromotionBlockPct
	}
	return out
}

// ErrInvalidCapConfig is the sentinel returned (wrapped) when a
// CapConfig fails Validate. Callers use errors.Is.
var ErrInvalidCapConfig = errors.New("normalize: invalid cap config")

// Validate enforces the documented ranges:
//   - CardinalityCapPerHost must be >= 0 (zero means "use default" via Resolved).
//   - TailPromotionBlockPct must be in [0, 100].
//
// Pure: no I/O.
func (c CapConfig) Validate() error {
	if c.CardinalityCapPerHost < 0 {
		return fmt.Errorf("normalize: %w (field=cardinality_cap_per_host, value=%d)", ErrInvalidCapConfig, c.CardinalityCapPerHost)
	}
	if c.TailPromotionBlockPct < 0 {
		return fmt.Errorf("normalize: %w (field=tail_promotion_block_pct, value=%v)", ErrInvalidCapConfig, c.TailPromotionBlockPct)
	}
	if c.TailPromotionBlockPct > maxTailPromotionBlockPct {
		return fmt.Errorf("normalize: %w (field=tail_promotion_block_pct, value=%v)", ErrInvalidCapConfig, c.TailPromotionBlockPct)
	}
	return nil
}

// ErrCapInvalidInput is the sentinel returned (wrapped) when
// CapPerHost is called with an empty host or with an input
// PathFamily that has a negative EventCount. These are programmer
// errors caught at the boundary; the runtime never produces them.
var ErrCapInvalidInput = errors.New("normalize: invalid cap input")

// CapPerHost applies the per-host cardinality cap to `families`,
// emitting the top-N kept entries and aggregating any overflow into
// a single `_other` tail bucket. The function is pure: no I/O, no
// goroutines, no allocations beyond the result.
//
// Algorithm (deterministic across calls and Go versions):
//  1. Stable-filter to entries whose Host == host.
//  2. Sort survivors by EventCount DESC, then Pattern ASC.
//  3. If len(filtered) <= cap, all are kept; tail is empty (Pattern
//     stays "_other" with EventCount == 0).
//  4. Otherwise top-N becomes Kept and the rest is summed into Tail.
//  5. PromotionBlock is set when Tail event% strictly exceeds the
//     threshold and acceptTail is false. Equality at the threshold
//     does NOT block (strict-greater-than semantic, pinned by test).
//
// Defensive checks reject host == "" and any input with
// EventCount < 0 with a wrapped ErrCapInvalidInput.
func CapPerHost(host string, families []PathFamily, cfg CapConfig, acceptTail bool) (CapResult, error) {
	if host == "" {
		return CapResult{}, fmt.Errorf("normalize: %w (field=host, value=\"\")", ErrCapInvalidInput)
	}
	for i, f := range families {
		if f.EventCount < 0 {
			return CapResult{}, fmt.Errorf("normalize: %w (field=families[%d].event_count, value=%d)", ErrCapInvalidInput, i, f.EventCount)
		}
	}

	resolved := cfg.Resolved()
	limit := resolved.CardinalityCapPerHost

	// Stable filter for entries that belong to this host.
	filtered := make([]PathFamily, 0, len(families))
	for _, f := range families {
		if f.Host == host {
			filtered = append(filtered, f)
		}
	}

	// Deterministic sort: EventCount DESC, Pattern ASC for ties.
	sort.SliceStable(filtered, func(i, j int) bool {
		if filtered[i].EventCount != filtered[j].EventCount {
			return filtered[i].EventCount > filtered[j].EventCount
		}
		return filtered[i].Pattern < filtered[j].Pattern
	})

	result := CapResult{
		Tail: PathFamily{
			Host:       host,
			Pattern:    tailBucketPattern,
			EventCount: 0,
		},
	}

	if len(filtered) <= limit {
		result.Kept = filtered
		for _, f := range filtered {
			result.HostTotalEvents += f.EventCount
		}
		return result, nil
	}

	// Overflow: top-N kept, rest aggregated into tail.
	result.Overflowed = true
	result.Kept = filtered[:limit]
	tailSum := 0
	for _, f := range filtered[limit:] {
		tailSum += f.EventCount
	}
	result.Tail.EventCount = tailSum

	for _, f := range result.Kept {
		result.HostTotalEvents += f.EventCount
	}
	result.HostTotalEvents += tailSum

	// Tail-coverage promotion block: strict-greater-than threshold.
	// HostTotalEvents > 0 here because overflow implies at least
	// (cap+1) entries; if every one were zero EventCount we still
	// wouldn't trip the threshold (0/0-style: tailSum == 0).
	if result.HostTotalEvents > 0 {
		tailPct := 100.0 * float64(tailSum) / float64(result.HostTotalEvents)
		if tailPct > resolved.TailPromotionBlockPct && !acceptTail {
			result.PromotionBlock = true
		}
	}

	return result, nil
}
