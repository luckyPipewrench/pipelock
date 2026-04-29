// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package normalize

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"reflect"
	"testing"
)

const (
	testHostA       = "api.example.com"
	testHostB       = "other.example.com"
	testHostVictim  = "victim.example"
	testTailPattern = "_other"
)

func TestDefaultCapConfig_Locked(t *testing.T) {
	t.Parallel()
	got := DefaultCapConfig()
	want := CapConfig{
		CardinalityCapPerHost: 1000,
		TailPromotionBlockPct: 5.0,
	}
	if got != want {
		t.Fatalf("DefaultCapConfig() drift: got=%+v want=%+v", got, want)
	}
}

func TestCapConfig_Resolved(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   CapConfig
		want CapConfig
	}{
		{
			name: "all_zero_uses_defaults",
			in:   CapConfig{},
			want: CapConfig{CardinalityCapPerHost: 1000, TailPromotionBlockPct: 5.0},
		},
		{
			name: "partial_zero_cap_only",
			in:   CapConfig{TailPromotionBlockPct: 10.0},
			want: CapConfig{CardinalityCapPerHost: 1000, TailPromotionBlockPct: 10.0},
		},
		{
			name: "partial_zero_pct_only",
			in:   CapConfig{CardinalityCapPerHost: 500},
			want: CapConfig{CardinalityCapPerHost: 500, TailPromotionBlockPct: 5.0},
		},
		{
			name: "all_set_passes_through",
			in:   CapConfig{CardinalityCapPerHost: 250, TailPromotionBlockPct: 2.5},
			want: CapConfig{CardinalityCapPerHost: 250, TailPromotionBlockPct: 2.5},
		},
		{
			name: "negative_passes_through_unchanged",
			in:   CapConfig{CardinalityCapPerHost: -1, TailPromotionBlockPct: -2.0},
			want: CapConfig{CardinalityCapPerHost: -1, TailPromotionBlockPct: -2.0},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.in.Resolved()
			if got != tc.want {
				t.Fatalf("Resolved(%+v) = %+v want %+v", tc.in, got, tc.want)
			}
		})
	}
}

func TestCapConfig_Validate(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		in      CapConfig
		wantErr bool
	}{
		{name: "defaults_pass", in: DefaultCapConfig(), wantErr: false},
		{name: "zero_pass", in: CapConfig{}, wantErr: false},
		{name: "valid_low_threshold", in: CapConfig{CardinalityCapPerHost: 1, TailPromotionBlockPct: 0}, wantErr: false},
		{name: "valid_max_threshold", in: CapConfig{CardinalityCapPerHost: 100, TailPromotionBlockPct: 100.0}, wantErr: false},
		{name: "negative_cap_rejects", in: CapConfig{CardinalityCapPerHost: -1, TailPromotionBlockPct: 5.0}, wantErr: true},
		{name: "negative_pct_rejects", in: CapConfig{CardinalityCapPerHost: 1000, TailPromotionBlockPct: -0.1}, wantErr: true},
		{name: "pct_above_100_rejects", in: CapConfig{CardinalityCapPerHost: 1000, TailPromotionBlockPct: 100.0001}, wantErr: true},
		{name: "pct_far_above_100_rejects", in: CapConfig{CardinalityCapPerHost: 1000, TailPromotionBlockPct: 1000.0}, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.in.Validate()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Validate(%+v) = nil want error", tc.in)
				}
				if !errors.Is(err, ErrInvalidCapConfig) {
					t.Fatalf("Validate(%+v) error not wrapping ErrInvalidCapConfig: %v", tc.in, err)
				}
			} else if err != nil {
				t.Fatalf("Validate(%+v) = %v want nil", tc.in, err)
			}
		})
	}
}

func TestCapPerHost_NoOverflow(t *testing.T) {
	t.Parallel()
	families := []PathFamily{
		{Host: testHostA, Pattern: "/a", EventCount: 50},
		{Host: testHostA, Pattern: "/b", EventCount: 25},
		{Host: testHostA, Pattern: "/c", EventCount: 10},
		{Host: testHostA, Pattern: "/d", EventCount: 5},
		{Host: testHostA, Pattern: "/e", EventCount: 2},
	}
	cfg := CapConfig{CardinalityCapPerHost: 10, TailPromotionBlockPct: 5.0}
	got, err := CapPerHost(testHostA, families, cfg, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Overflowed {
		t.Fatalf("expected Overflowed=false")
	}
	if got.PromotionBlock {
		t.Fatalf("expected PromotionBlock=false")
	}
	if len(got.Kept) != 5 {
		t.Fatalf("expected 5 kept, got %d", len(got.Kept))
	}
	if got.Tail.EventCount != 0 {
		t.Fatalf("expected empty tail, got EventCount=%d", got.Tail.EventCount)
	}
	if got.Tail.Pattern != testTailPattern {
		t.Fatalf("tail pattern = %q want %q", got.Tail.Pattern, testTailPattern)
	}
	if got.Tail.Host != testHostA {
		t.Fatalf("tail host = %q want %q", got.Tail.Host, testHostA)
	}
	if got.HostTotalEvents != 92 {
		t.Fatalf("HostTotalEvents = %d want 92", got.HostTotalEvents)
	}
}

func TestCapPerHost_ExactBoundary(t *testing.T) {
	t.Parallel()
	// N families, cap=N → all kept, no overflow. Off-by-one trap.
	cfg := CapConfig{CardinalityCapPerHost: 5, TailPromotionBlockPct: 5.0}
	families := []PathFamily{
		{Host: testHostA, Pattern: "/a", EventCount: 10},
		{Host: testHostA, Pattern: "/b", EventCount: 10},
		{Host: testHostA, Pattern: "/c", EventCount: 10},
		{Host: testHostA, Pattern: "/d", EventCount: 10},
		{Host: testHostA, Pattern: "/e", EventCount: 10},
	}
	got, err := CapPerHost(testHostA, families, cfg, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Overflowed {
		t.Fatalf("expected Overflowed=false at boundary")
	}
	if len(got.Kept) != 5 {
		t.Fatalf("expected 5 kept, got %d", len(got.Kept))
	}
	if got.Tail.EventCount != 0 {
		t.Fatalf("expected empty tail")
	}
	if got.HostTotalEvents != 50 {
		t.Fatalf("HostTotalEvents = %d want 50", got.HostTotalEvents)
	}
}

func TestCapPerHost_Overflow_PromotionAllowed(t *testing.T) {
	t.Parallel()
	// 12 families, cap=10. Top 10 dominate. Tail is ~1% → no block.
	families := make([]PathFamily, 0, 12)
	for i := range 10 {
		families = append(families, PathFamily{
			Host:       testHostA,
			Pattern:    fmt.Sprintf("/big-%02d", i),
			EventCount: 1000,
		})
	}
	families = append(families,
		PathFamily{Host: testHostA, Pattern: "/tail-1", EventCount: 50},
		PathFamily{Host: testHostA, Pattern: "/tail-2", EventCount: 50},
	)
	cfg := CapConfig{CardinalityCapPerHost: 10, TailPromotionBlockPct: 5.0}
	got, err := CapPerHost(testHostA, families, cfg, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got.Overflowed {
		t.Fatalf("expected Overflowed=true")
	}
	if got.PromotionBlock {
		t.Fatalf("expected PromotionBlock=false (tail ~1%%)")
	}
	if len(got.Kept) != 10 {
		t.Fatalf("expected 10 kept, got %d", len(got.Kept))
	}
	if got.Tail.EventCount != 100 {
		t.Fatalf("Tail.EventCount = %d want 100", got.Tail.EventCount)
	}
	if got.HostTotalEvents != 10100 {
		t.Fatalf("HostTotalEvents = %d want 10100", got.HostTotalEvents)
	}
}

func TestCapPerHost_Overflow_PromotionBlocked(t *testing.T) {
	t.Parallel()
	// Tail = 30% of total → blocks promotion.
	// The kept entries must dominate (top-N by EventCount DESC), so
	// they get the larger counts. The dropped entries make up the
	// tail — with EventCount that totals 30% of all events.
	// 10 kept × 70 = 700 events. 2 dropped × 150 = 300 events. Total = 1000.
	// 300/1000 = 30% > 5% threshold → block.
	families := make([]PathFamily, 0, 12)
	for i := range 10 {
		families = append(families, PathFamily{
			Host:       testHostA,
			Pattern:    fmt.Sprintf("/kept-%02d", i),
			EventCount: 70,
		})
	}
	// Make these have LOWER per-entry EventCount than kept entries
	// so the sort places them after the kept ones. But we want their
	// TOTAL to be 30% of events. 10 entries × 30 events = 300 events.
	for i := range 10 {
		families = append(families, PathFamily{
			Host:       testHostA,
			Pattern:    fmt.Sprintf("/dropped-%02d", i),
			EventCount: 30,
		})
	}
	cfg := CapConfig{CardinalityCapPerHost: 10, TailPromotionBlockPct: 5.0}
	got, err := CapPerHost(testHostA, families, cfg, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got.Overflowed {
		t.Fatalf("expected Overflowed=true")
	}
	if !got.PromotionBlock {
		t.Fatalf("expected PromotionBlock=true (tail=300/1000=30%%)")
	}
	if !got.ShouldBlockPromotion() {
		t.Fatalf("ShouldBlockPromotion() should mirror PromotionBlock")
	}
	if got.Tail.EventCount != 300 {
		t.Fatalf("Tail.EventCount = %d want 300", got.Tail.EventCount)
	}
	if got.HostTotalEvents != 1000 {
		t.Fatalf("HostTotalEvents = %d want 1000", got.HostTotalEvents)
	}
	if len(got.Kept) != 10 {
		t.Fatalf("expected 10 kept, got %d", len(got.Kept))
	}
}

func TestCapPerHost_AcceptTailOverridesBlock(t *testing.T) {
	t.Parallel()
	// Same shape as TestCapPerHost_Overflow_PromotionBlocked: tail
	// would be 30% of total events without acceptTail. acceptTail=true
	// must override the block.
	families := make([]PathFamily, 0, 20)
	for i := range 10 {
		families = append(families, PathFamily{
			Host:       testHostA,
			Pattern:    fmt.Sprintf("/kept-%02d", i),
			EventCount: 70,
		})
	}
	for i := range 10 {
		families = append(families, PathFamily{
			Host:       testHostA,
			Pattern:    fmt.Sprintf("/dropped-%02d", i),
			EventCount: 30,
		})
	}
	cfg := CapConfig{CardinalityCapPerHost: 10, TailPromotionBlockPct: 5.0}
	got, err := CapPerHost(testHostA, families, cfg, true) // acceptTail=true
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got.Overflowed {
		t.Fatalf("expected Overflowed=true")
	}
	if got.PromotionBlock {
		t.Fatalf("expected PromotionBlock=false when acceptTail=true")
	}
	if got.Tail.EventCount != 300 {
		t.Fatalf("Tail.EventCount = %d want 300", got.Tail.EventCount)
	}
}

func TestCapPerHost_TailExactlyAtThreshold(t *testing.T) {
	t.Parallel()
	// Build families where the tail is exactly 5% of total events.
	// 11 families, cap=10. Kept gets 950 events; tail (one entry)
	// gets 50 events. 50/1000 = 5.0% — strict-greater-than means
	// PromotionBlock is FALSE.
	families := make([]PathFamily, 0, 11)
	for i := range 10 {
		families = append(families, PathFamily{
			Host:       testHostA,
			Pattern:    fmt.Sprintf("/kept-%02d", i),
			EventCount: 95,
		})
	}
	families = append(families, PathFamily{
		Host:       testHostA,
		Pattern:    "/tail-only",
		EventCount: 50,
	})
	cfg := CapConfig{CardinalityCapPerHost: 10, TailPromotionBlockPct: 5.0}
	got, err := CapPerHost(testHostA, families, cfg, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got.Overflowed {
		t.Fatalf("expected Overflowed=true")
	}
	if got.Tail.EventCount != 50 {
		t.Fatalf("Tail.EventCount = %d want 50", got.Tail.EventCount)
	}
	if got.HostTotalEvents != 1000 {
		t.Fatalf("HostTotalEvents = %d want 1000", got.HostTotalEvents)
	}
	// 50.0 / 1000.0 == 5.0; threshold 5.0; strict greater-than means
	// no block. Pin this boundary semantic.
	if got.PromotionBlock {
		t.Fatalf("PromotionBlock=true at exact threshold; semantic should be strict-greater-than")
	}
}

func TestCapPerHost_StableTieBreaking(t *testing.T) {
	t.Parallel()
	// Two families with identical EventCount but different patterns;
	// cap=1 → the one with Pattern lexicographically lower wins.
	families := []PathFamily{
		{Host: testHostA, Pattern: "/zebra", EventCount: 100},
		{Host: testHostA, Pattern: "/apple", EventCount: 100},
	}
	cfg := CapConfig{CardinalityCapPerHost: 1, TailPromotionBlockPct: 5.0}
	got, err := CapPerHost(testHostA, families, cfg, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got.Kept) != 1 {
		t.Fatalf("expected 1 kept, got %d", len(got.Kept))
	}
	if got.Kept[0].Pattern != "/apple" {
		t.Fatalf("tie-break failed: kept %q want %q", got.Kept[0].Pattern, "/apple")
	}
	if got.Tail.EventCount != 100 {
		t.Fatalf("Tail.EventCount = %d want 100", got.Tail.EventCount)
	}
}

func TestCapPerHost_DeterministicAcross1000Calls(t *testing.T) {
	t.Parallel()
	// Build 100 random-ish families. Using a seeded RNG for the test
	// itself doesn't matter — we just need a fixed corpus that
	// exercises ties + ordering.
	rng := rand.New(rand.NewPCG(0xCAFE, 0xBEEF)) //nolint:gosec // G404: deterministic test corpus, not security-sensitive
	families := make([]PathFamily, 100)
	for i := range families {
		families[i] = PathFamily{
			Host:       testHostA,
			Pattern:    fmt.Sprintf("/p-%03d", i),
			EventCount: rng.IntN(50), // ties guaranteed in [0, 50)
		}
	}
	cfg := CapConfig{CardinalityCapPerHost: 25, TailPromotionBlockPct: 5.0}

	first, err := CapPerHost(testHostA, families, cfg, false)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	for i := range 1000 {
		got, err := CapPerHost(testHostA, families, cfg, false)
		if err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
		if !reflect.DeepEqual(got, first) {
			t.Fatalf("non-deterministic at call %d:\n first=%+v\n got=  %+v", i, first, got)
		}
	}
}

func TestCapPerHost_RejectsEmptyHost(t *testing.T) {
	t.Parallel()
	_, err := CapPerHost("", []PathFamily{{Host: testHostA, Pattern: "/x", EventCount: 1}}, DefaultCapConfig(), false)
	if err == nil {
		t.Fatalf("expected error for empty host")
	}
	if !errors.Is(err, ErrCapInvalidInput) {
		t.Fatalf("error not wrapping ErrCapInvalidInput: %v", err)
	}
}

func TestCapPerHost_RejectsNegativeEventCount(t *testing.T) {
	t.Parallel()
	families := []PathFamily{
		{Host: testHostA, Pattern: "/a", EventCount: 5},
		{Host: testHostA, Pattern: "/b", EventCount: -1},
	}
	_, err := CapPerHost(testHostA, families, DefaultCapConfig(), false)
	if err == nil {
		t.Fatalf("expected error for negative EventCount")
	}
	if !errors.Is(err, ErrCapInvalidInput) {
		t.Fatalf("error not wrapping ErrCapInvalidInput: %v", err)
	}
}

func TestCapPerHost_FiltersForeignHosts(t *testing.T) {
	t.Parallel()
	// Mixed input. CapPerHost("A", ...) must only see host-A entries.
	families := []PathFamily{
		{Host: testHostA, Pattern: "/a1", EventCount: 50},
		{Host: testHostB, Pattern: "/b1", EventCount: 999},
		{Host: testHostA, Pattern: "/a2", EventCount: 25},
		{Host: testHostB, Pattern: "/b2", EventCount: 999},
	}
	cfg := CapConfig{CardinalityCapPerHost: 10, TailPromotionBlockPct: 5.0}
	got, err := CapPerHost(testHostA, families, cfg, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got.Kept) != 2 {
		t.Fatalf("expected 2 kept (only host A), got %d", len(got.Kept))
	}
	if got.HostTotalEvents != 75 {
		t.Fatalf("HostTotalEvents = %d want 75 (foreign hosts excluded)", got.HostTotalEvents)
	}
	// Verify only host-A patterns made it through.
	for _, f := range got.Kept {
		if f.Host != testHostA {
			t.Fatalf("foreign host leaked into Kept: %+v", f)
		}
	}
}

func TestCapPerHost_EmptyFamilies(t *testing.T) {
	t.Parallel()
	got, err := CapPerHost(testHostA, nil, DefaultCapConfig(), false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got.Kept) != 0 {
		t.Fatalf("expected empty Kept")
	}
	if got.Overflowed {
		t.Fatalf("expected Overflowed=false")
	}
	if got.PromotionBlock {
		t.Fatalf("expected PromotionBlock=false")
	}
	if got.HostTotalEvents != 0 {
		t.Fatalf("expected HostTotalEvents=0")
	}
	if got.Tail.Pattern != testTailPattern {
		t.Fatalf("Tail.Pattern = %q want %q (tail bucket label is constant)", got.Tail.Pattern, testTailPattern)
	}
	if got.Tail.Host != testHostA {
		t.Fatalf("Tail.Host = %q want %q", got.Tail.Host, testHostA)
	}
}

func TestCapPerHost_DefaultsAppliedWhenZero(t *testing.T) {
	t.Parallel()
	// CapConfig{} → Resolved → 1000 cap, 5% threshold. With only
	// 3 families nothing overflows.
	families := []PathFamily{
		{Host: testHostA, Pattern: "/a", EventCount: 1},
		{Host: testHostA, Pattern: "/b", EventCount: 1},
		{Host: testHostA, Pattern: "/c", EventCount: 1},
	}
	got, err := CapPerHost(testHostA, families, CapConfig{}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Overflowed {
		t.Fatalf("expected Overflowed=false")
	}
	if len(got.Kept) != 3 {
		t.Fatalf("expected 3 kept, got %d", len(got.Kept))
	}
}

func TestCapPerHost_AdversarialCorpus_100k_Distinct(t *testing.T) {
	t.Parallel()
	const total = 100_000
	const capLimit = 1000
	rng := rand.New(rand.NewPCG(0xDEADBEEF, 0xCAFEBABE)) //nolint:gosec // G404: deterministic test corpus, not security-sensitive
	families := make([]PathFamily, total)
	totalEvents := 0
	for i := range families {
		ec := 1 + rng.IntN(10) // [1, 10]
		families[i] = PathFamily{
			Host:       testHostVictim,
			Pattern:    fmt.Sprintf("/path-%06d", i),
			EventCount: ec,
		}
		totalEvents += ec
	}
	cfg := CapConfig{CardinalityCapPerHost: capLimit, TailPromotionBlockPct: 5.0}
	got, err := CapPerHost(testHostVictim, families, cfg, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got.Overflowed {
		t.Fatalf("expected Overflowed=true")
	}
	if len(got.Kept) != capLimit {
		t.Fatalf("expected len(Kept)=%d, got %d", capLimit, len(got.Kept))
	}
	if got.Tail.Pattern != testTailPattern {
		t.Fatalf("Tail.Pattern = %q want %q", got.Tail.Pattern, testTailPattern)
	}
	if got.HostTotalEvents != totalEvents {
		t.Fatalf("HostTotalEvents = %d want %d", got.HostTotalEvents, totalEvents)
	}
	// Tail.EventCount = total - kept events.
	keptSum := 0
	for _, f := range got.Kept {
		keptSum += f.EventCount
	}
	if got.Tail.EventCount != totalEvents-keptSum {
		t.Fatalf("Tail.EventCount mismatch: tail=%d, total=%d, kept=%d, expected_tail=%d",
			got.Tail.EventCount, totalEvents, keptSum, totalEvents-keptSum)
	}
	// With ~99k of 100k entries dropped the tail will dominate.
	if !got.PromotionBlock {
		tailPct := 100.0 * float64(got.Tail.EventCount) / float64(got.HostTotalEvents)
		t.Fatalf("expected PromotionBlock=true (tail %v%% of total)", tailPct)
	}
}

func TestShouldBlockPromotion_DelegatesField(t *testing.T) {
	t.Parallel()
	c1 := CapResult{PromotionBlock: false}
	if c1.ShouldBlockPromotion() {
		t.Fatalf("ShouldBlockPromotion() = true want false")
	}
	c2 := CapResult{PromotionBlock: true}
	if !c2.ShouldBlockPromotion() {
		t.Fatalf("ShouldBlockPromotion() = false want true")
	}
}
