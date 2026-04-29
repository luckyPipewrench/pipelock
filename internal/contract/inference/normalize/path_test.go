// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package normalize

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
)

const (
	testValRepos = "repos"
	testValAdmin = "admin"
	testValUsers = "users"
	testValAuth  = "auth"
	testValDebug = "debug"
)

// ---------- Canonicalize ----------

func TestCanonicalize_HappyPath(t *testing.T) {
	tests := []struct {
		name     string
		in       string
		wantPath string
		wantSegs []string
	}{
		{"simple ascii", "/foo/bar", "/foo/bar", []string{"foo", "bar"}},
		{"root", "/", "/", []string{}},
		{"case folding", "/FOO/Bar", "/foo/bar", []string{"foo", "bar"}},
		{"percent decoded", "/foo%20bar", "/foo bar", []string{"foo bar"}},
		{"multi segment", "/repos/octocat/hello-world", "/repos/octocat/hello-world", []string{"repos", "octocat", "hello-world"}},
		{"unicode path lowercased", "/Repos/ÉClair", "/repos/éclair", []string{"repos", "éclair"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPath, gotSegs, err := Canonicalize(tt.in)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotPath != tt.wantPath {
				t.Errorf("path: got %q, want %q", gotPath, tt.wantPath)
			}
			if len(gotSegs) != len(tt.wantSegs) {
				t.Fatalf("segs len: got %d, want %d (got=%v)", len(gotSegs), len(tt.wantSegs), gotSegs)
			}
			for i := range gotSegs {
				if gotSegs[i] != tt.wantSegs[i] {
					t.Errorf("seg[%d]: got %q, want %q", i, gotSegs[i], tt.wantSegs[i])
				}
			}
		})
	}
}

func TestCanonicalize_RejectsEmpty(t *testing.T) {
	_, _, err := Canonicalize("")
	if !errors.Is(err, ErrPathEmpty) {
		t.Fatalf("got %v, want ErrPathEmpty", err)
	}
}

func TestCanonicalize_RejectsTooLong(t *testing.T) {
	// 2049-char path rejects.
	long := "/" + strings.Repeat("a", maxPathBytes)
	_, _, err := Canonicalize(long)
	if !errors.Is(err, ErrPathTooLong) {
		t.Fatalf("got %v, want ErrPathTooLong", err)
	}
	// 2048-char path accepts.
	exact := "/" + strings.Repeat("a", maxPathBytes-1)
	if len(exact) != maxPathBytes {
		t.Fatalf("test setup: exact path length %d != %d", len(exact), maxPathBytes)
	}
	if _, _, err := Canonicalize(exact); err != nil {
		t.Fatalf("2048-char path should accept, got %v", err)
	}
}

func TestCanonicalize_RejectsNonCanonical(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{"dot dot", "/foo/../bar"},
		{"dot", "/foo/./bar"},
		{"double slash", "/foo//bar"},
		{"trailing slash", "/foo/bar/"},
		{"null byte", "/foo\x00bar"},
		{"control 0x1f", "/foo\x1fbar"},
		{"control 0x7f", "/foo\x7fbar"},
		{"missing leading slash", "foo/bar"},
		{"leading dot dot", "/../etc/passwd"},
		{"trailing dot", "/foo/."},
		{"trailing slash root extension", "/foo/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := Canonicalize(tt.in)
			if !errors.Is(err, ErrPathNonCanonical) {
				t.Fatalf("got %v, want ErrPathNonCanonical", err)
			}
		})
	}
}

func TestCanonicalize_RejectsBadPercentDecode(t *testing.T) {
	tests := []string{
		"/foo%2",
		"/foo%XX",
		"/foo%G0",
	}
	for _, in := range tests {
		t.Run(in, func(t *testing.T) {
			_, _, err := Canonicalize(in)
			if !errors.Is(err, ErrPathDecodeFailure) {
				t.Fatalf("got %v, want ErrPathDecodeFailure", err)
			}
		})
	}
}

func TestCanonicalize_RejectsPercentEncodedSlash(t *testing.T) {
	// %2F decodes to '/', which would split one segment into two.
	_, _, err := Canonicalize("/foo%2Fbar")
	if !errors.Is(err, ErrPathNonCanonical) {
		t.Fatalf("got %v, want ErrPathNonCanonical", err)
	}
}

func TestCanonicalize_RejectsDecodedControlChar(t *testing.T) {
	// %01 decodes to a C0 control char that wasn't visible pre-decode.
	_, _, err := Canonicalize("/foo%01bar")
	if !errors.Is(err, ErrPathNonCanonical) {
		t.Fatalf("got %v, want ErrPathNonCanonical", err)
	}
}

func TestCanonicalize_NFCApplied(t *testing.T) {
	// "é" (decomposed) and "é" (composed) must fold to the
	// same canonical form via NFC.
	decomposed := "/café" // /cafe + combining acute
	composed := "/café"    // /café composed
	gotDec, _, err := Canonicalize(decomposed)
	if err != nil {
		t.Fatalf("decomposed: %v", err)
	}
	gotComp, _, err := Canonicalize(composed)
	if err != nil {
		t.Fatalf("composed: %v", err)
	}
	if gotDec != gotComp {
		t.Fatalf("NFC fold mismatch: decomposed=%q composed=%q", gotDec, gotComp)
	}
}

func TestCanonicalize_RootPath(t *testing.T) {
	gotPath, gotSegs, err := Canonicalize("/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotPath != "/" {
		t.Errorf("path: got %q, want /", gotPath)
	}
	if len(gotSegs) != 0 {
		t.Errorf("segs: got %v, want empty", gotSegs)
	}
}

func TestCanonicalize_DeterministicAcross1000Calls(t *testing.T) {
	in := "/Repos/Octocat/Hello-World%20Test"
	wantPath, wantSegs, err := Canonicalize(in)
	if err != nil {
		t.Fatalf("seed run: %v", err)
	}
	for i := 0; i < 1000; i++ {
		gotPath, gotSegs, err := Canonicalize(in)
		if err != nil {
			t.Fatalf("iter %d: %v", i, err)
		}
		if gotPath != wantPath {
			t.Fatalf("iter %d: path drift got %q want %q", i, gotPath, wantPath)
		}
		if len(gotSegs) != len(wantSegs) {
			t.Fatalf("iter %d: seg-count drift", i)
		}
		for j := range gotSegs {
			if gotSegs[j] != wantSegs[j] {
				t.Fatalf("iter %d seg[%d]: drift got %q want %q", i, j, gotSegs[j], wantSegs[j])
			}
		}
	}
}

// ---------- Entropy ----------

func TestEntropy_EmptyReturnsZero(t *testing.T) {
	if got := Entropy(map[string]int{}); got != 0.0 {
		t.Errorf("got %v, want 0", got)
	}
	if got := Entropy(nil); got != 0.0 {
		t.Errorf("nil: got %v, want 0", got)
	}
}

func TestEntropy_SingleValueReturnsZero(t *testing.T) {
	got := Entropy(map[string]int{"foo": 100})
	if got != 0.0 {
		t.Errorf("got %v, want 0", got)
	}
}

func TestEntropy_FiftyFifty(t *testing.T) {
	got := Entropy(map[string]int{"a": 50, "b": 50})
	if math.Abs(got-1.0) > 1e-9 {
		t.Errorf("got %v, want 1.0", got)
	}
}

func TestEntropy_UniformN(t *testing.T) {
	// 4 equal-count values => log2(4) = 2.
	got := Entropy(map[string]int{"a": 1, "b": 1, "c": 1, "d": 1})
	if math.Abs(got-2.0) > 1e-9 {
		t.Errorf("got %v, want 2.0", got)
	}
}

func TestEntropy_DesignTableRow(t *testing.T) {
	// Design example: 87 distinct values, 412 events, entropy ~5.9.
	// We construct a near-uniform distribution: 87 values, total 412
	// events (412/87 ≈ 4.74). Allocate 4 events to most values and 5
	// to the first 412-87*4 = 64 values to use up the total.
	counts := make(map[string]int)
	const distinct = 87
	const total = 412
	base := total / distinct
	extras := total - base*distinct
	for i := 0; i < distinct; i++ {
		k := fmt.Sprintf("v%03d", i)
		c := base
		if i < extras {
			c++
		}
		counts[k] = c
	}
	got := Entropy(counts)
	// Upper bound is log2(87) ~= 6.44; near-uniform should land in
	// roughly [5.8, 6.5] per the design's "5.9" stated value.
	if got < 5.5 || got > 6.5 {
		t.Errorf("got %v, want in [5.5, 6.5] (design row says ~5.9)", got)
	}
	// Tighter assertion: within 0.1 of 6.44 (uniform limit) since
	// our distribution is nearly uniform.
	uniformLimit := math.Log2(distinct)
	if math.Abs(got-uniformLimit) > 0.1 {
		t.Errorf("near-uniform should approach log2(87)=%v, got %v", uniformLimit, got)
	}
}

func TestEntropy_NeverNaN(t *testing.T) {
	// Synthetic mixes: zero counts, large counts, one-offs, and a
	// deterministic pseudo-random pattern. None should produce NaN
	// or Inf. We use a stateful linear-congruential mixer rather
	// than math/rand so the test is fully deterministic without
	// pulling in a weak-RNG dependency.
	state := uint64(0xDEADBEEFCAFEBABE)
	mix := func() uint64 {
		state = state*6364136223846793005 + 1442695040888963407
		return state
	}
	for i := 0; i < 100; i++ {
		counts := make(map[string]int)
		n := int(mix() % 20)
		for j := 0; j < n; j++ {
			counts[fmt.Sprintf("k%d", j)] = int(mix() % 1_000_000)
		}
		got := Entropy(counts)
		if math.IsNaN(got) || math.IsInf(got, 0) {
			t.Fatalf("iter %d: got %v from %v", i, got, counts)
		}
		if got < 0 {
			t.Fatalf("iter %d: negative entropy %v", i, got)
		}
	}
}

func TestEntropy_DeterministicAcross1000Calls(t *testing.T) {
	counts := map[string]int{"a": 11, "b": 22, "c": 33, "d": 44}
	want := Entropy(counts)
	for i := 0; i < 1000; i++ {
		if got := Entropy(counts); got != want {
			t.Fatalf("iter %d: drift got %v want %v", i, got, want)
		}
	}
}

func TestEntropy_HandlesNonPositiveCounts(t *testing.T) {
	// Zero/negative counts must be skipped without panic.
	got := Entropy(map[string]int{"a": 50, "b": 50, "skipped-zero": 0, "skipped-neg": -5})
	if math.Abs(got-1.0) > 1e-9 {
		t.Errorf("got %v, want 1.0 (non-positive entries skipped)", got)
	}
}

func TestEntropy_AllNonPositiveCountsReturnsZero(t *testing.T) {
	// Map is non-empty (so len-zero guard skipped) but every count is
	// non-positive. Exercises the "total <= 0" defensive guard.
	got := Entropy(map[string]int{"a": 0, "b": -1, "c": -100})
	if got != 0.0 {
		t.Errorf("got %v, want 0", got)
	}
}

// ---------- DecideConfig ----------

func TestDefaultDecideConfig_Locked(t *testing.T) {
	got := DefaultDecideConfig()
	want := DecideConfig{
		MinEvents:            10,
		MinDistinctValues:    5,
		EntropyThresholdBits: 3.0,
		ReservedExtras:       nil,
		HighRiskSiblings:     nil,
	}
	if got.MinEvents != want.MinEvents ||
		got.MinDistinctValues != want.MinDistinctValues ||
		got.EntropyThresholdBits != want.EntropyThresholdBits ||
		got.ReservedExtras != nil ||
		got.HighRiskSiblings != nil {
		t.Fatalf("default drifted: got %+v, want %+v", got, want)
	}
}

func TestDecideConfig_Resolved(t *testing.T) {
	tests := []struct {
		name string
		in   DecideConfig
		want DecideConfig
	}{
		{
			"all zero",
			DecideConfig{},
			DefaultDecideConfig(),
		},
		{
			"min_events set, others default",
			DecideConfig{MinEvents: 25},
			DecideConfig{MinEvents: 25, MinDistinctValues: 5, EntropyThresholdBits: 3.0},
		},
		{
			"min_distinct set, others default",
			DecideConfig{MinDistinctValues: 8},
			DecideConfig{MinEvents: 10, MinDistinctValues: 8, EntropyThresholdBits: 3.0},
		},
		{
			"entropy set, others default",
			DecideConfig{EntropyThresholdBits: 4.5},
			DecideConfig{MinEvents: 10, MinDistinctValues: 5, EntropyThresholdBits: 4.5},
		},
		{
			"all set",
			DecideConfig{MinEvents: 20, MinDistinctValues: 6, EntropyThresholdBits: 2.5},
			DecideConfig{MinEvents: 20, MinDistinctValues: 6, EntropyThresholdBits: 2.5},
		},
		{
			"negatives pass through",
			DecideConfig{MinEvents: -1, MinDistinctValues: -2, EntropyThresholdBits: -3},
			DecideConfig{MinEvents: -1, MinDistinctValues: -2, EntropyThresholdBits: -3},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.in.Resolved()
			if got.MinEvents != tt.want.MinEvents ||
				got.MinDistinctValues != tt.want.MinDistinctValues ||
				got.EntropyThresholdBits != tt.want.EntropyThresholdBits {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestDecideConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     DecideConfig
		wantErr bool
	}{
		{"defaults ok", DefaultDecideConfig(), false},
		{"zeroes ok (treated as defaults at apply-time)", DecideConfig{}, false},
		{"max entropy ok", DecideConfig{EntropyThresholdBits: EntropyThresholdMaxBits}, false},
		{"high entropy reasonable", DecideConfig{EntropyThresholdBits: 5.5}, false},
		{"neg min_events", DecideConfig{MinEvents: -1}, true},
		{"neg min_distinct", DecideConfig{MinDistinctValues: -1}, true},
		{"neg entropy", DecideConfig{EntropyThresholdBits: -0.1}, true},
		{"entropy above max", DecideConfig{EntropyThresholdBits: 8.1}, true},
		{"entropy way above max", DecideConfig{EntropyThresholdBits: 30}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("got err=%v, wantErr=%v", err, tt.wantErr)
			}
			if tt.wantErr && !errors.Is(err, ErrInvalidDecideConfig) {
				t.Fatalf("got %v, want errors.Is ErrInvalidDecideConfig", err)
			}
		})
	}
}

// ---------- Decide: gate matrix ----------

// makeUniformObs builds a SegmentObservation list at a given index,
// distinct count, and per-value event count. Values are numbered
// "v000", "v001", ... so they don't collide with reserved or sibling
// names.
func makeUniformObs(index, distinct, perValue int) []SegmentObservation {
	out := make([]SegmentObservation, 0, distinct)
	for i := 0; i < distinct; i++ {
		out = append(out, SegmentObservation{
			Index:      index,
			Value:      fmt.Sprintf("v%03d", i),
			EventCount: perValue,
		})
	}
	return out
}

func TestDecide_AllFiveGatesPassYieldsCollapse(t *testing.T) {
	// Index 1 = "/repos" everywhere (single distinct value -> retain).
	// Index 2 = 87 random IDs (high entropy -> collapse).
	obs := []SegmentObservation{}
	for i := 0; i < 100; i++ {
		obs = append(obs, SegmentObservation{Index: 1, Value: testValRepos, EventCount: 1})
	}
	obs = append(obs, makeUniformObs(2, 87, 5)...)

	ev := Decide(obs, DefaultDecideConfig())
	if ev.Algorithm != AlgorithmFrequencyWeightedEntropyV1 {
		t.Errorf("algorithm: got %q, want %q", ev.Algorithm, AlgorithmFrequencyWeightedEntropyV1)
	}
	if len(ev.CollapsedSegments) != 1 {
		t.Fatalf("collapsed: got %d, want 1", len(ev.CollapsedSegments))
	}
	if ev.CollapsedSegments[0].Index != 2 {
		t.Errorf("collapsed index: got %d, want 2", ev.CollapsedSegments[0].Index)
	}
	if ev.CollapsedSegments[0].DistinctValues != 87 {
		t.Errorf("collapsed distinct: got %d, want 87", ev.CollapsedSegments[0].DistinctValues)
	}
	if ev.CollapsedSegments[0].EventCount != 87*5 {
		t.Errorf("collapsed events: got %d, want %d", ev.CollapsedSegments[0].EventCount, 87*5)
	}
	if ev.CollapsedSegments[0].Reason != ReasonHighEntropyIdentifierSegment {
		t.Errorf("collapsed reason: got %q, want %q", ev.CollapsedSegments[0].Reason, ReasonHighEntropyIdentifierSegment)
	}
	if len(ev.RetainedSegments) != 1 {
		t.Fatalf("retained: got %d, want 1", len(ev.RetainedSegments))
	}
	if ev.RetainedSegments[0].Index != 1 {
		t.Errorf("retained index: got %d, want 1", ev.RetainedSegments[0].Index)
	}
	if ev.RetainedSegments[0].Reason != ReasonLowEntropyLiteralSegment {
		t.Errorf("retained reason: got %q, want %q", ev.RetainedSegments[0].Reason, ReasonLowEntropyLiteralSegment)
	}
}

func TestDecide_Gate1_FailsWhenInsufficientEvents(t *testing.T) {
	// 5 distinct values, 1 event each, total 5 < min_events=10.
	obs := makeUniformObs(2, 5, 1)
	ev := Decide(obs, DefaultDecideConfig())
	if len(ev.RetainedSegments) != 1 || ev.RetainedSegments[0].Reason != ReasonInsufficientEvents {
		t.Fatalf("got retained=%v, want one with ReasonInsufficientEvents", ev.RetainedSegments)
	}
	if len(ev.CollapsedSegments) != 0 {
		t.Errorf("collapsed: want 0, got %d", len(ev.CollapsedSegments))
	}
}

func TestDecide_Gate2_FailsWhenInsufficientDistinct(t *testing.T) {
	// 4 distinct values, 10 events each (total=40, passes gate 1), but
	// distinct=4 < min_distinct=5.
	obs := makeUniformObs(2, 4, 10)
	ev := Decide(obs, DefaultDecideConfig())
	if len(ev.RetainedSegments) != 1 || ev.RetainedSegments[0].Reason != ReasonInsufficientDistinct {
		t.Fatalf("got retained=%v, want one with ReasonInsufficientDistinct", ev.RetainedSegments)
	}
}

func TestDecide_Gate2_FailsWithSingleValue(t *testing.T) {
	// 1 distinct value, 1000 events. Should retain with
	// LowEntropyLiteralSegment, not InsufficientDistinct, because
	// "single literal" is the audit-friendly framing.
	obs := []SegmentObservation{{Index: 1, Value: testValRepos, EventCount: 1000}}
	ev := Decide(obs, DefaultDecideConfig())
	if len(ev.RetainedSegments) != 1 {
		t.Fatalf("retained: got %d, want 1", len(ev.RetainedSegments))
	}
	if ev.RetainedSegments[0].Reason != ReasonLowEntropyLiteralSegment {
		t.Errorf("reason: got %q, want %q", ev.RetainedSegments[0].Reason, ReasonLowEntropyLiteralSegment)
	}
	if ev.RetainedSegments[0].Value != testValRepos {
		t.Errorf("value: got %q, want %q", ev.RetainedSegments[0].Value, testValRepos)
	}
}

func TestDecide_Gate3_FailsWhenLowEntropy(t *testing.T) {
	// 6 distinct values: 5 of them "foo*" copies (highly skewed) and
	// one outlier. Total events = 5*100 + 1 = 501. Distinct = 6 >= 5.
	// Entropy is dominated by the heavy class, well below 3 bits.
	obs := []SegmentObservation{
		{Index: 2, Value: "foo1", EventCount: 100},
		{Index: 2, Value: "foo2", EventCount: 100},
		{Index: 2, Value: "foo3", EventCount: 100},
		{Index: 2, Value: "foo4", EventCount: 100},
		{Index: 2, Value: "foo5", EventCount: 100},
		{Index: 2, Value: "outlier", EventCount: 1},
	}
	ev := Decide(obs, DefaultDecideConfig())
	if len(ev.CollapsedSegments) != 0 {
		t.Errorf("collapsed: want 0, got %d", len(ev.CollapsedSegments))
	}
	if len(ev.RetainedSegments) != 1 || ev.RetainedSegments[0].Reason != ReasonLowEntropyLiteralSegment {
		t.Fatalf("retained=%v, want LowEntropyLiteralSegment", ev.RetainedSegments)
	}
}

func TestDecide_Gate4_ReservedSegmentBlocksCollapse(t *testing.T) {
	// 87 high-entropy values at index 2 PLUS one reserved "admin"
	// value. The whole position must retain because the reserved
	// floor wins.
	obs := makeUniformObs(2, 87, 5)
	obs = append(obs, SegmentObservation{Index: 2, Value: testValAdmin, EventCount: 5})
	ev := Decide(obs, DefaultDecideConfig())
	if len(ev.CollapsedSegments) != 0 {
		t.Errorf("collapsed: want 0, got %d", len(ev.CollapsedSegments))
	}
	if len(ev.RetainedSegments) != 1 || ev.RetainedSegments[0].Reason != ReasonReservedSegment {
		t.Fatalf("retained=%v, want ReservedSegment", ev.RetainedSegments)
	}
	if ev.RetainedSegments[0].Value != testValAdmin {
		t.Errorf("value: got %q, want %q", ev.RetainedSegments[0].Value, testValAdmin)
	}
}

func TestDecide_Gate4_ExtrasReservedAlsoBlocks(t *testing.T) {
	// 87 high-entropy values + "debug" at index 2. "debug" is not in
	// the canonical list, but the extras list should catch it.
	obs := makeUniformObs(2, 87, 5)
	obs = append(obs, SegmentObservation{Index: 2, Value: testValDebug, EventCount: 5})
	cfg := DefaultDecideConfig()
	cfg.ReservedExtras = []string{testValDebug}
	ev := Decide(obs, cfg)
	if len(ev.CollapsedSegments) != 0 {
		t.Errorf("collapsed: want 0, got %d", len(ev.CollapsedSegments))
	}
	if len(ev.RetainedSegments) != 1 || ev.RetainedSegments[0].Reason != ReasonReservedSegment {
		t.Fatalf("retained=%v, want ReservedSegment", ev.RetainedSegments)
	}
	if ev.RetainedSegments[0].Value != testValDebug {
		t.Errorf("value: got %q, want %q", ev.RetainedSegments[0].Value, testValDebug)
	}
}

func TestDecide_Gate5_HighRiskSiblingBlocksCollapse(t *testing.T) {
	// "users" and "admin" at the same index. Both are reserved AND
	// sibling, but reserved is checked first; we use a non-reserved
	// sibling list here to isolate gate 5.
	obs := []SegmentObservation{
		{Index: 2, Value: "alpha", EventCount: 50},
		{Index: 2, Value: "beta", EventCount: 50},
		{Index: 2, Value: "gamma", EventCount: 50},
		{Index: 2, Value: "delta", EventCount: 50},
		{Index: 2, Value: "epsilon", EventCount: 50},
		{Index: 2, Value: "premium", EventCount: 50}, // sibling
	}
	cfg := DefaultDecideConfig()
	cfg.HighRiskSiblings = []string{"premium", "vip"}
	ev := Decide(obs, cfg)
	if len(ev.CollapsedSegments) != 0 {
		t.Errorf("collapsed: want 0, got %d", len(ev.CollapsedSegments))
	}
	if len(ev.RetainedSegments) != 1 || ev.RetainedSegments[0].Reason != ReasonNoMergeRule {
		t.Fatalf("retained=%v, want NoMergeRule", ev.RetainedSegments)
	}
	if ev.RetainedSegments[0].Value != "premium" {
		t.Errorf("value: got %q, want premium", ev.RetainedSegments[0].Value)
	}
}

func TestDecide_DeterministicEvidenceOrder(t *testing.T) {
	// Build observations with two collapsable positions (3 and 5) and
	// two retainable positions (1 and 4). Expect ascending Index in
	// each output slice on every call.
	obs := []SegmentObservation{}
	// idx 5 first in the slice — but emission must still be sorted.
	obs = append(obs, makeUniformObs(5, 87, 5)...)
	for i := 0; i < 100; i++ {
		obs = append(obs, SegmentObservation{Index: 1, Value: "v1", EventCount: 1})
	}
	obs = append(obs, makeUniformObs(3, 87, 5)...)
	for i := 0; i < 100; i++ {
		obs = append(obs, SegmentObservation{Index: 4, Value: "v4", EventCount: 1})
	}

	ev1 := Decide(obs, DefaultDecideConfig())
	ev2 := Decide(obs, DefaultDecideConfig())

	// Compare slice-by-slice: we want the Decide output to be byte-
	// identical for identical input.
	if len(ev1.CollapsedSegments) != len(ev2.CollapsedSegments) {
		t.Fatalf("collapsed len drift: %d vs %d", len(ev1.CollapsedSegments), len(ev2.CollapsedSegments))
	}
	for i := range ev1.CollapsedSegments {
		if ev1.CollapsedSegments[i] != ev2.CollapsedSegments[i] {
			t.Errorf("collapsed[%d]: %+v vs %+v", i, ev1.CollapsedSegments[i], ev2.CollapsedSegments[i])
		}
	}
	if len(ev1.RetainedSegments) != len(ev2.RetainedSegments) {
		t.Fatalf("retained len drift")
	}
	for i := range ev1.RetainedSegments {
		if ev1.RetainedSegments[i] != ev2.RetainedSegments[i] {
			t.Errorf("retained[%d]: %+v vs %+v", i, ev1.RetainedSegments[i], ev2.RetainedSegments[i])
		}
	}

	// And ascending order assertions.
	for i := 1; i < len(ev1.CollapsedSegments); i++ {
		if ev1.CollapsedSegments[i].Index <= ev1.CollapsedSegments[i-1].Index {
			t.Errorf("collapsed not ascending at %d", i)
		}
	}
	for i := 1; i < len(ev1.RetainedSegments); i++ {
		if ev1.RetainedSegments[i].Index <= ev1.RetainedSegments[i-1].Index {
			t.Errorf("retained not ascending at %d", i)
		}
	}
}

func TestDecide_EmptyInputReturnsEmptyEvidence(t *testing.T) {
	ev := Decide(nil, DefaultDecideConfig())
	if ev.Algorithm != AlgorithmFrequencyWeightedEntropyV1 {
		t.Errorf("algorithm: got %q", ev.Algorithm)
	}
	if len(ev.CollapsedSegments) != 0 || len(ev.RetainedSegments) != 0 {
		t.Errorf("non-empty evidence on nil input: %+v", ev)
	}
	ev2 := Decide([]SegmentObservation{}, DefaultDecideConfig())
	if ev2.Algorithm != AlgorithmFrequencyWeightedEntropyV1 {
		t.Errorf("algorithm: got %q", ev2.Algorithm)
	}
	if len(ev2.CollapsedSegments) != 0 || len(ev2.RetainedSegments) != 0 {
		t.Errorf("non-empty evidence on empty slice: %+v", ev2)
	}
}

func TestDecide_NonPositiveCountsIgnored(t *testing.T) {
	// Zero-count and negative-count observations should be skipped
	// without panic and without polluting the aggregate.
	obs := []SegmentObservation{
		{Index: 1, Value: "real", EventCount: 100},
		{Index: 1, Value: "ghost", EventCount: 0},
		{Index: 1, Value: "neg", EventCount: -50},
	}
	ev := Decide(obs, DefaultDecideConfig())
	// Only one real value at index 1 -> retain low-entropy.
	if len(ev.RetainedSegments) != 1 {
		t.Fatalf("retained: got %d, want 1", len(ev.RetainedSegments))
	}
	if ev.RetainedSegments[0].Value != "real" {
		t.Errorf("value: got %q, want real", ev.RetainedSegments[0].Value)
	}
}

func TestDecide_NegativeIndexIgnored(t *testing.T) {
	// Defensive: caller's bug shouldn't crash us, but should also
	// not produce evidence for the bad position.
	obs := []SegmentObservation{
		{Index: 0, Value: "bad", EventCount: 100},
		{Index: -1, Value: "worse", EventCount: 100},
	}
	ev := Decide(obs, DefaultDecideConfig())
	if len(ev.RetainedSegments) != 0 || len(ev.CollapsedSegments) != 0 {
		t.Errorf("non-empty evidence on bad-index input: %+v", ev)
	}
}

func TestDecide_ResolvesZeroConfig(t *testing.T) {
	// A zero-value DecideConfig should behave like the defaults.
	obs := makeUniformObs(2, 87, 5)
	ev := Decide(obs, DecideConfig{})
	if len(ev.CollapsedSegments) != 1 {
		t.Fatalf("zero cfg should collapse high-entropy: got %+v", ev)
	}
}

// ---------- Adversarial corpus ----------

func TestDecide_AdversarialCorpus_AdminCannotCollapse(t *testing.T) {
	// 100 random siblings + one "admin". Even with overwhelming
	// random entropy, the reserved floor must hold.
	obs := makeUniformObs(2, 100, 5)
	obs = append(obs, SegmentObservation{Index: 2, Value: testValAdmin, EventCount: 1})
	ev := Decide(obs, DefaultDecideConfig())
	if len(ev.CollapsedSegments) != 0 {
		t.Errorf("collapsed: want 0, got %d", len(ev.CollapsedSegments))
	}
	if len(ev.RetainedSegments) != 1 || ev.RetainedSegments[0].Reason != ReasonReservedSegment {
		t.Fatalf("retained=%v, want ReservedSegment", ev.RetainedSegments)
	}
	if ev.RetainedSegments[0].Value != testValAdmin {
		t.Errorf("value: got %q, want %q", ev.RetainedSegments[0].Value, testValAdmin)
	}
}

func TestDecide_AdversarialCorpus_HighEntropyDoesNotForceCollapse(t *testing.T) {
	// 1000 distinct values + "auth". Reserved-segment-presence is
	// position-level, so the entire position retains.
	obs := makeUniformObs(2, 1000, 2)
	obs = append(obs, SegmentObservation{Index: 2, Value: testValAuth, EventCount: 2})
	ev := Decide(obs, DefaultDecideConfig())
	if len(ev.CollapsedSegments) != 0 {
		t.Errorf("collapsed: want 0, got %d", len(ev.CollapsedSegments))
	}
	if len(ev.RetainedSegments) != 1 || ev.RetainedSegments[0].Reason != ReasonReservedSegment {
		t.Fatalf("retained=%v, want ReservedSegment", ev.RetainedSegments)
	}
	if ev.RetainedSegments[0].Value != testValAuth {
		t.Errorf("value: got %q, want %q", ev.RetainedSegments[0].Value, testValAuth)
	}
}

func TestRepresentativeValue_EmptyCountsReturnsEmpty(t *testing.T) {
	// White-box: representativeValue is unreachable from the public
	// API with empty counts (Decide filters), but the defensive
	// guard exists to protect downstream code from a panic on
	// empty slices. Test it directly.
	if got := representativeValue(map[string]int{}); got != "" {
		t.Errorf("got %q, want \"\"", got)
	}
}

func TestFirstReservedValue_NoMatchReturnsEmpty(t *testing.T) {
	// White-box: a non-empty counts map with no reserved hits.
	got := firstReservedValue(map[string]int{"alpha": 1, "beta": 2}, nil)
	if got != "" {
		t.Errorf("got %q, want \"\"", got)
	}
}

func TestDecide_HighRiskSiblings_NoMatchAllowsCollapse(t *testing.T) {
	// HighRiskSiblings is set but none of the values match.
	// Decide should still collapse because gate 5 doesn't fire.
	// Exercises the firstSiblingValue branch where siblings is
	// non-empty but no match is found.
	obs := makeUniformObs(2, 87, 5)
	cfg := DefaultDecideConfig()
	cfg.HighRiskSiblings = []string{"unicorn", "phoenix"}
	ev := Decide(obs, cfg)
	if len(ev.CollapsedSegments) != 1 {
		t.Fatalf("collapsed: got %d, want 1 (siblings list is non-empty but none match)", len(ev.CollapsedSegments))
	}
}

func TestDecide_AdversarialCorpus_UsersAndAdminCannotMerge(t *testing.T) {
	// /v1/admin and /v1/users at index 2: the design's high-risk
	// sibling case. With both as siblings, the position retains.
	// Note: both are also in the canonical reserved list, so this
	// passes via the reserved path. We assert that retain happens
	// regardless of which gate fires first.
	obs := []SegmentObservation{
		{Index: 2, Value: testValAdmin, EventCount: 100},
		{Index: 2, Value: testValUsers, EventCount: 100},
	}
	cfg := DefaultDecideConfig()
	cfg.HighRiskSiblings = []string{testValAdmin, testValUsers}
	ev := Decide(obs, cfg)
	if len(ev.CollapsedSegments) != 0 {
		t.Errorf("collapsed: want 0, got %d", len(ev.CollapsedSegments))
	}
	if len(ev.RetainedSegments) != 1 {
		t.Fatalf("retained: got %d, want 1", len(ev.RetainedSegments))
	}
	if ev.RetainedSegments[0].Reason != ReasonReservedSegment && ev.RetainedSegments[0].Reason != ReasonNoMergeRule {
		t.Errorf("reason: got %q, want one of {%q, %q}", ev.RetainedSegments[0].Reason, ReasonReservedSegment, ReasonNoMergeRule)
	}
}
