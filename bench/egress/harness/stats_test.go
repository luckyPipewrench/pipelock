package harness

import (
	"testing"
	"time"
)

func TestSummarize_Empty(t *testing.T) {
	t.Parallel()
	got := Summarize(nil)
	if got.N != 0 {
		t.Errorf("empty: N=%d, want 0", got.N)
	}
	if got.Mean != 0 || got.P50 != 0 || got.P95 != 0 || got.P99 != 0 {
		t.Errorf("empty: nonzero stats %+v", got)
	}
}

func TestSummarize_SingleSample(t *testing.T) {
	t.Parallel()
	got := Summarize([]time.Duration{42 * time.Millisecond})
	if got.N != 1 {
		t.Errorf("N=%d, want 1", got.N)
	}
	want := 42 * time.Millisecond
	if got.Mean != want || got.P50 != want || got.P95 != want || got.P99 != want {
		t.Errorf("single sample: %+v, want all %v", got, want)
	}
	if got.StdDev != 0 {
		t.Errorf("StdDev=%v, want 0 for single sample", got.StdDev)
	}
}

func TestSummarize_Percentiles(t *testing.T) {
	t.Parallel()
	// 100 samples: 1ns, 2ns, ..., 100ns.
	samples := make([]time.Duration, 100)
	for i := range samples {
		samples[i] = time.Duration(i + 1)
	}
	got := Summarize(samples)
	cases := []struct {
		label string
		have  time.Duration
		want  time.Duration
	}{
		{"min", got.Min, 1},
		{"max", got.Max, 100},
		// nearest-rank: ceil(p/100 * n) -> p50=50, p95=95, p99=99
		{"p50", got.P50, 50},
		{"p95", got.P95, 95},
		{"p99", got.P99, 99},
	}
	for _, tc := range cases {
		if tc.have != tc.want {
			t.Errorf("%s: have %v, want %v", tc.label, tc.have, tc.want)
		}
	}
}

func TestSummarize_MonotonicallyOrderedPercentiles(t *testing.T) {
	t.Parallel()
	// Property: p50 <= p95 <= p99 for any non-trivial distribution.
	samples := []time.Duration{
		5, 1, 9, 3, 7, 2, 4, 8, 6, 10,
		50, 20, 80, 30, 60, 40, 70, 90, 100, 25,
	}
	got := Summarize(samples)
	if got.P50 > got.P95 || got.P95 > got.P99 {
		t.Errorf("ordering broken: p50=%v p95=%v p99=%v", got.P50, got.P95, got.P99)
	}
	if got.Min > got.P50 {
		t.Errorf("min %v > p50 %v", got.Min, got.P50)
	}
	if got.P99 > got.Max {
		t.Errorf("p99 %v > max %v", got.P99, got.Max)
	}
}

func TestNearestRank_Edges(t *testing.T) {
	t.Parallel()
	sorted := []time.Duration{10, 20, 30}
	cases := []struct {
		p    int
		want time.Duration
	}{
		{0, 10},   // clamps to first element
		{1, 10},   // ceil(0.01*3)=1 -> first
		{50, 20},  // ceil(0.5*3)=2 -> second
		{99, 30},  // ceil(0.99*3)=3 -> third
		{100, 30}, // last
	}
	for _, tc := range cases {
		got := nearestRank(sorted, tc.p)
		if got != tc.want {
			t.Errorf("p=%d: got %v, want %v", tc.p, got, tc.want)
		}
	}
}

func TestNearestRank_EmptySlice(t *testing.T) {
	t.Parallel()
	if got := nearestRank(nil, 50); got != 0 {
		t.Errorf("empty slice: got %v, want 0", got)
	}
}

func TestSqrt(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   float64
		want float64
	}{
		{0, 0},
		{-1, 0}, // sentinel: negative inputs return 0
		{1, 1},
		{4, 2},
		{9, 3},
		{100, 10},
	}
	for _, tc := range cases {
		got := sqrt(tc.in)
		if abs(got-tc.want) > 1e-9 {
			t.Errorf("sqrt(%v)=%v, want %v", tc.in, got, tc.want)
		}
	}
}

func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}
