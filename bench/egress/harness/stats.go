// Package harness implements the egress-overhead benchmark harness. It drives
// traffic through five transports (HTTP, SSE, tool-chain, MCP stdio,
// WebSocket) both directly against in-process mocks and through a running
// pipelock instance, and emits machine-readable JSON.
package harness

import (
	"sort"
	"time"
)

// Stats holds aggregated timing measurements for a single transport-mode pair.
type Stats struct {
	N      int           `json:"n"`
	Mean   time.Duration `json:"mean_ns"`
	P50    time.Duration `json:"p50_ns"`
	P95    time.Duration `json:"p95_ns"`
	P99    time.Duration `json:"p99_ns"`
	Min    time.Duration `json:"min_ns"`
	Max    time.Duration `json:"max_ns"`
	StdDev time.Duration `json:"stddev_ns"`
}

// Summarize computes percentiles from a slice of durations.
//
// The slice is sorted in place. Percentile selection uses the
// nearest-rank method (NIST), which is robust for the modest sample
// sizes the bench uses (1000-10000) and avoids interpolation surprises.
func Summarize(samples []time.Duration) Stats {
	if len(samples) == 0 {
		return Stats{}
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	var sum int64
	for _, s := range samples {
		sum += int64(s)
	}
	mean := time.Duration(sum / int64(len(samples)))
	var sqdiff float64
	for _, s := range samples {
		d := float64(int64(s) - int64(mean))
		sqdiff += d * d
	}
	stddev := time.Duration(0)
	if len(samples) > 1 {
		stddev = time.Duration(sqrt(sqdiff / float64(len(samples)-1)))
	}
	return Stats{
		N:      len(samples),
		Mean:   mean,
		P50:    nearestRank(samples, 50),
		P95:    nearestRank(samples, 95),
		P99:    nearestRank(samples, 99),
		Min:    samples[0],
		Max:    samples[len(samples)-1],
		StdDev: stddev,
	}
}

// nearestRank returns the percentile p (0-100) of a pre-sorted samples slice.
// It uses ceil(p/100 * n) - 1 (NIST nearest-rank), clamped to [0, n-1].
func nearestRank(sorted []time.Duration, p int) time.Duration {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	// Multiply before dividing to avoid float drift on small N.
	idx := (p*n + 99) / 100
	if idx < 1 {
		idx = 1
	}
	if idx > n {
		idx = n
	}
	return sorted[idx-1]
}

// sqrt is a tiny Newton-Raphson sqrt to avoid pulling in math/cmplx-shaped
// imports purely for one float operation. Sufficient for stddev reporting.
func sqrt(x float64) float64 {
	if x <= 0 {
		return 0
	}
	z := x
	for i := 0; i < 16; i++ {
		z = (z + x/z) / 2
	}
	return z
}
