// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package tools

// testRNG is a small deterministic generator (splitmix64) for reproducible
// test corpora and schedules. It is not used for anything security-relevant.
type testRNG struct{ state uint64 }

func newTestRNG(seed, stream uint64) *testRNG {
	return &testRNG{state: seed*0x9E3779B97F4A7C15 ^ stream}
}

func (r *testRNG) next() uint64 {
	r.state += 0x9E3779B97F4A7C15
	z := r.state
	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
	z = (z ^ (z >> 27)) * 0x94D049BB133111EB
	return z ^ (z >> 31)
}

// IntN returns a value in [0, n). The slight modulo bias does not matter for
// test corpora.
func (r *testRNG) IntN(n int) int {
	if n <= 0 {
		return 0
	}
	// Reduce the 64 random bits modulo n one bit at a time, in int
	// arithmetic, so no conversion between signed and unsigned is needed.
	v := r.next()
	res := 0
	for i := 63; i >= 0; i-- {
		res = 2 * res % n
		if v>>uint(i)&1 == 1 {
			res = (res + 1) % n
		}
	}
	return res
}

// Shuffle permutes n elements with Fisher-Yates.
func (r *testRNG) Shuffle(n int, swap func(i, j int)) {
	for i := n - 1; i > 0; i-- {
		swap(i, r.IntN(i+1))
	}
}
