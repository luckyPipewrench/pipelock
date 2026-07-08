// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

// PreviousChainSeq returns seq-1, clamped to 0 for a segment genesis.
func PreviousChainSeq(seq uint64) uint64 {
	if seq == 0 {
		return 0
	}
	return seq - 1
}
