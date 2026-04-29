// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package compile

// IntToUint64 converts non-negative counters to uint64 and clamps negative
// defensive values to zero before writing unsigned wire fields.
func IntToUint64(v int) uint64 {
	if v <= 0 {
		return 0
	}
	return uint64(v)
}
