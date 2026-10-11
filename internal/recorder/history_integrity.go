// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import "fmt"

// VerifySessionHistoryChain verifies the recorder chain across every shard,
// including entries outside the signed receipt subsequence. Call inside a
// WithSessionHistorySnapshot when combining this result with other reads.
// It detects observed breaks, not a missing tail without an external anchor.
func VerifySessionHistoryChain(location EvidenceLocation, session string) error {
	var chain ChainWalker
	if err := WalkSessionHistoryResolved(location, session, chain.Add); err != nil {
		return fmt.Errorf("recorder entry hash chain: %w", err)
	}
	return nil
}
