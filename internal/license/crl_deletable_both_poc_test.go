// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package license

import (
	"os"
	"testing"
)

// TestPoC_CRLHighWaterDeleteBothFilesReplays is the flipped round-3 regression:
// deleting the primary and secondary high-water records while the CRL context
// marker remains must fail closed instead of resetting to first-run.
func TestPoC_CRLHighWaterDeleteBothFilesReplays(t *testing.T) {
	dir := t.TempDir()
	crlFile := dir + "/crl.json"

	// 1. We have accepted a CRL at generation 5 (e.g. it revokes a license).
	if _, err := AdvanceCRLHighWater(crlFile, 5); err != nil {
		t.Fatalf("seed floor=5: %v", err)
	}

	// 2. The floor protects: an older CRL (gen 2, pre-revocation) is rejected.
	if _, err := AdvanceCRLHighWater(crlFile, 2); err == nil {
		t.Fatal("baseline: floor=5 should reject generation 2 (rollback)")
	}

	// 3. Attacker with write access to the state dir deletes BOTH value records.
	if err := os.Remove(CRLHighWaterPath(crlFile)); err != nil {
		t.Fatalf("remove primary: %v", err)
	}
	if err := os.Remove(CRLHighWaterAnchorPath(crlFile)); err != nil {
		t.Fatalf("remove anchor: %v", err)
	}

	// 4. Replay the older CRL (gen 2). The context marker proves this is not a
	// genuine first-run, so the missing floor must fail closed.
	if _, err := AdvanceCRLHighWater(crlFile, 2); err == nil {
		t.Fatal("delete-both CRL high-water replay succeeded; want fail-closed rejection")
	}
}
