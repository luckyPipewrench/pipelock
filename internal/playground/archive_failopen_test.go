// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground_test

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/playground"
)

// Archive mode must never report a run VALID without a root-signed archive
// authorization, whatever shape the run takes. Two independent gaps combined to
// break that for a contained run signed directly by the root: the containment
// branch rebuilt the required-check set from the base list and dropped the
// archive check, and the no-delegation path never recorded that check at all.
// Either one alone is caught -- the required set fails a missing check, and the
// delegated path records the failure explicitly -- so only the pair fails open,
// and every real playground run is contained.
func TestVerifyArchivedReplay_ContainedDirectRootRunIsNotAuthorized(t *testing.T) {
	dir, pubHex, _ := buildRunDir(t, true)

	rep, err := playground.VerifyArchivedReplay(dir, pubHex)
	if err != nil {
		t.Fatalf("VerifyArchivedReplay: %v", err)
	}
	if rep.OK {
		t.Fatal("a run carrying no replay archive authorization was reported VALID in archive mode")
	}

	var archiveCheck *playground.Check
	for i := range rep.Checks {
		if rep.Checks[i].Name == "replay-archive-authorization" {
			archiveCheck = &rep.Checks[i]
			break
		}
	}
	if archiveCheck == nil {
		t.Fatal("archive mode recorded no replay-archive-authorization check at all")
	}
	if archiveCheck.OK {
		t.Fatalf("replay-archive-authorization passed without an authorization: %s", archiveCheck.Reason)
	}

	// Control: the same run still verifies in strict mode, so the refusal above
	// comes from the missing authorization and not from a broken fixture.
	strict, err := playground.VerifyRun(dir, pubHex)
	if err != nil {
		t.Fatalf("VerifyRun: %v", err)
	}
	if !strict.OK {
		t.Fatalf("the fixture does not verify in strict mode: %+v", strict.Checks)
	}
}
