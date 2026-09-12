// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestFragmentBuffer_DerivedOwnershipCheckedBeforeAdmission(t *testing.T) {
	sc := MustNew(config.Defaults())
	t.Cleanup(sc.Close)
	ctx := context.Background()
	owner := testCEEIdentity("owner")
	foreign := testCEEIdentity("foreign")
	stream := owner.Stream("|raw")
	for _, operation := range []string{"append", "append and scan", "path", "path and scan"} {
		for _, candidate := range []struct {
			name    string
			foreign bool
		}{{name: "rightful owner"}, {name: "foreign owner", foreign: true}} {
			t.Run(operation+"/"+candidate.name, func(t *testing.T) {
				fb := NewFragmentBuffer(64, 2, testWindowSecs)
				t.Cleanup(fb.Close)
				appendOwner := owner
				if candidate.foreign {
					appendOwner = foreign
				}
				var result FragmentAppendResult
				switch operation {
				case "append":
					result = fb.AppendOwnedInGroup(appendOwner, stream, stream, []byte("ordinary"))
				case "append and scan":
					result, _ = fb.AppendAndScanOwnedInGroup(ctx, appendOwner, stream, stream, []byte("ordinary"), sc)
				case "path":
					result = fb.AppendPathSegmentsOwned(appendOwner, stream, [][]byte{[]byte("ordinary")})
				case "path and scan":
					result, _ = fb.AppendAndScanPathSegmentsOwned(ctx, appendOwner, stream, [][]byte{[]byte("ordinary")}, sc)
				}
				if result.OwnerMismatch != candidate.foreign {
					t.Fatalf("result=%+v wantOwnerMismatch=%v", result, candidate.foreign)
				}
				if candidate.foreign && fb.TotalBufferBytes() != 0 {
					t.Fatal("rejected identity created retained state")
				}
			})
		}
	}
	for _, scan := range []bool{false, true} {
		fb := NewFragmentBuffer(64, 2, testWindowSecs)
		t.Cleanup(fb.Close)
		var result FragmentAppendResult
		if scan {
			result, _ = fb.AppendAndScanOwnedInGroup(ctx, owner, foreign.Stream("|group"), stream, []byte("ordinary"), sc)
		} else {
			result = fb.AppendOwnedInGroup(owner, foreign.Stream("|group"), stream, []byte("ordinary"))
		}
		if !result.OwnerMismatch || fb.TotalBufferBytes() != 0 {
			t.Fatalf("foreign group admitted: scan=%v result=%+v", scan, result)
		}
	}
}
