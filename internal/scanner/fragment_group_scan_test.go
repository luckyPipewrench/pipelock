// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"strings"
	"sync"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/identitykey"
)

func TestFragmentBuffer_RequestBatchPreservesCompletingFields(t *testing.T) {
	cfg, err := config.LoadBytes([]byte("dlp:\n  patterns:\n    - name: Boundary token\n      regex: 'CTOK[A-Z]{12}'\n      severity: high\n"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Internal = nil
	sc := MustNew(cfg)
	defer sc.Close()
	owner := testCEEIdentity(testSessionA)
	group, target, padding := owner.Stream("group"), owner.Stream("target"), owner.Stream("padding")
	for _, withPadding := range []bool{false, true} {
		t.Run(map[bool]string{false: "positive-control", true: "earlier-field"}[withPadding], func(t *testing.T) {
			fb := NewFragmentBuffer(65536, 10, testWindowSecs)
			defer fb.Close()
			_, _ = fb.AppendAndScanOwnedInGroup(t.Context(), owner, group, target, []byte(strings.Repeat("x", 40000)+"CTOKBBBB"), sc)
			var appends []FragmentAppend
			if withPadding {
				appends = append(appends, FragmentAppend{Group: group, Stream: padding, Payload: []byte(strings.Repeat("x", 40000))})
			}
			appends = append(appends, FragmentAppend{Group: group, Stream: target, Payload: []byte("BBBBBBBB")})
			result, matches := fb.AppendAndScanOwnedBatch(t.Context(), owner, appends, sc)
			if result != (FragmentAppendResult{}) || len(matches) != len(appends) || len(matches[len(matches)-1]) != 1 {
				t.Fatalf("completing field lost its evidence: result=%+v matches=%v", result, matches)
			}
			if fb.TotalBufferBytes() > 65536 {
				t.Fatal("batch exceeded retained group budget")
			}
		})
	}
}

func TestFragmentBuffer_RequestBatchAdmission(t *testing.T) {
	owner, foreign := testCEEIdentity(testSessionA), testCEEIdentity(testSessionB)
	for _, foreignGroup := range []bool{false, true} {
		t.Run(map[bool]string{false: "foreign-stream", true: "foreign-group"}[foreignGroup], func(t *testing.T) {
			fb := NewFragmentBuffer(64, 1, testWindowSecs)
			t.Cleanup(fb.Close)
			bad := FragmentAppend{Group: owner.Stream("group"), Stream: foreign.Stream("stream"), Payload: []byte("bad")}
			if foreignGroup {
				bad.Group, bad.Stream = foreign.Stream("group"), owner.Stream("stream")
			}
			good := FragmentAppend{Group: owner.Stream("group"), Stream: owner.Stream("stream"), Payload: []byte("good")}
			result, matches := fb.AppendAndScanOwnedBatch(t.Context(), owner, []FragmentAppend{good, bad}, nil)
			if !result.OwnerMismatch || len(matches) != 0 || fb.TotalBufferBytes() != 0 {
				t.Fatalf("foreign batch admitted state: %+v, %v, bytes=%d", result, matches, fb.TotalBufferBytes())
			}
			if result, _ = fb.AppendAndScanOwnedBatch(t.Context(), owner, []FragmentAppend{good}, nil); result != (FragmentAppendResult{}) {
				t.Fatalf("rightful admission failed: %+v", result)
			}
			other := FragmentAppend{Group: foreign.Stream("group"), Stream: foreign.Stream("stream"), Payload: []byte("other")}
			if result, matches = fb.AppendAndScanOwnedBatch(t.Context(), foreign, []FragmentAppend{other}, nil); !result.CapacityExceeded || len(matches) != 0 {
				t.Fatalf("capacity failure reported success: %+v, %v", result, matches)
			}
			if result, matches = fb.AppendAndScanOwnedBatch(t.Context(), owner, nil, nil); result != (FragmentAppendResult{}) || len(matches) != 0 {
				t.Fatalf("empty batch result: %+v, %v", result, matches)
			}
		})
	}
}

func TestFragmentBuffer_RequestBatchConcurrentRetention(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	fb := NewFragmentBuffer(64, 10, testWindowSecs)
	t.Cleanup(fb.Close)
	owner := testCEEIdentity(testSessionA)
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			for range 16 {
				result, matches := fb.AppendAndScanOwnedBatch(t.Context(), owner, []FragmentAppend{
					{Group: owner.Stream("group"), Stream: owner.Stream("first"), Payload: []byte(strings.Repeat("x", 48))},
					{Group: owner.Stream("group"), Stream: owner.Stream("second"), Payload: []byte(strings.Repeat("y", 48))},
				}, sc)
				if result != (FragmentAppendResult{}) || len(matches) != 2 {
					t.Errorf("concurrent batch: %+v, %v", result, matches)
				}
			}
		})
	}
	workers.Wait()
	if retained := fb.TotalBufferBytes(); retained > 64 {
		t.Fatalf("retained %d bytes, limit 64", retained)
	}
}

func TestFragmentBuffer_RequestBatchCollisionDoesNotPrimeState(t *testing.T) {
	fb := NewFragmentBuffer(64, 2, testWindowSecs)
	t.Cleanup(fb.Close)
	foreign := identitykey.NewMCPCEEIdentity("owner-x")
	owner := identitykey.NewMCPCEEIdentity("owner")
	if result := fb.AppendOwned(foreign, foreign.Stream(""), []byte("existing")); result != (FragmentAppendResult{}) {
		t.Fatal(result)
	}
	if owner.Stream("-x").Key() != foreign.Stream("").Key() {
		t.Fatal("collision fixture no longer collides")
	}
	before := fb.TotalBufferBytes()
	result, matches := fb.AppendAndScanOwnedBatch(t.Context(), owner, []FragmentAppend{
		{Group: owner.Stream("group"), Stream: owner.Stream("ok"), Payload: []byte("must not persist")},
		{Group: owner.Stream("group"), Stream: owner.Stream("-x"), Payload: []byte("rejected")},
	}, nil)
	if !result.OwnerMismatch || len(matches) != 0 || fb.TotalBufferBytes() != before {
		t.Fatalf("rejected batch primed state: %+v, matches=%v, bytes=%d want %d", result, matches, fb.TotalBufferBytes(), before)
	}
}
