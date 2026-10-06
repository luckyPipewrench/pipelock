// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package anchor

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func preflightHex(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(sum[:])
}

// preflightMarker is a recorded anchor-state marker with no signer, so its
// coverage is its final sequence plus one.
func preflightMarker(session string, finalSeq uint64, root string) StateMarker {
	return StateMarker{
		Schema:       stateMarkerSchema,
		SessionID:    session,
		FinalSeq:     finalSeq,
		RootHash:     preflightHex(root),
		Backend:      RekorBackend,
		LogIndex:     9,
		AnchoredAt:   time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC),
		BundleSHA256: preflightHex("bundle-" + root),
		BundlePath:   "anchor-" + root + ".json",
	}
}

func preflightCheckpoint(session string, finalSeq uint64, root string) Checkpoint {
	return Checkpoint{SessionID: session, FinalSeq: finalSeq, RootHash: preflightHex(root), ReceiptCount: finalSeq + 1}
}

// PreflightStateMarker must refuse exactly what WriteStateMarker would refuse,
// before anything reaches a remote log. Each case builds the recorded state in
// two directories, asks the preflight on one, then records the same marker in
// the other, and requires the two answers to agree.
func TestPreflightStateMarker_AgreesWithWriteStateMarker(t *testing.T) {
	t.Parallel()
	const session = "proxy.run.0123456789abcdef0123456789abcdef"
	type step struct {
		session string
		seq     uint64
		root    string
	}
	for _, tc := range []struct {
		name       string
		recorded   []step
		next       step
		wantErrHas string
	}{
		{name: "empty state", next: step{session, 4, "a"}},
		{name: "same checkpoint already anchored", recorded: []step{{session, 4, "a"}}, next: step{session, 4, "a"}, wantErrHas: "already anchored"},
		{name: "different root at the same coverage", recorded: []step{{session, 4, "a"}}, next: step{session, 4, "b"}, wantErrHas: "conflicts with latest marker"},
		{name: "newer coverage", recorded: []step{{session, 4, "a"}}, next: step{session, 9, "b"}},
		{name: "older coverage", recorded: []step{{session, 4, "a"}}, next: step{session, 2, "c"}},
		{name: "same coverage in another session", recorded: []step{{session, 4, "a"}}, next: step{"proxy.run.fedcba9876543210fedcba9876543210", 4, "b"}},
		{name: "conflict behind another session's latest pointer", recorded: []step{{session, 4, "a"}, {"other", 1, "z"}}, next: step{session, 4, "b"}, wantErrHas: "conflicts with history"},
		{name: "newer coverage behind another session's latest pointer", recorded: []step{{session, 4, "a"}, {"other", 1, "z"}}, next: step{session, 7, "b"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			build := func(dir string) {
				for _, s := range tc.recorded {
					if err := WriteStateMarker(dir, preflightMarker(s.session, s.seq, s.root)); err != nil {
						t.Fatalf("record %+v: %v", s, err)
					}
				}
			}
			preDir, writeDir := t.TempDir(), t.TempDir()
			build(preDir)
			build(writeDir)

			preErr := PreflightStateMarker(preDir, preflightCheckpoint(tc.next.session, tc.next.seq, tc.next.root))
			// A same-identity marker that differs in its log fields is what a
			// second submit of the same checkpoint would record.
			next := preflightMarker(tc.next.session, tc.next.seq, tc.next.root)
			next.LogIndex = 10
			writeErr := WriteStateMarker(writeDir, next)

			if (preErr != nil) != (writeErr != nil) {
				t.Fatalf("preflight error = %v, WriteStateMarker error = %v; they must agree", preErr, writeErr)
			}
			if tc.wantErrHas == "" {
				if preErr != nil {
					t.Fatalf("preflight refused a recordable checkpoint: %v", preErr)
				}
				return
			}
			if preErr == nil || !strings.Contains(preErr.Error(), tc.wantErrHas) {
				t.Fatalf("preflight error = %v, want %q", preErr, tc.wantErrHas)
			}
		})
	}
}

// The preflight reads; it never records. A refused or accepted preflight
// leaves the recorded state exactly as it found it.
func TestPreflightStateMarker_RecordsNothing(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := WriteStateMarker(dir, preflightMarker("proxy", 4, "a")); err != nil {
		t.Fatalf("record: %v", err)
	}
	before, err := LoadStateMarkers(dir)
	if err != nil {
		t.Fatalf("LoadStateMarkers: %v", err)
	}
	if err := PreflightStateMarker(dir, preflightCheckpoint("proxy", 9, "b")); err != nil {
		t.Fatalf("preflight: %v", err)
	}
	if err := PreflightStateMarker(dir, preflightCheckpoint("proxy", 4, "b")); err == nil {
		t.Fatal("conflicting checkpoint passed the preflight")
	}
	after, err := LoadStateMarkers(dir)
	if err != nil {
		t.Fatalf("LoadStateMarkers: %v", err)
	}
	if len(before) != len(after) {
		t.Fatalf("preflight changed the recorded markers: %d before, %d after", len(before), len(after))
	}
}
