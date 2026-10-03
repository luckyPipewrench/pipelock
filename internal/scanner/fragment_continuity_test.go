// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/identitykey"
)

func TestFragmentContinuityKeepsSiblingLeavesApart(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)

	owner := identitykey.NewCEEIdentity("", "203.0.113.10", envelope.ActorAuthSelfDeclared)
	group := owner.Stream("|body|")
	stream := owner.Stream("|body|bucket")
	prefix := []byte("AKI" + "A")
	suffix := []byte("IOSFODNN7" + "EXAMPLE")

	t.Run("split field still matches", func(t *testing.T) {
		fb := NewFragmentBuffer(4096, 4, 300)
		t.Cleanup(fb.Close)
		if _, matches := appendLeaves(t, fb, sc, owner, group, stream, []FragmentPiece{
			{Continuity: []byte("content"), Data: prefix},
			{Continuity: []byte("decoy"), Data: []byte("INTRUDERTEXT")},
		}); len(matches) != 0 {
			t.Fatalf("first half matched: %#v", matches)
		}
		_, matches := appendLeaves(t, fb, sc, owner, group, stream, []FragmentPiece{
			{Continuity: []byte("content"), Data: suffix},
			{Continuity: []byte("decoy"), Data: []byte("INTRUDERTEXT")},
		})
		if len(matches) == 0 {
			t.Fatal("completing half was not detected once the sibling was kept out of the field")
		}
	})

	t.Run("one request does not match around a sibling", func(t *testing.T) {
		fb := NewFragmentBuffer(4096, 4, 300)
		t.Cleanup(fb.Close)
		_, matches := appendLeaves(t, fb, sc, owner, group, stream, []FragmentPiece{
			{Continuity: []byte("content"), Data: prefix},
			{Continuity: []byte("decoy"), Data: []byte("INTRUDERTEXT")},
			{Continuity: []byte("content"), Data: suffix},
		})
		if len(matches) != 0 {
			t.Fatalf("one request matched across a sibling: %#v", matches)
		}
	})

	t.Run("sibling halves do not match", func(t *testing.T) {
		fb := NewFragmentBuffer(4096, 4, 300)
		t.Cleanup(fb.Close)
		_, _ = appendLeaves(t, fb, sc, owner, group, stream, []FragmentPiece{
			{Continuity: []byte("content"), Data: []byte("xxxxordinary")},
			{Continuity: []byte("decoy"), Data: prefix},
		})
		_, matches := appendLeaves(t, fb, sc, owner, group, stream, []FragmentPiece{
			{Continuity: []byte("content"), Data: suffix},
			{Continuity: []byte("decoy"), Data: []byte("yyyyordinary")},
		})
		if len(matches) != 0 {
			t.Fatalf("sibling fields formed a secret: %#v", matches)
		}
	})
}

func appendLeaves(t *testing.T, fb *FragmentBuffer, sc *Scanner, owner identitykey.CEEIdentity, group, stream identitykey.CEEStream, pieces []FragmentPiece) (FragmentAppendResult, []DLPMatch) {
	t.Helper()
	result, matches := fb.AppendAndScanOwnedBatch(t.Context(), owner, []FragmentAppend{{
		Group:  group,
		Stream: stream,
		Pieces: pieces,
	}}, sc)
	if result != (FragmentAppendResult{}) {
		t.Fatalf("append = %+v", result)
	}
	if len(matches) != 1 {
		t.Fatalf("match groups = %d, want 1", len(matches))
	}
	return result, matches[0]
}
