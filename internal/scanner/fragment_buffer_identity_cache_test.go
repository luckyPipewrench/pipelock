// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"bytes"
	"testing"
)

func TestFragmentBufferStreamIdentityReuseIsolation(t *testing.T) {
	fb := NewFragmentBuffer(64, 8, 300)
	t.Cleanup(fb.Close)
	first := testCEEIdentity("first-session")
	second := testCEEIdentity("second-session")
	for _, tc := range []struct {
		name    string
		first   bool
		payload string
	}{
		{name: "first request", first: true, payload: "first body"},
		{name: "second request", first: false, payload: "second body"},
		{name: "repeat first", first: true, payload: "first again"},
		{name: "repeat second", first: false, payload: "second again"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			owner := second
			if tc.first {
				owner = first
			}
			stream := owner.Stream("shared-partition")
			if got := fb.AppendOwned(owner, stream, []byte(tc.payload)); got != (FragmentAppendResult{}) {
				t.Fatalf("append failed: %+v", got)
			}
			fb.mu.Lock()
			defer fb.mu.Unlock()
			sb := fb.sessions[stream.Key()]
			wantID := fragmentStreamID(fragmentStreamKindData, stream.Key())
			if sb == nil || sb.streamID != wantID || fb.streamOwners[wantID] != owner.Key() {
				t.Fatalf("stream ID reused across owners: got %+v, want %q", sb, wantID)
			}
			if !bytes.Equal(sb.fragments[len(sb.fragments)-1].data, []byte(tc.payload)) {
				t.Fatal("request payload mixed with another stream")
			}
		})
	}
	stream := first.Stream("shared-partition")
	fb.Delete(stream)
	if got := fb.AppendOwned(first, stream, []byte("recreated")); got != (FragmentAppendResult{}) {
		t.Fatalf("recreated stream failed: %+v", got)
	}
	fb.mu.Lock()
	defer fb.mu.Unlock()
	sb := fb.sessions[stream.Key()]
	if sb == nil || sb.streamID != fragmentStreamID(fragmentStreamKindData, stream.Key()) || len(sb.fragments) != 1 || string(sb.fragments[0].data) != "recreated" {
		t.Fatalf("recreated stream kept stale identity or data: %+v", sb)
	}
}

func TestFragmentBufferCachedGroupMembershipTracksLaterRequests(t *testing.T) {
	fb := NewFragmentBuffer(12, 8, 300)
	t.Cleanup(fb.Close)
	owner := testCEEIdentity("growing-session")
	group := owner.Stream("group")
	first := owner.Stream("first")
	second := owner.Stream("second")
	if got := fb.AppendOwnedInGroup(owner, group, first, []byte("first body")); got != (FragmentAppendResult{}) {
		t.Fatalf("first append: %+v", got)
	}
	if got := fb.AppendOwnedInGroup(owner, group, second, []byte("next body")); got != (FragmentAppendResult{}) {
		t.Fatalf("second append: %+v", got)
	}
	if got := fb.AppendOwnedInGroup(owner, group, first, []byte("last body")); got != (FragmentAppendResult{}) {
		t.Fatalf("returning append: %+v", got)
	}
	if got := fb.TotalBufferBytes(); got > 12 {
		t.Fatalf("cached singleton membership retained %d bytes, want at most 12", got)
	}
}
