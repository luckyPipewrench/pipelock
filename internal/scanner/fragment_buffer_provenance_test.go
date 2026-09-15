// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/identitykey"
)

func appendFragmentWithSource(t *testing.T, fb *FragmentBuffer, owner identitykey.CEEIdentity, stream identitykey.CEEStream, source, payload []byte, sc *Scanner) []DLPMatch {
	t.Helper()
	result, matches := fb.AppendAndScanOwnedBatch(context.Background(), owner, []FragmentAppend{{
		Group:           stream,
		Stream:          stream,
		Payload:         payload,
		SourceRequestID: source,
	}}, sc)
	if result != (FragmentAppendResult{}) {
		t.Fatalf("append result = %+v", result)
	}
	return matches[0]
}

func TestFragmentBufferMatchContributorsFollowRetainedFragments(t *testing.T) {
	owner := testCEEIdentity(testSessionA)
	stream := owner.Stream("|raw")
	prefix := []byte("AKI" + "A")
	suffix := []byte(testAWSKeySuffix)

	t.Run("current and prior", func(t *testing.T) {
		fb := NewFragmentBuffer(64, 2, testWindowSecs)
		t.Cleanup(fb.Close)
		sc := testFragmentScanner()
		t.Cleanup(sc.Close)
		appendFragmentWithSource(t, fb, owner, stream, []byte("1"), prefix, sc)
		matches := appendFragmentWithSource(t, fb, owner, stream, []byte(`"current"`), suffix, sc)
		if len(matches) != 1 {
			t.Fatalf("matches = %+v, want one", matches)
		}
		if got, want := matches[0].Contributors, [][]byte{[]byte("1"), []byte(`"current"`)}; !reflect.DeepEqual(got, want) {
			t.Fatalf("contributors = %q, want %q", got, want)
		}
	})

	t.Run("byte eviction", func(t *testing.T) {
		fb := NewFragmentBuffer(len(prefix)+len(suffix), 2, testWindowSecs)
		t.Cleanup(fb.Close)
		sc := testFragmentScanner()
		t.Cleanup(sc.Close)
		appendFragmentWithSource(t, fb, owner, stream, []byte("0"), []byte("junk"), sc)
		appendFragmentWithSource(t, fb, owner, stream, []byte("2"), prefix, sc)
		matches := appendFragmentWithSource(t, fb, owner, stream, []byte("3"), suffix, sc)
		if len(matches) != 1 || !reflect.DeepEqual(matches[0].Contributors, [][]byte{[]byte("2"), []byte("3")}) {
			t.Fatalf("matches after eviction = %+v, want contributors 2 and 3", matches)
		}
	})

	t.Run("expiry", func(t *testing.T) {
		fb := NewFragmentBuffer(64, 2, 1)
		t.Cleanup(fb.Close)
		sc := testFragmentScanner()
		t.Cleanup(sc.Close)
		appendFragmentWithSource(t, fb, owner, stream, []byte("expired"), []byte("old"), sc)
		fb.sessions[stream.Key()].fragments[0].at = time.Now().Add(-2 * time.Second)
		fb.lastCleanup = time.Now().Add(-2 * time.Second)
		appendFragmentWithSource(t, fb, owner, stream, []byte("4"), prefix, sc)
		matches := appendFragmentWithSource(t, fb, owner, stream, []byte("5"), suffix, sc)
		if len(matches) != 1 || !reflect.DeepEqual(matches[0].Contributors, [][]byte{[]byte("4"), []byte("5")}) {
			t.Fatalf("matches after expiry = %+v, want contributors 4 and 5", matches)
		}
	})

	t.Run("legacy source omitted", func(t *testing.T) {
		fb := NewFragmentBuffer(64, 2, testWindowSecs)
		t.Cleanup(fb.Close)
		sc := testFragmentScanner()
		t.Cleanup(sc.Close)
		appendFragmentWithSource(t, fb, owner, stream, nil, prefix, sc)
		matches := appendFragmentWithSource(t, fb, owner, stream, nil, suffix, sc)
		if len(matches) != 1 || len(matches[0].Contributors) != 0 {
			t.Fatalf("legacy match = %+v, want detected match with no contributors", matches)
		}
	})
}

func TestFragmentBufferCapacityRefusalPreservesSourceProvenance(t *testing.T) {
	fb := NewFragmentBuffer(64, 1, testWindowSecs)
	t.Cleanup(fb.Close)
	sc := testFragmentScanner()
	t.Cleanup(sc.Close)
	owner := testCEEIdentity(testSessionA)
	stream := owner.Stream("|raw")
	appendFragmentWithSource(t, fb, owner, stream, []byte("1"), []byte("AKI"+"A"), sc)
	if result := fb.Append(testCEEIdentity(testSessionB), []byte("uninspectable")); !result.CapacityExceeded {
		t.Fatal("new owner was admitted at capacity")
	}
	matches := appendFragmentWithSource(t, fb, owner, stream, []byte("2"), []byte(testAWSKeySuffix), sc)
	if len(matches) != 1 || !reflect.DeepEqual(matches[0].Contributors, [][]byte{[]byte("1"), []byte("2")}) {
		t.Fatalf("matches after capacity refusal = %+v, want contributors 1 and 2", matches)
	}
}
