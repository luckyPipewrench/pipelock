// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"testing"
	"time"
)

func pathSegmentsForTest(parts ...string) [][]byte {
	segments := make([][]byte, 0, len(parts))
	for _, part := range parts {
		segments = append(segments, []byte(part))
	}
	return segments
}

func TestFragmentBufferPath_StaticPositionsStoredOnceAndDynamicValuesRepeat(t *testing.T) {
	fb := NewFragmentBuffer(4096, 10, testWindowSecs)
	defer fb.Close()

	fb.AppendPathSegments(testSessionA, pathSegmentsForTest("upload", "one"))
	if got, want := fb.TotalBufferBytes(), len("uploadone"); got != want {
		t.Fatalf("first path buffered %d bytes, want %d", got, want)
	}

	// The static route at position zero is stored only once. Position one now
	// varies, so every later value at that position must be retained, including
	// a repeat of "two".
	fb.AppendPathSegments(testSessionA, pathSegmentsForTest("upload", "two"))
	fb.AppendPathSegments(testSessionA, pathSegmentsForTest("upload", "two"))
	if got, want := fb.TotalBufferBytes(), len("uploadonetwotwo"); got != want {
		t.Fatalf("position-aware path bytes = %d, want %d", got, want)
	}

	fb.mu.Lock()
	position := fb.pathSessions[testSessionA].positions[1]
	varied := position.varied
	count := len(position.fragments)
	fb.mu.Unlock()
	if !varied || count != 3 {
		t.Fatalf("dynamic position = varied:%v fragments:%d, want true:3", varied, count)
	}
}

func TestFragmentBufferPath_ExactDuplicatePrimingCannotSuppressCompletingSuffix(t *testing.T) {
	fb := NewFragmentBuffer(65536, 10, testWindowSecs)
	defer fb.Close()
	sc := testFragmentScanner()
	defer sc.Close()

	prefix := "AKI" + "A"
	suffix := testAWSKeySuffix

	// The attack order: suffix first, then prefix, then the same suffix. A
	// value-based dedupe drops the third fragment. A varying position keeps it
	// and the latter two fragments reconstruct the credential.
	fb.AppendPathSegments(testSessionA, pathSegmentsForTest("upload", suffix))
	fb.AppendPathSegments(testSessionA, pathSegmentsForTest("upload", prefix))
	fb.AppendPathSegments(testSessionA, pathSegmentsForTest("upload", suffix))

	if matches := fb.ScanPathForSecrets(context.Background(), testSessionA, sc); len(matches) == 0 {
		t.Fatal("exact-duplicate priming suppressed the completing suffix")
	}
}

func TestFragmentBufferPath_SeparatePositionsDoNotCreateSingleRequestMatches(t *testing.T) {
	fb := NewFragmentBuffer(65536, 10, testWindowSecs)
	defer fb.Close()
	sc := testFragmentScanner()
	defer sc.Close()

	// One complete key in one path position is handled by normal URL DLP. It
	// must not become a CEE match merely because static positions also exist.
	fullKey := "AKI" + "A" + testAWSKeySuffix
	fb.AppendPathSegments(testSessionA, pathSegmentsForTest("upload", fullKey))
	fb.AppendPathSegments(testSessionA, pathSegmentsForTest("upload", "normal"))
	if matches := fb.ScanPathForSecrets(context.Background(), testSessionA, sc); len(matches) != 0 {
		t.Fatalf("single-request path secret produced %d CEE matches", len(matches))
	}
}

func TestFragmentBufferPath_DepthCapDoesNotAllocateOrConsumeGlobalSessions(t *testing.T) {
	fb := NewFragmentBuffer(4096, 1, testWindowSecs)
	defer fb.Close()

	deep := make([][]byte, MaxPathPositions+1)
	for i := range deep {
		deep[i] = []byte("x")
	}
	if result := fb.AppendPathSegments(testSessionA, deep); !result.PathDepthExceeded {
		t.Fatal("path over depth cap was accepted")
	}
	if got := fb.TotalBufferBytes(); got != 0 {
		t.Fatalf("over-depth path retained %d bytes", got)
	}
	if result := fb.Append(testSessionB, []byte("ordinary")); result.CapacityExceeded {
		t.Fatal("over-depth path consumed the only global session slot")
	}
}

func TestFragmentBufferPath_EmptyAndCapacityInputsDoNotAllocate(t *testing.T) {
	var nilBuffer *FragmentBuffer
	if result := nilBuffer.AppendPathSegments(testSessionA, pathSegmentsForTest("ignored")); result != (FragmentAppendResult{}) {
		t.Fatalf("nil buffer result = %+v, want empty", result)
	}

	fb := NewFragmentBuffer(4096, 1, testWindowSecs)
	defer fb.Close()
	if result := fb.AppendPathSegments(testSessionA, nil); result != (FragmentAppendResult{}) {
		t.Fatalf("nil path result = %+v, want empty", result)
	}
	if result := fb.AppendPathSegments(testSessionA, pathSegmentsForTest("", "")); result != (FragmentAppendResult{}) {
		t.Fatalf("empty path result = %+v, want empty", result)
	}
	if got := fb.TotalBufferBytes(); got != 0 {
		t.Fatalf("empty path retained %d bytes", got)
	}
	fb.mu.Lock()
	_, allocated := fb.pathSessions[testSessionA]
	fb.mu.Unlock()
	if allocated {
		t.Fatal("empty path allocated a logical session")
	}

	// A logical path session consumes one shared session slot, not one per
	// position; a second session fails closed when the global limit is full.
	fb.AppendPathSegments(testSessionA, pathSegmentsForTest("route"))
	if result := fb.AppendPathSegments(testSessionB, pathSegmentsForTest("route")); !result.CapacityExceeded {
		t.Fatal("path session capacity exhaustion was accepted")
	}
}

func TestFragmentBufferPath_UsesOneGlobalSessionRegardlessOfDepth(t *testing.T) {
	fb := NewFragmentBuffer(4096, 2, testWindowSecs)
	defer fb.Close()

	segments := make([][]byte, MaxPathPositions)
	for i := range segments {
		segments[i] = []byte("static")
	}
	if result := fb.AppendPathSegments(testSessionA, segments); result.CapacityExceeded || result.PathDepthExceeded {
		t.Fatalf("bounded path session was not admitted: %+v", result)
	}
	if result := fb.Append(testSessionB, []byte("ordinary")); result.CapacityExceeded {
		t.Fatal("one path session consumed more than one global session slot")
	}
	if result := fb.Append(testSessionC, []byte("overflow")); !result.CapacityExceeded {
		t.Fatal("global session cap did not account for the path session")
	}
}

func TestFragmentBufferPath_EvictionAndWindowDiscardPositionState(t *testing.T) {
	fb := NewFragmentBuffer(8, 10, 1)
	defer fb.Close()

	fb.AppendPathSegments(testSessionA, pathSegmentsForTest("route", "abcdef"))
	fb.AppendPathSegments(testSessionA, pathSegmentsForTest("route", "ghijkl"))
	if got := fb.TotalBufferBytes(); got > 8 {
		t.Fatalf("path bytes %d exceed shared session cap", got)
	}

	fb.mu.Lock()
	ps := fb.pathSessions[testSessionA]
	for _, position := range ps.positions {
		for i := range position.fragments {
			position.fragments[i].at = time.Now().Add(-2 * time.Second)
		}
	}
	fb.lastCleanup = time.Now().Add(-2 * time.Second)
	fb.mu.Unlock()

	// Trigger cleanup through the public path API. Expired fragments must also
	// discard their "static versus dynamic" classifications.
	fb.AppendPathSegments(testSessionB, pathSegmentsForTest("fresh"))
	fb.mu.Lock()
	_, exists := fb.pathSessions[testSessionA]
	fb.mu.Unlock()
	if exists {
		t.Fatal("expired path position state survived its retention window")
	}
}

func TestFragmentBufferPath_ScanSkipsMissingSingleAndCleanStreams(t *testing.T) {
	fb := NewFragmentBuffer(4096, 10, testWindowSecs)
	defer fb.Close()
	sc := testFragmentScanner()
	defer sc.Close()

	if matches := fb.ScanPathForSecrets(context.Background(), testSessionA, sc); len(matches) != 0 {
		t.Fatalf("missing path state returned %d matches", len(matches))
	}
	fb.AppendPathSegments(testSessionA, pathSegmentsForTest("fixed"))
	if matches := fb.ScanPathForSecrets(context.Background(), testSessionA, sc); len(matches) != 0 {
		t.Fatalf("one static fragment returned %d CEE matches", len(matches))
	}
	fb.AppendPathSegments(testSessionA, pathSegmentsForTest("changed"))
	if matches := fb.ScanPathForSecrets(context.Background(), testSessionA, sc); len(matches) != 0 {
		t.Fatalf("clean dynamic path returned %d CEE matches", len(matches))
	}
}

func TestFragmentBufferPath_ReloadAndCloseBoundPathState(t *testing.T) {
	fb := NewFragmentBuffer(4096, 10, testWindowSecs)
	fb.AppendPathSegments(testSessionA, pathSegmentsForTest("static", "abcdef"))
	fb.AppendPathSegments(testSessionA, pathSegmentsForTest("static", "ghijkl"))

	// Invalid reload values are clamped and immediately trim the shared path
	// budget instead of leaving position buffers at their old size.
	fb.UpdateConfig(0, 0)
	if got := fb.TotalBufferBytes(); got > 1 {
		t.Fatalf("reload retained %d path bytes, want at most 1", got)
	}
	fb.mu.Lock()
	maxBytes, windowSecs := fb.maxBytes, fb.windowSecs
	fb.mu.Unlock()
	if maxBytes != 1 || windowSecs != 1 {
		t.Fatalf("reload limits = %d bytes, %d seconds; want 1, 1", maxBytes, windowSecs)
	}

	fb.Close()
	if got := fb.TotalBufferBytes(); got != 0 {
		t.Fatalf("Close retained %d path bytes", got)
	}
	var nilBuffer *FragmentBuffer
	nilBuffer.Close()
}

func TestFragmentBufferPath_EvictionDefensivelyHandlesEmptyPosition(t *testing.T) {
	fb := NewFragmentBuffer(1, 10, testWindowSecs)
	defer fb.Close()

	// This cannot arise through AppendPathSegments, but the eviction guard must
	// safely handle a partially-pruned position rather than loop forever.
	ps := &pathSessionBuffer{
		positions:  map[int]*pathPositionBuffer{0: {}},
		totalBytes: 2,
	}
	fb.mu.Lock()
	fb.enforcePathMaxBytesLocked(ps)
	fb.mu.Unlock()
	if ps.totalBytes != 2 {
		t.Fatalf("empty position changed defensive total to %d", ps.totalBytes)
	}
}
