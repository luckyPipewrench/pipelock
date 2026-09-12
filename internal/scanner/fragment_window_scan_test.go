// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestFragmentBuffer_ScansCompletingBodyBeforeRetention(t *testing.T) {
	cfg, err := config.LoadBytes([]byte("dlp:\n  patterns:\n    - name: Boundary token\n      regex: 'CTOK[A-Z]{12}'\n      severity: high\n"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Internal = nil
	sc := MustNew(cfg)
	defer sc.Close()
	ctx := context.Background()
	secret := "CTOKBBBBBBBBBBBB"
	const bodyBytes = 65536
	first := []byte(strings.Repeat("x", bodyBytes-8) + secret[:8])
	second := []byte(secret[8:] + strings.Repeat("x", bodyBytes-8))
	if sc.ScanTextForDLPQuiet(ctx, string(first)+string(second)).Clean {
		t.Fatal("positive control missed the joined boundary token")
	}
	if !sc.ScanTextForDLPQuiet(ctx, string(first)).Clean || !sc.ScanTextForDLPQuiet(ctx, string(second)).Clean {
		t.Fatal("one body alone matched; test does not isolate cross-request inspection")
	}
	for _, budget := range []int{bodyBytes, bodyBytes / 2, bodyBytes * 2} {
		t.Run(strconv.Itoa(budget), func(t *testing.T) {
			fb := NewFragmentBuffer(budget, 10, testWindowSecs)
			defer fb.Close()
			firstResult, firstMatches := fb.AppendAndScanOwnedInGroup(ctx, testCEEIdentity(testSessionA), testCEEStream(testSessionA), testCEEStream(testSessionA), first, sc)
			if firstResult != (FragmentAppendResult{}) || len(firstMatches) != 0 {
				t.Fatal("initial body was rejected or treated as cross-request")
			}
			result, matches := fb.AppendAndScanOwnedInGroup(ctx, testCEEIdentity(testSessionA), testCEEStream(testSessionA), testCEEStream(testSessionA), second, sc)
			if result != (FragmentAppendResult{}) {
				t.Fatalf("second body rejected: %+v", result)
			}
			if len(matches) == 0 {
				t.Fatal("retention eviction removed the completing request boundary before inspection")
			}
			if retained := fb.TotalBufferBytes(); retained > budget {
				t.Fatalf("retained %d bytes exceeds configured %d", retained, budget)
			}
		})
	}
}

func TestFragmentBuffer_PreEvictionPathAndIsolation(t *testing.T) {
	cfg, err := config.LoadBytes([]byte("dlp:\n  patterns:\n    - name: Boundary token\n      regex: 'CTOK[A-Z]{12}'\n      severity: high\n"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Internal = nil
	sc := MustNew(cfg)
	defer sc.Close()
	ctx := context.Background()
	prefix, suffix := []byte("CTOKBBBB"), []byte("BBBBBBBB")
	if sc.ScanTextForDLPQuiet(ctx, string(prefix)+string(suffix)).Clean {
		t.Fatal("positive control missed joined token")
	}
	t.Run("path completes before eviction", func(t *testing.T) {
		fb := NewFragmentBuffer(8, 10, testWindowSecs)
		defer fb.Close()
		_, first := fb.AppendAndScanPathSegmentsOwned(ctx, testCEEIdentity(testSessionA), testCEEStream(testSessionA), [][]byte{prefix}, sc)
		result, matches := fb.AppendAndScanPathSegmentsOwned(ctx, testCEEIdentity(testSessionA), testCEEStream(testSessionA), [][]byte{suffix}, sc)
		if len(first) != 0 || result != (FragmentAppendResult{}) || len(matches) != 1 {
			t.Fatalf("first=%v result=%+v completed=%v", first, result, matches)
		}
		if fb.TotalBufferBytes() > 8 {
			t.Fatal("path exceeded retention budget")
		}
	})
	t.Run("expired prefix cannot join", func(t *testing.T) {
		fb := NewFragmentBuffer(8, 10, testWindowSecs)
		defer fb.Close()
		_, _ = fb.AppendAndScanOwnedInGroup(ctx, testCEEIdentity(testSessionA), testCEEStream(testSessionA), testCEEStream(testSessionA), prefix, sc)
		fb.mu.Lock()
		fb.sessions[testSessionA].fragments[0].at = time.Now().Add(-2 * time.Duration(testWindowSecs) * time.Second)
		fb.mu.Unlock()
		_, matches := fb.AppendAndScanOwnedInGroup(ctx, testCEEIdentity(testSessionA), testCEEStream(testSessionA), testCEEStream(testSessionA), suffix, sc)
		if len(matches) != 0 {
			t.Fatalf("expired bytes formed a match: %v", matches)
		}
	})
	t.Run("foreign owner cannot complete", func(t *testing.T) {
		fb := NewFragmentBuffer(8, 10, testWindowSecs)
		defer fb.Close()
		_, _ = fb.AppendAndScanOwnedInGroup(ctx, testCEEIdentity(testSessionA), testCEEStream(testSessionA), testCEEStream(testSessionA), prefix, sc)
		result, matches := fb.AppendAndScanOwnedInGroup(ctx, testCEEIdentity(testSessionB), testCEEStream(testSessionA), testCEEStream(testSessionA), suffix, sc)
		if !result.OwnerMismatch || len(matches) != 0 {
			t.Fatalf("foreign owner inspected: result=%+v matches=%v", result, matches)
		}
		_, matches = fb.AppendAndScanOwnedInGroup(ctx, testCEEIdentity(testSessionA), testCEEStream(testSessionA), testCEEStream(testSessionA), suffix, sc)
		if len(matches) != 1 {
			t.Fatal("foreign append destroyed original owner's evidence")
		}
	})
	t.Run("concurrent identities retain boundaries", func(t *testing.T) {
		const workers = 8
		fb := NewFragmentBuffer(8, workers, testWindowSecs)
		defer fb.Close()
		var wg sync.WaitGroup
		for i := range workers {
			wg.Go(func() {
				key := strconv.Itoa(i)
				_, _ = fb.AppendAndScanOwnedInGroup(ctx, testCEEIdentity(key), testCEEStream(key), testCEEStream(key), prefix, sc)
				result, matches := fb.AppendAndScanOwnedInGroup(ctx, testCEEIdentity(key), testCEEStream(key), testCEEStream(key), suffix, sc)
				if result != (FragmentAppendResult{}) || len(matches) != 1 {
					t.Errorf("identity %s: result=%+v matches=%v", key, result, matches)
				}
			})
		}
		wg.Wait()
		if fb.TotalBufferBytes() > workers*8 {
			t.Fatal("concurrent appends exceeded retention budget")
		}
	})
}
