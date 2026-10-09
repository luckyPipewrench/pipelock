// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"math"
	"testing"
)

func TestKnownValueStrideIntegerBoundary(t *testing.T) {
	t.Parallel()
	for _, span := range []int{0, 1, maxKnownValuePartialAnchors, maxKnownValuePartialAnchors + 1, math.MaxInt - 1, math.MaxInt} {
		got := knownValueStride(span)
		want := 1
		if span > maxKnownValuePartialAnchors {
			want = span / maxKnownValuePartialAnchors
			if span%maxKnownValuePartialAnchors != 0 {
				want++
			}
		}
		if got != want {
			t.Fatalf("span %d: stride %d, want %d", span, got, want)
		}
	}
}

func TestCollectValueWindowsPhasedIntegerBoundary(t *testing.T) {
	t.Parallel()
	const value = "aB3dE6gH9jK2mN5pQrStUvWx"
	starts := len(value) - minKnownSecretSubstringLen + 1
	for _, tt := range []struct {
		name                                string
		value                               string
		stride, phase, wantCount, wantPhase int
	}{
		{"maximum stride", value, math.MaxInt, 0, 1, math.MaxInt - starts},
		{"maximum phase", value, 1, math.MaxInt, 0, math.MaxInt - starts},
		{"phase at end", value, 1, starts, 0, 0},
		{"empty", "", 1, 0, 0, 0},
		{"short maximum phase", "short", 1, math.MaxInt, 0, math.MaxInt},
		{"ordinary sampling", value, 3, 1, 3, 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			windows, phase, err := collectValueWindowsPhased(tt.value, 7, 100, tt.stride, tt.phase)
			if err != nil {
				t.Fatal(err)
			}
			if len(windows) != tt.wantCount || phase != tt.wantPhase {
				t.Fatalf("windows=%d phase=%d, want %d/%d", len(windows), phase, tt.wantCount, tt.wantPhase)
			}
			for window, offsets := range windows {
				for _, offset := range offsets {
					if tt.value[offset-7:offset-7+minKnownSecretSubstringLen] != window {
						t.Fatal("window source offset changed")
					}
				}
			}
		})
	}
}
