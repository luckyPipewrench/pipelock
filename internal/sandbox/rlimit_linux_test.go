// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sandbox

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestBoundedNProcLimit(t *testing.T) {
	tests := []struct {
		name      string
		inherited unix.Rlimit
		want      uint64
	}{
		{name: "infinite inherited caps get absolute ceiling", inherited: unix.Rlimit{Cur: unix.RLIM_INFINITY, Max: unix.RLIM_INFINITY}, want: rlimitNProc},
		{name: "larger inherited caps get absolute ceiling", inherited: unix.Rlimit{Cur: rlimitNProc + 1, Max: rlimitNProc + 1}, want: rlimitNProc},
		{name: "stricter inherited soft cap is preserved", inherited: unix.Rlimit{Cur: rlimitNProc - 2, Max: rlimitNProc + 1}, want: rlimitNProc - 2},
		{name: "stricter inherited hard cap is preserved", inherited: unix.Rlimit{Cur: rlimitNProc - 1, Max: rlimitNProc - 1}, want: rlimitNProc - 1},
		{name: "hard cap binds below unlimited soft cap", inherited: unix.Rlimit{Cur: unix.RLIM_INFINITY, Max: rlimitNProc - 3}, want: rlimitNProc - 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := boundedNProcLimit(tt.inherited); got != tt.want {
				t.Fatalf("boundedNProcLimit(%+v) = %d, want %d", tt.inherited, got, tt.want)
			}
		})
	}
}

func TestRequestedNProcLimit(t *testing.T) {
	if got, err := requestedNProcLimit(100, 2048); err != nil || got != 1124 {
		t.Fatalf("requestedNProcLimit(100, 2048) = (%d, %v), want (1124, nil)", got, err)
	}
	if _, err := requestedNProcLimit(1025, 2048); err == nil {
		t.Fatal("launch without full process headroom was accepted")
	}
	if _, err := requestedNProcLimit(^uint64(0), ^uint64(0)); err == nil {
		t.Fatal("overflowing process headroom was accepted")
	}
}

func TestProcessUIDAndThreads(t *testing.T) {
	uid, threads, err := processUIDAndThreads([]byte("Name:\ttest\nUid:\t1000\t1000\t1000\t1000\nThreads:\t7\n"))
	if err != nil || uid != 1000 || threads != 7 {
		t.Fatalf("processUIDAndThreads = (%d, %d, %v), want (1000, 7, nil)", uid, threads, err)
	}
	if _, _, err := processUIDAndThreads([]byte("Name:\ttest\n")); err == nil {
		t.Fatal("missing UID and thread fields accepted")
	}
	t.Run("malformed UID", func(t *testing.T) {
		if _, _, err := processUIDAndThreads([]byte("Uid:\tinvalid\nThreads:\t7\n")); err == nil {
			t.Fatal("malformed UID accepted")
		}
	})
	t.Run("malformed threads", func(t *testing.T) {
		if _, _, err := processUIDAndThreads([]byte("Uid:\t1000\nThreads:\tinvalid\n")); err == nil {
			t.Fatal("malformed thread count accepted")
		}
	})
}
