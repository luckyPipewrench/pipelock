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

func TestValidateNProcHeadroom(t *testing.T) {
	if err := validateNProcHeadroom(10, 11); err != nil {
		t.Fatalf("available headroom rejected: %v", err)
	}
	for _, tasks := range []uint64{10, 11} {
		if err := validateNProcHeadroom(tasks, 10); err == nil {
			t.Fatalf("tasks=%d accepted at limit 10", tasks)
		}
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
}
