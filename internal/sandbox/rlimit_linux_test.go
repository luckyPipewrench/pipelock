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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := boundedNProcLimit(tt.inherited); got != tt.want {
				t.Fatalf("boundedNProcLimit(%+v) = %d, want %d", tt.inherited, got, tt.want)
			}
		})
	}
}
