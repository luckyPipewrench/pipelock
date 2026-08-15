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
	tests := []struct {
		name    string
		tasks   uint64
		ceiling uint64
		want    uint64
		wantErr bool
	}{
		{name: "reserves headroom", tasks: 100, ceiling: 2048, want: 1124},
		{name: "rejects insufficient headroom", tasks: 1025, ceiling: 2048, wantErr: true},
		{name: "rejects overflow", tasks: ^uint64(0), ceiling: ^uint64(0), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := requestedNProcLimit(tt.tasks, tt.ceiling)
			if (err != nil) != tt.wantErr {
				t.Fatalf("requestedNProcLimit(%d, %d) error = %v, wantErr %t", tt.tasks, tt.ceiling, err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Fatalf("requestedNProcLimit(%d, %d) = %d, want %d", tt.tasks, tt.ceiling, got, tt.want)
			}
		})
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
