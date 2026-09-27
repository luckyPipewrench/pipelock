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
		{name: "desktop limit above ceiling", inherited: unix.Rlimit{Cur: 200000, Max: 200000}, want: rlimitNProc},
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
		{name: "busy UID above old ceiling", tasks: 5000, ceiling: rlimitNProc, want: 5000 + rlimitNProcHeadroom},
		{name: "stricter inherited limit allows remaining headroom", tasks: 5000, ceiling: 5500, want: 5500},
		{name: "stricter inherited limit still binds", tasks: 5000, ceiling: 5000, wantErr: true},
		{name: "caps partial headroom at ceiling", tasks: 1025, ceiling: 2048, want: 2048},
		{name: "allows final task below ceiling", tasks: 2047, ceiling: 2048, want: 2048},
		{name: "rejects at ceiling", tasks: 2048, ceiling: 2048, wantErr: true},
		{name: "rejects above ceiling", tasks: 2049, ceiling: 2048, wantErr: true},
		{name: "avoids overflow near uint maximum", tasks: ^uint64(0) - 1, ceiling: ^uint64(0), want: ^uint64(0)},
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

func TestRequestedNProcLimitAntiRatchet(t *testing.T) {
	// Concurrent launches can observe the same initial count. Each child
	// receives its own rlimit, so none can grant a limit past the shared cap.
	const simultaneousLaunches = 16
	for i := 0; i < simultaneousLaunches; i++ {
		limit, err := requestedNProcLimit(rlimitNProc-100, rlimitNProc)
		if err != nil || limit != rlimitNProc {
			t.Fatalf("launch %d from shared count: limit=%d, err=%v", i, limit, err)
		}
	}

	// Each launch sees the tasks created by earlier launches. Its own hard
	// limit can rise, but no launch may grant capacity above the shared cap.
	tasks := uint64(5000)
	for tasks < rlimitNProc {
		limit, err := requestedNProcLimit(tasks, rlimitNProc)
		if err != nil {
			t.Fatalf("request at %d tasks: %v", tasks, err)
		}
		if limit <= tasks || limit > rlimitNProc || limit-tasks > rlimitNProcHeadroom {
			t.Fatalf("request at %d tasks granted %d", tasks, limit)
		}
		tasks = limit
	}
	if tasks != rlimitNProc {
		t.Fatalf("successive launch capacity = %d, want ceiling %d", tasks, rlimitNProc)
	}
	if _, err := requestedNProcLimit(tasks, rlimitNProc); err == nil {
		t.Fatal("launch at shared UID ceiling was accepted")
	}
}

func TestCurrentUIDTaskCountLive(t *testing.T) {
	var inherited unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NPROC, &inherited); err != nil {
		t.Fatalf("get inherited RLIMIT_NPROC: %v", err)
	}
	ceiling := boundedNProcLimit(inherited)
	tasks, err := currentUIDTaskCount(ceiling)
	if err != nil {
		t.Fatalf("count current UID tasks: %v", err)
	}
	if tasks >= ceiling {
		t.Skipf("shared UID is already at sandbox task ceiling: tasks=%d ceiling=%d", tasks, ceiling)
	}
	limit, err := requestedNProcLimit(tasks, ceiling)
	if err != nil {
		t.Fatalf("request limit below ceiling: tasks=%d ceiling=%d: %v", tasks, ceiling, err)
	}
	if limit <= tasks || limit > ceiling {
		t.Fatalf("requested limit = %d, want (%d, %d]", limit, tasks, ceiling)
	}
}

func TestProcessTaskCount(t *testing.T) {
	threads, belongs, err := processTaskCount([]byte("Name:\ttest\nUid:\t1000\t1000\t1000\t1000\nThreads:\t7\n"), 1000)
	if err != nil || !belongs || threads != 7 {
		t.Fatalf("processTaskCount = (%d, %t, %v), want (7, true, nil)", threads, belongs, err)
	}
	if _, _, err := processTaskCount([]byte("Name:\ttest\n"), 1000); err == nil {
		t.Fatal("missing UID and thread fields accepted")
	}
	t.Run("missing threads", func(t *testing.T) {
		if _, _, err := processTaskCount([]byte("Uid:\t1000\n"), 1000); err == nil {
			t.Fatal("missing thread field accepted for target UID")
		}
	})
	t.Run("malformed UID", func(t *testing.T) {
		if _, _, err := processTaskCount([]byte("Uid:\tinvalid\nThreads:\t7\n"), 1000); err == nil {
			t.Fatal("malformed UID accepted")
		}
	})
	t.Run("malformed threads", func(t *testing.T) {
		if _, _, err := processTaskCount([]byte("Uid:\t1000\nThreads:\tinvalid\n"), 1000); err == nil {
			t.Fatal("malformed thread count accepted")
		}
	})
	t.Run("foreign process does not require threads", func(t *testing.T) {
		threads, belongs, err := processTaskCount([]byte("Uid:\t2000\nThreads:\tinvalid\n"), 1000)
		if err != nil || belongs || threads != 0 {
			t.Fatalf("foreign process = (%d, %t, %v), want (0, false, nil)", threads, belongs, err)
		}
	})
	t.Run("empty status is transient", func(t *testing.T) {
		threads, belongs, err := processTaskCount(nil, 1000)
		if err != nil || belongs || threads != 0 {
			t.Fatalf("empty status = (%d, %t, %v), want (0, false, nil)", threads, belongs, err)
		}
	})
}
